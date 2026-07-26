use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use headscale_client::LiveConnector;
use kube::Client;
use kube::api::Api;
use kube::runtime::events::Reporter;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing::info;

use shadow_rs::shadow;
shadow!(build);

const HEALTH_PORT: u16 = 8080;

use operator::context::Context;
use operator::controllers::external_service;
use operator::controllers::headscale_instance;
use operator::controllers::ingress;
use operator::server::health;
use operator::server::webhook;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    info!(
        commit = build::SHORT_COMMIT,
        branch = build::BRANCH,
        dirty = !build::GIT_CLEAN,
        built_at = build::BUILD_TIME_3339,
        rustc = build::RUST_VERSION,
        "starting"
    );
    if !build::GIT_CLEAN {
        tracing::warn!(
            files = build::GIT_STATUS_FILE,
            "built from dirty working tree"
        );
    }

    let operator_namespace =
        std::env::var("OPERATOR_NAMESPACE").expect("OPERATOR_NAMESPACE env var must be set");
    let webhook_tls_dir = std::env::var("WEBHOOK_TLS_DIR").ok();
    let headscale_image =
        std::env::var("HEADSCALE_IMAGE").expect("HEADSCALE_IMAGE env var must be set");
    let proxy_image = std::env::var("PROXY_IMAGE").expect("PROXY_IMAGE env var must be set");
    let socat_image = std::env::var("SOCAT_IMAGE").expect("SOCAT_IMAGE env var must be set");
    let egress_dns_coredns_custom =
        std::env::var("EGRESS_DNS_COREDNS_CUSTOM").is_ok_and(|v| v == "true");
    let tun_device = match std::env::var("TUN_DEVICE_ACCESS").as_deref() {
        Ok("privileged") | Err(_) => operator::context::TunDeviceAccess::Privileged,
        Ok("device-plugin") => operator::context::TunDeviceAccess::DevicePlugin {
            resource: std::env::var("TUN_DEVICE_PLUGIN_RESOURCE")
                .unwrap_or_else(|_| "squat.ai/tun".to_string()),
        },
        Ok(other) => {
            return Err(format!(
                "TUN_DEVICE_ACCESS={other:?}: expected \"privileged\" or \"device-plugin\""
            )
            .into());
        }
    };
    let operator_image =
        std::env::var("OPERATOR_IMAGE").expect("OPERATOR_IMAGE env var must be set");

    let ingress_enabled = match std::env::var("INGRESS_ENABLED") {
        Ok(v) => v
            .parse::<bool>()
            .map_err(|e| format!("INGRESS_ENABLED={v:?}: {e}"))?,
        Err(_) => true,
    };
    // None        = take default if unclaimed, gracefully back off if contested
    // Some(true)  = "force": forcibly take default (use when migrating)
    // Some(false) = "false": do not claim default at all
    let claim_default_config: Option<bool> = match std::env::var("CLAIM_DEFAULT") {
        Ok(v) => Some(match v.as_str() {
            "force" => true,
            "false" => false,
            other => {
                return Err(
                    format!("CLAIM_DEFAULT={other:?}: expected \"force\" or \"false\"").into(),
                );
            }
        }),
        Err(_) => None,
    };

    let client = Client::try_default().await?;

    let claim_default = if ingress_enabled {
        let is_default =
            ingress::ensure_ingress_class(&client, &operator_namespace, claim_default_config)
                .await?;
        info!(
            is_default_handler = is_default,
            "IngressClass 'headmaster' applied"
        );
        is_default
    } else {
        false
    };

    let ctx = Arc::new(Context {
        client: client.clone(),
        operator_namespace: operator_namespace.clone(),
        headscale: Arc::new(LiveConnector),
        reporter: Reporter {
            controller: "headmaster".into(),
            instance: std::env::var("POD_NAME").ok(),
        },
        headscale_image,
        proxy_image,
        socat_image,
        tun_device,
        egress_dns_coredns_custom,
        operator_image,
        claim_default,
    });

    // Bind before spawning so a port conflict fails main() immediately.
    let health_listener = TcpListener::bind(("0.0.0.0", HEALTH_PORT)).await?;
    info!("health server listening on 0.0.0.0:{HEALTH_PORT}");

    let ready = Arc::new(AtomicBool::new(false));
    tokio::spawn({
        let ready = ready.clone();
        async move {
            if let Err(e) = axum::serve(health_listener, health::router(ready)).await {
                tracing::warn!("health server error: {e}");
            }
        }
    });

    let shutdown = CancellationToken::new();

    let controllers = tokio::spawn({
        let ns = operator_namespace.clone();
        let headscale_instance_client = client.clone();
        let ingress_client = client.clone();
        let service_client = client.clone();
        let headscale_instance_ctx = ctx.clone();
        let ingress_ctx = ctx.clone();
        let service_ctx = ctx.clone();
        let headscale_instance_shutdown = shutdown.clone();
        let ingress_shutdown = shutdown.clone();
        let service_shutdown = shutdown.clone();
        async move {
            let headscale_instance_fut = headscale_instance::stream(
                Api::namespaced(headscale_instance_client, &ns),
                headscale_instance_ctx,
                headscale_instance_shutdown.cancelled_owned(),
            );
            // INGRESS_ENABLED gates both proxy controllers: they are two
            // frontends (HTTP Ingresses; Services — egress and exposure)
            // over the same proxy machinery, enabled and disabled as one
            // unit.
            if ingress_enabled {
                tokio::join!(
                    headscale_instance_fut,
                    ingress::stream(
                        Api::all(ingress_client),
                        ingress_ctx,
                        ingress_shutdown.cancelled_owned()
                    ),
                    external_service::stream(
                        Api::all(service_client),
                        service_ctx,
                        service_shutdown.cancelled_owned()
                    ),
                );
            } else {
                headscale_instance_fut.await;
            }
        }
    });

    if let Some(ref tls_dir) = webhook_tls_dir {
        // Load TLS config eagerly so a missing/unreadable cert fails main() here
        // rather than silently disabling admission control after the operator reports Ready.
        let tls_config = webhook::load_tls_config(std::path::Path::new(tls_dir)).await?;
        let webhook_ctx = ctx.clone();
        let webhook_shutdown = shutdown.clone();
        tokio::spawn(async move {
            if let Err(e) =
                webhook::serve(webhook_ctx, tls_config, webhook_shutdown.cancelled_owned()).await
            {
                tracing::error!("webhook server error: {e}");
            }
        });
    }

    ready.store(true, Ordering::Relaxed);
    info!("operator started; waiting for shutdown signal");
    shutdown_signal().await;
    info!("shutdown signal received; draining controllers");
    shutdown.cancel();
    controllers.await.ok();

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
