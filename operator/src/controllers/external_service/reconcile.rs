//! Main reconcile loop for tailnet egress `Service` objects. For every
//! ExternalName Service carrying the headmaster config annotation with a
//! `tailnet-fqdn`, provisions an egress proxy — a pod that joins the tailnet
//! as its own node and forwards each declared Service port to the tailnet
//! destination — and points the Service's `externalName` at it, so in-cluster
//! pods reach the tailnet host like any other Service.

use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use headscale_client::Code;
use headscale_client::headscale::v1::{DeleteNodeRequest, SetTagsRequest};
use k8s_ext::{
    ContainerExt, EnvVarExt, PodSpecExt, PodTemplateSpecExt, ServiceExt, ServicePortExt,
    StatefulSetExt,
};
use k8s_openapi::api::apps::v1::StatefulSet;
use k8s_openapi::api::core::v1::{
    Container, ContainerPort, EnvVar, PodSecurityContext, PodSpec, PodTemplateSpec, SeccompProfile,
    Secret, Service, ServicePort, ServiceSpec,
};
use kube::api::{Api, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::runtime::finalizer::{Event as Finalizer, finalizer};
use kube::runtime::reflector::ObjectRef;
use kube::runtime::watcher;
use kube::{Resource, ResourceExt};

use crate::context::Context;
use crate::controllers::applier::{ChildApplier, delete_ignoring_404};
use crate::controllers::proxy::{
    AuthKeyStatus, Error, ProxyNames, apply_proxy_rbac, cleanup_proxy_resources,
    deregister_and_cleanup, ensure_auth_key, ensure_state_secret, headscale_connect,
    namespace_is_deleting, read_secret_json, read_secret_string,
};
use crate::controllers::recorder::RecorderExt;
use crate::labels;
use crate::types::{ANNOTATION_CONFIG, HeadscaleInstance, IngressAnnotations, ResourceStatus};

const EXTERNAL_NAME_TYPE: &str = "ExternalName";
const PROXY_COMPONENT: &str = "tailscale-proxy";
/// tailscaled's userspace SOCKS5 listener, loopback-only inside the pod.
const SOCKS5_PORT: u16 = 1055;
/// socat listeners start here: unprivileged (no NET_BIND_SERVICE needed even
/// when the Service declares a port like 443) and collision-free with the
/// SOCKS5 port. The egress ClusterIP Service maps each declared port onto
/// its listener.
const LISTEN_PORT_BASE: i32 = 10000;

pub fn stream(
    service_api: Api<Service>,
    ctx: Arc<Context>,
    shutdown: impl std::future::Future<Output = ()> + Send + Sync + 'static,
) -> impl std::future::Future<Output = ()> {
    let controller = kube::runtime::Controller::new(service_api, watcher::Config::default());
    let service_store = controller.store();
    controller
        .watches(
            Api::<Secret>::namespaced(ctx.client.clone(), &ctx.operator_namespace),
            watcher::Config::default().labels(&format!(
                "{}={}",
                labels::APP_MANAGED_BY,
                labels::MANAGED_BY_VALUE
            )),
            |secret| {
                // Only children of Service parents; ingress children (kind
                // "ingress", or absent from before the label existed) belong
                // to the Ingress controller.
                if secret.labels().get(labels::PARENT_KIND).map(String::as_str)
                    != Some(labels::PARENT_KIND_SERVICE)
                {
                    return None;
                }
                let svc_name = secret.labels().get(labels::INGRESS_NAME)?.clone();
                let svc_ns = secret.labels().get(labels::INGRESS_NAMESPACE)?.clone();
                Some(ObjectRef::<Service>::new(&svc_name).within(&svc_ns))
            },
        )
        .watches(
            Api::<HeadscaleInstance>::namespaced(ctx.client.clone(), &ctx.operator_namespace),
            watcher::Config::default(),
            move |instance| {
                // Same caveat as the Ingress controller: an empty store during
                // the initial list/watch cycle is covered by trigger_self.
                let instance_name = instance.name_any();
                service_store
                    .state()
                    .into_iter()
                    .filter(move |svc| {
                        IngressAnnotations::headscale_ref(&**svc).as_deref() == Some(&instance_name)
                    })
                    .map(|svc| ObjectRef::from_obj(&*svc))
            },
        )
        .graceful_shutdown_on(shutdown)
        .run(reconcile, error_policy, ctx)
        .for_each(|res| async move {
            if let Err(e) = res {
                tracing::warn!("egress Service reconcile error: {e:?}");
            }
        })
}

// ── reconcile ─────────────────────────────────────────────────────────────────

fn error_policy(obj: Arc<Service>, e: &Error, _ctx: Arc<Context>) -> Action {
    tracing::warn!(
        name = obj.name_any(),
        "egress Service reconcile failed: {e:?}"
    );
    Action::requeue(Duration::from_secs(30))
}

fn is_external_name(svc: &Service) -> bool {
    svc.spec.as_ref().and_then(|s| s.type_.as_deref()) == Some(EXTERNAL_NAME_TYPE)
}

/// An ExternalName Service carrying our config annotation — the shape the
/// egress controller (and the DNS sync scanning all Services) cares about.
pub(super) fn is_egress_shape(svc: &Service) -> bool {
    is_external_name(svc) && svc.annotations().contains_key(ANNOTATION_CONFIG)
}

async fn reconcile(svc: Arc<Service>, ctx: Arc<Context>) -> Result<Action, Error> {
    let our_finalizer = crate::finalizer(&ctx.operator_namespace);
    let has_our_finalizer = svc.finalizers().iter().any(|f| f == &our_finalizer);

    let is_ours_shape = is_egress_shape(&svc);
    if !is_ours_shape && !has_our_finalizer {
        return Ok(Action::await_change());
    }

    let ns = svc.namespace().ok_or(Error::MissingNamespace)?;

    // Layer 1: sharding gate — only adopt Services targeted at this deployment.
    let target_namespace = IngressAnnotations::headscale_namespace(&*svc);
    let is_ours = match &target_namespace {
        Some(n) => n == &ctx.operator_namespace,
        None => ctx.claim_default,
    };
    if !is_ours && !has_our_finalizer {
        return Ok(Action::await_change());
    }

    // Layer 2: authorization gate — only runs pre-adoption. A Service without
    // a valid config annotation is not ours to manage; an excluded namespace
    // must never acquire our finalizer (see the Ingress controller for the
    // full rationale).
    if !has_our_finalizer {
        match IngressAnnotations::parse(&*svc) {
            Ok(annotations) => {
                let instance_api: Api<HeadscaleInstance> =
                    Api::namespaced(ctx.client.clone(), &ctx.operator_namespace);
                match instance_api.get(&annotations.headscale_ref).await {
                    Ok(instance) => {
                        if !instance.spec.namespace_allowed(&ns) {
                            return Ok(Action::await_change());
                        }
                    }
                    Err(kube::Error::Api(ref e)) if e.code == 404 => {}
                    Err(e) => return Err(Error::Kube(e)),
                }
            }
            Err(_) => return Ok(Action::await_change()),
        }
    }

    let api: Api<Service> = Api::namespaced(ctx.client.clone(), &ns);

    finalizer(&api, &our_finalizer, svc, |event| async {
        match event {
            Finalizer::Apply(s) => apply(s, &ctx).await,
            Finalizer::Cleanup(s) => cleanup(s, &ctx).await,
        }
    })
    .await
    .map_err(|e| match e {
        kube::runtime::finalizer::Error::ApplyFailed(e) => e,
        kube::runtime::finalizer::Error::CleanupFailed(e) => e,
        kube::runtime::finalizer::Error::AddFinalizer(e) => Error::Kube(e),
        kube::runtime::finalizer::Error::RemoveFinalizer(e) => Error::Kube(e),
        kube::runtime::finalizer::Error::UnnamedObject => Error::UnnamedObject,
        kube::runtime::finalizer::Error::InvalidFinalizer => {
            panic!("BUG: '{}' is not a valid finalizer string", our_finalizer)
        }
    })
}

// ── apply ─────────────────────────────────────────────────────────────────────

async fn apply(svc: Arc<Service>, ctx: &Context) -> Result<Action, Error> {
    let svc_ns = svc.namespace().unwrap_or_default();
    let svc_name = svc.name_any();
    let op_ns = &ctx.operator_namespace;
    let names = ProxyNames::for_service(&svc_ns, &svc_name);

    // Shape release: the annotation was removed, or the Service is no longer
    // ExternalName. Deregister and relinquish. spec.externalName is left
    // as-is; it may still point at the (now deleted) egress Service until the
    // user updates it.
    if !is_external_name(&svc) || !svc.annotations().contains_key(ANNOTATION_CONFIG) {
        if let Some(headscale_ref) = IngressAnnotations::headscale_ref(&*svc) {
            deregister_and_cleanup(ctx, op_ns, &names, &svc.object_ref(&()), &headscale_ref)
                .await?;
        } else {
            cleanup_proxy_resources(ctx, op_ns, &names).await;
        }
        release_service(ctx, &svc_ns, &svc_name).await?;
        super::dns::sync_egress_dns(ctx).await?;
        return Ok(Action::await_change());
    }

    // Sharding release: the headscale-namespace annotation now points elsewhere.
    let target_namespace = IngressAnnotations::headscale_namespace(&*svc);
    let is_ours = match &target_namespace {
        Some(n) => n == op_ns,
        None => ctx.claim_default,
    };
    if !is_ours {
        if let Some(headscale_ref) = IngressAnnotations::headscale_ref(&*svc) {
            deregister_and_cleanup(ctx, op_ns, &names, &svc.object_ref(&()), &headscale_ref)
                .await?;
        } else {
            cleanup_proxy_resources(ctx, op_ns, &names).await;
        }
        release_service(ctx, &svc_ns, &svc_name).await?;
        return Ok(Action::await_change());
    }

    let annotations = IngressAnnotations::parse(&*svc)?;

    let Some(tailnet_fqdn) = annotations.tailnet_fqdn.clone().filter(|f| !f.is_empty()) else {
        let _ = ctx
            .recorder()
            .publish_warning(
                &svc.object_ref(&()),
                "InvalidConfig",
                "egress Service needs 'tailnet-fqdn' in the config annotation: \
                 the tailnet destination to forward to",
            )
            .await;
        return Ok(Action::await_change());
    };

    // Egress proxies are tailnet *clients*: access grants describe who may
    // reach a destination, and host networking serves inbound reachability —
    // neither applies here. Warn so a copy-pasted config isn't silently
    // misleading, then continue.
    if !annotations.access.is_empty() {
        let _ = ctx
            .recorder()
            .publish_warning(
                &svc.object_ref(&()),
                "IgnoredConfig",
                "'access' does not apply to egress proxies; grant this proxy's \
                 tag access to the destination in the tailnet ACL instead",
            )
            .await;
    }
    if annotations.host_network {
        let _ = ctx
            .recorder()
            .publish_warning(
                &svc.object_ref(&()),
                "IgnoredConfig",
                "'host-network' does not apply to egress proxies; ignored",
            )
            .await;
    }

    let forwards = collect_tcp_forwards(&svc);
    if forwards.is_empty() {
        let _ = ctx
            .recorder()
            .publish_warning(
                &svc.object_ref(&()),
                "InvalidConfig",
                "egress Service declares no TCP ports; add spec.ports to forward them",
            )
            .await;
        return Ok(Action::await_change());
    }

    if namespace_is_deleting(&ctx.client, &svc_ns).await? {
        tracing::info!(
            name = svc_name,
            namespace = svc_ns,
            "egress Service: namespace is deleting; skipping"
        );
        return Ok(Action::await_change());
    }

    let instance_api: Api<HeadscaleInstance> = Api::namespaced(ctx.client.clone(), op_ns);
    let instance = match instance_api.get(&annotations.headscale_ref).await {
        Ok(inst) => inst,
        Err(kube::Error::Api(ref e)) if e.code == 404 => {
            let _ = ctx
                .recorder()
                .publish_warning(
                    &svc.object_ref(&()),
                    "Pending",
                    &format!(
                        "HeadscaleInstance '{}' does not exist",
                        annotations.headscale_ref
                    ),
                )
                .await;
            return Ok(Action::requeue(Duration::from_secs(30)));
        }
        Err(e) => return Err(Error::Kube(e)),
    };

    // Authorization release: watchedNamespaces no longer covers this Service.
    if !instance.spec.namespace_allowed(&svc_ns) {
        let _ = ctx
            .recorder()
            .publish_warning(
                &svc.object_ref(&()),
                "NamespaceExcluded",
                &format!(
                    "namespace '{}' is not in HeadscaleInstance \
                     '{}' watchedNamespaces; this Service is now orphaned",
                    svc_ns, annotations.headscale_ref,
                ),
            )
            .await;
        deregister_and_cleanup(
            ctx,
            op_ns,
            &names,
            &svc.object_ref(&()),
            &annotations.headscale_ref,
        )
        .await?;
        release_service(ctx, &svc_ns, &svc_name).await?;
        return Ok(Action::await_change());
    }

    if !instance.status.as_ref().is_some_and(|s| s.is_ready()) {
        let _ = ctx
            .recorder()
            .publish_warning(
                &svc.object_ref(&()),
                "Pending",
                &format!(
                    "HeadscaleInstance '{}' is not yet ready",
                    annotations.headscale_ref
                ),
            )
            .await;
        return Ok(Action::requeue(Duration::from_secs(5)));
    }

    let login_url = if instance.spec.external.is_some() {
        instance.spec.server_url.clone()
    } else {
        format!(
            "http://headscale-server-{}.{op_ns}.svc.cluster.local:8080",
            annotations.headscale_ref,
        )
    };

    let child = ChildApplier::for_proxy(
        ctx,
        op_ns,
        &names.proxy_base,
        &instance,
        labels::PARENT_KIND_SERVICE,
        &svc_name,
        &svc_ns,
    );

    let mut headscale = headscale_connect(ctx, op_ns, &annotations.headscale_ref).await?;

    // If headscale_ref changed, deregister from old HI and reset secrets before ensure_auth_key.
    let retarget = match Api::<Secret>::namespaced(ctx.client.clone(), op_ns)
        .get(&names.state_secret_name)
        .await
    {
        Ok(secret) => {
            let old_ref = read_secret_string(&secret, "headscale_ref");
            let old_node_id =
                read_secret_string(&secret, "device_id").and_then(|s| s.parse::<u64>().ok());
            old_ref
                .filter(|r| r != &annotations.headscale_ref)
                .map(|r| (r, old_node_id))
        }
        Err(kube::Error::Api(ref e)) if e.code == 404 => None,
        Err(e) => return Err(Error::Kube(e)),
    };
    if let Some((old_headscale_ref, old_node_id)) = retarget {
        if let Some(node_id) = old_node_id {
            match headscale_connect(ctx, op_ns, &old_headscale_ref).await {
                Ok(mut old_headscale) => {
                    match old_headscale
                        .delete_node(DeleteNodeRequest { node_id })
                        .await
                    {
                        Ok(_) => {}
                        Err(e) if e.code() == Code::NotFound => {}
                        Err(e) => return Err(Error::HeadscaleApi(e)),
                    }
                }
                Err(kube::Error::Api(ref ae)) if ae.code == 404 => {}
                Err(e) => return Err(Error::Kube(e)),
            }
        }
        delete_ignoring_404(
            Api::<Secret>::namespaced(ctx.client.clone(), op_ns),
            &names.config_secret_name,
        )
        .await?;
        delete_ignoring_404(
            Api::<Secret>::namespaced(ctx.client.clone(), op_ns),
            &names.state_secret_name,
        )
        .await?;
    }

    if let AuthKeyStatus::WaitingForUser = ensure_auth_key(
        ctx,
        op_ns,
        &svc.object_ref(&()),
        &mut headscale,
        &child,
        &names,
        annotations.user.as_deref(),
        &annotations.managed_key_tags,
        None,
        annotations.auth_key_expiry_secs,
        annotations.auth_key_reusable,
    )
    .await?
    {
        return Ok(Action::requeue(Duration::from_secs(30)));
    }

    let state_secret = ensure_state_secret(&child, &names, &annotations.headscale_ref).await?;

    // The egress ClusterIP Service: declared port → socat listener port.
    // apply_service stamps the selector, targeting only this proxy's pods.
    child
        .apply_service(
            PROXY_COMPONENT,
            Service::new(&names.wg_service_name).spec(ServiceSpec {
                ports: Some(
                    forwards
                        .iter()
                        .enumerate()
                        .map(|(idx, (port, _))| {
                            ServicePort::tcp(format!("fwd-{port}"), *port)
                                .target_port(LISTEN_PORT_BASE + idx as i32)
                        })
                        .collect(),
                ),
                ..Default::default()
            }),
        )
        .await?;

    apply_proxy_rbac(&child, &names).await?;

    child
        .apply_statefulset(
            PROXY_COMPONENT,
            build_egress_statefulset(
                &names,
                &ctx.proxy_image,
                &ctx.socat_image,
                &login_url,
                &annotations.hostname,
                &tailnet_fqdn,
                &forwards,
            ),
        )
        .await?;

    // Point the annotated Service at the egress proxy and record ownership.
    // spec.externalName is operator-owned on adopted Services; the user's
    // original value is a placeholder.
    Api::<Service>::namespaced(ctx.client.clone(), &svc_ns)
        .patch(
            &svc_name,
            &PatchParams::apply(&crate::field_manager(op_ns)).force(),
            &Patch::Apply(serde_json::json!({
                "apiVersion": "v1",
                "kind": "Service",
                "metadata": {
                    "name": svc_name,
                    "namespace": svc_ns,
                    "annotations": {
                        crate::ANNOTATION_CLAIMED_BY: op_ns,
                    }
                },
                "spec": {
                    "type": EXTERNAL_NAME_TYPE,
                    "externalName": format!(
                        "{}.{op_ns}.svc.cluster.local",
                        names.wg_service_name
                    ),
                }
            })),
        )
        .await
        .map_err(Error::Kube)?;

    let device_id = read_secret_string(&state_secret, "device_id");
    let device_ips =
        read_secret_json::<Vec<String>>(&state_secret, "device_ips").unwrap_or_default();

    // Keep the registered node's ACL tags in sync with the desired state on
    // every reconcile (see the Ingress controller for rationale).
    let mut set_tags_failed = false;
    let desired_tags: Vec<String> = annotations
        .managed_key_tags
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    if let Some(node_id) = device_id.as_ref().and_then(|s| s.parse::<u64>().ok())
        && !desired_tags.is_empty()
        && let Err(e) = headscale
            .set_tags(SetTagsRequest {
                node_id,
                tags: desired_tags,
            })
            .await
    {
        tracing::warn!(
            name = svc_name,
            node_id,
            error = %e,
            "failed to set ACL tags on headscale node; will retry on next reconcile"
        );
        set_tags_failed = true;
    }

    if device_id.is_some() {
        if device_ips.is_empty() {
            tracing::info!(
                name = svc_name,
                tailnet_fqdn,
                "egress Service: proxy registered but waiting for IP assignment"
            );
        } else {
            let _ = ctx.recorder().publish_ready(&svc.object_ref(&())).await;
        }
    } else {
        tracing::info!(
            name = svc_name,
            tailnet_fqdn,
            "egress Service: waiting for proxy to register"
        );
        let _ = ctx
            .recorder()
            .publish_warning(
                &svc.object_ref(&()),
                "ProxyNotRegistered",
                &format!(
                    "egress proxy for Service '{svc_name}' has not registered with headscale; \
                     if this persists beyond the auth-key expiry window, delete the \
                     Secret '{}' to force key rotation",
                    names.config_secret_name
                ),
            )
            .await;
    }

    super::dns::sync_egress_dns(ctx).await?;

    if set_tags_failed {
        return Ok(Action::requeue(Duration::from_secs(30)));
    }
    Ok(Action::await_change())
}

/// Collects `(service_port, backend_port)` pairs from the Service's declared
/// ports. Only TCP is forwardable; UDP/SCTP entries are skipped with a
/// warning. An integer `targetPort` overrides the destination port on the
/// tailnet host; named target ports are meaningless there and fall back to
/// `port`.
fn collect_tcp_forwards(svc: &Service) -> Vec<(i32, i32)> {
    use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
    svc.spec
        .as_ref()
        .and_then(|s| s.ports.as_ref())
        .into_iter()
        .flatten()
        .filter(|p| {
            let tcp = p.protocol.as_deref().is_none_or(|proto| proto == "TCP");
            if !tcp {
                tracing::warn!(
                    service = svc.name_any(),
                    port = p.port,
                    protocol = p.protocol.as_deref().unwrap_or_default(),
                    "egress Service: non-TCP port skipped; only TCP is forwarded"
                );
            }
            tcp
        })
        .map(|p| {
            let backend = match &p.target_port {
                Some(IntOrString::Int(n)) => *n,
                _ => p.port,
            };
            (p.port, backend)
        })
        .collect()
}

fn build_egress_statefulset(
    names: &ProxyNames,
    proxy_image: &str,
    socat_image: &str,
    headscale_url: &str,
    hostname: &str,
    tailnet_fqdn: &str,
    forwards: &[(i32, i32)],
) -> StatefulSet {
    let tailscale = Container::new("tailscale")
        .image(proxy_image)
        .allow_privilege_escalation(false)
        .drop_capabilities(["ALL"])
        .env([
            EnvVar::secret_key_ref("TS_AUTHKEY", &names.config_secret_name, "key"),
            EnvVar::value("TS_HOSTNAME", hostname),
            // TS_EXTRA_ARGS → passed to `tailscale up` (CLI flags only).
            EnvVar::value(
                "TS_EXTRA_ARGS",
                format!(
                    "--login-server={headscale_url} \
                     --advertise-exit-node=false \
                     --snat-subnet-routes=false \
                     --stateful-filtering=false"
                ),
            ),
            // Outbound-only client: no pinned WireGuard port, no serve
            // config. --socket places the IPC socket in /tmp which is
            // writable in restricted containers.
            EnvVar::value("TS_TAILSCALED_EXTRA_ARGS", "--socket=/tmp/tailscaled.sock"),
            EnvVar::value("TS_USERSPACE", "true"),
            // Loopback SOCKS5: the forwarder shares the pod network
            // namespace and dials the tailnet through it; nothing outside
            // the pod can reach it.
            EnvVar::value("TS_SOCKS5_SERVER", format!("localhost:{SOCKS5_PORT}")),
            EnvVar::value("TS_KUBE_SECRET", &names.state_secret_name),
            EnvVar::metadata_name("POD_NAME"),
            EnvVar::metadata_namespace("POD_NAMESPACE"),
        ]);
    let forwarder = Container::new("forwarder")
        .image(socat_image)
        .allow_privilege_escalation(false)
        .drop_capabilities(["ALL"])
        .command(["/bin/sh", "-c", &forwarder_script(tailnet_fqdn, forwards)])
        .ports(
            forwards
                .iter()
                .enumerate()
                .map(|(idx, (port, _))| ContainerPort {
                    name: Some(format!("fwd-{port}")),
                    container_port: LISTEN_PORT_BASE + idx as i32,
                    protocol: Some("TCP".to_string()),
                    ..Default::default()
                }),
        );
    let mut base = PodSpec::container(tailscale).service_account_name(&names.proxy_name);
    base.containers.push(forwarder);
    let pod_spec = PodSpec {
        security_context: Some(PodSecurityContext {
            seccomp_profile: Some(SeccompProfile {
                type_: "RuntimeDefault".into(),
                localhost_profile: None,
            }),
            ..Default::default()
        }),
        ..base
    };
    StatefulSet::new(&names.proxy_name)
        .replicas(1)
        .service_name(&names.wg_service_name)
        .template(PodTemplateSpec::new().pod_spec(pod_spec))
}

/// One socat per forward, all backgrounded, `wait` keeping the container
/// alive. SOCKS5-CONNECT passes the tailnet FQDN through to tailscaled's
/// SOCKS5 server unresolved, so MagicDNS resolution and ACL enforcement
/// happen inside the tailnet client — the pod needs no route or DNS for the
/// tailnet at all.
fn forwarder_script(tailnet_fqdn: &str, forwards: &[(i32, i32)]) -> String {
    let mut lines: Vec<String> = forwards
        .iter()
        .enumerate()
        .map(|(idx, (_, backend))| {
            format!(
                "socat TCP-LISTEN:{listen},fork,reuseaddr \
                 SOCKS5-CONNECT:127.0.0.1:{SOCKS5_PORT}:{tailnet_fqdn}:{backend} &",
                listen = LISTEN_PORT_BASE + idx as i32,
            )
        })
        .collect();
    lines.push("wait".to_string());
    lines.join("\n")
}

// ── cleanup ───────────────────────────────────────────────────────────────────

async fn cleanup(svc: Arc<Service>, ctx: &Context) -> Result<Action, Error> {
    let svc_ns = svc.namespace().unwrap_or_default();
    let svc_name = svc.name_any();
    let names = ProxyNames::for_service(&svc_ns, &svc_name);
    let headscale_ref_fallback = IngressAnnotations::headscale_ref(&*svc);
    deregister_and_cleanup(
        ctx,
        &ctx.operator_namespace,
        &names,
        &svc.object_ref(&()),
        headscale_ref_fallback.as_deref().unwrap_or(""),
    )
    .await?;
    super::dns::sync_egress_dns(ctx).await?;
    Ok(Action::await_change())
}

/// Removes our finalizer from the Service and clears the `claimed-by`
/// annotation. Same optimistic-lock dance as the Ingress controller's
/// `release_ingress`.
async fn release_service(ctx: &Context, svc_ns: &str, svc_name: &str) -> Result<(), Error> {
    let api = Api::<Service>::namespaced(ctx.client.clone(), svc_ns);
    let live = api.get(svc_name).await.map_err(Error::Kube)?;
    let our_finalizer = crate::finalizer(&ctx.operator_namespace);
    let remaining: Vec<String> = live
        .finalizers()
        .iter()
        .filter(|f| f.as_str() != our_finalizer)
        .cloned()
        .collect();
    let resource_version = live.resource_version().unwrap_or_default();
    api.patch(
        svc_name,
        &PatchParams::default(),
        &Patch::Merge(serde_json::json!({
            "metadata": {
                "resourceVersion": resource_version,
                "finalizers": remaining,
                "annotations": {
                    crate::ANNOTATION_CLAIMED_BY: serde_json::Value::Null,
                }
            }
        })),
    )
    .await
    .map_err(Error::Kube)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controllers::ingress::test_support::test_ctx;
    use crate::test_support::{FaultService, all_500};
    use k8s_openapi::api::core::v1::ServicePort as CoreServicePort;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
    use std::collections::BTreeMap;

    fn egress_service(annotation: Option<&str>) -> Service {
        Service {
            metadata: ObjectMeta {
                name: Some("qbittorrent".to_string()),
                namespace: Some("media".to_string()),
                uid: Some("00000000-0000-0000-0000-000000000002".to_string()),
                annotations: annotation
                    .map(|a| BTreeMap::from([(ANNOTATION_CONFIG.to_string(), a.to_string())])),
                ..Default::default()
            },
            spec: Some(ServiceSpec {
                type_: Some("ExternalName".to_string()),
                external_name: Some("placeholder".to_string()),
                ports: Some(vec![CoreServicePort {
                    port: 443,
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    // ── forwarder tests ───────────────────────────────────────────────────────

    #[test]
    fn forwarder_script_one_socat_per_port_via_socks5() {
        let script = forwarder_script("qbittorrent.ts.example.com", &[(443, 443), (8080, 9090)]);
        assert_eq!(
            script,
            "socat TCP-LISTEN:10000,fork,reuseaddr \
             SOCKS5-CONNECT:127.0.0.1:1055:qbittorrent.ts.example.com:443 &\n\
             socat TCP-LISTEN:10001,fork,reuseaddr \
             SOCKS5-CONNECT:127.0.0.1:1055:qbittorrent.ts.example.com:9090 &\n\
             wait"
        );
    }

    #[test]
    fn egress_statefulset_has_socks5_and_no_serve_config() {
        let names = ProxyNames::for_service("media", "qbittorrent");
        let sts = build_egress_statefulset(
            &names,
            "tailscale/tailscale:stable",
            "alpine/socat:1.8.0.3",
            "https://headscale.example.com",
            "egress-qbittorrent",
            "qbittorrent.ts.example.com",
            &[(443, 443)],
        );
        let pod = sts.spec.as_ref().unwrap().template.spec.as_ref().unwrap();
        let ts = pod
            .containers
            .iter()
            .find(|c| c.name == "tailscale")
            .unwrap();
        let env_names: Vec<_> = ts
            .env
            .as_ref()
            .unwrap()
            .iter()
            .map(|e| e.name.as_str())
            .collect();
        assert!(env_names.contains(&"TS_SOCKS5_SERVER"));
        assert!(
            !env_names.contains(&"TS_SERVE_CONFIG"),
            "egress proxies serve nothing inbound"
        );
        assert!(
            !env_names.contains(&"TS_DEBUG_PRETENDPOINT"),
            "egress proxies advertise no endpoint"
        );
        let fwd = pod
            .containers
            .iter()
            .find(|c| c.name == "forwarder")
            .unwrap();
        assert_eq!(
            fwd.ports.as_ref().unwrap()[0].container_port,
            10000,
            "listeners start at the unprivileged base port"
        );
    }

    #[test]
    fn collect_forwards_defaults_backend_to_port() {
        let svc = egress_service(None);
        assert_eq!(collect_tcp_forwards(&svc), vec![(443, 443)]);
    }

    #[test]
    fn collect_forwards_honors_integer_target_port() {
        let mut svc = egress_service(None);
        svc.spec.as_mut().unwrap().ports = Some(vec![CoreServicePort {
            port: 443,
            target_port: Some(IntOrString::Int(8443)),
            ..Default::default()
        }]);
        assert_eq!(collect_tcp_forwards(&svc), vec![(443, 8443)]);
    }

    #[test]
    fn collect_forwards_ignores_named_target_port() {
        let mut svc = egress_service(None);
        svc.spec.as_mut().unwrap().ports = Some(vec![CoreServicePort {
            port: 443,
            target_port: Some(IntOrString::String("https".to_string())),
            ..Default::default()
        }]);
        assert_eq!(
            collect_tcp_forwards(&svc),
            vec![(443, 443)],
            "named targetPort is meaningless for a tailnet host; use port"
        );
    }

    #[test]
    fn collect_forwards_skips_udp_ports() {
        let mut svc = egress_service(None);
        svc.spec.as_mut().unwrap().ports = Some(vec![
            CoreServicePort {
                port: 53,
                protocol: Some("UDP".to_string()),
                ..Default::default()
            },
            CoreServicePort {
                port: 853,
                protocol: Some("TCP".to_string()),
                ..Default::default()
            },
        ]);
        assert_eq!(collect_tcp_forwards(&svc), vec![(853, 853)]);
    }

    // ── adoption gate tests ───────────────────────────────────────────────────

    #[tokio::test]
    async fn reconcile_skips_service_without_annotation() {
        let ctx = Arc::new(test_ctx(FaultService::client(all_500)));
        let svc = Arc::new(egress_service(None));
        let result = reconcile(svc, ctx).await;
        assert!(
            result.is_ok(),
            "Service without our annotation must be silently skipped"
        );
    }

    #[tokio::test]
    async fn reconcile_skips_non_external_name_service() {
        let ctx = Arc::new(test_ctx(FaultService::client(all_500)));
        let mut svc = egress_service(Some(
            r#"{"headscale-ref":"main","user":"alice","tailnet-fqdn":"x.ts.example.com"}"#,
        ));
        svc.spec.as_mut().unwrap().type_ = Some("ClusterIP".to_string());
        let result = reconcile(Arc::new(svc), ctx).await;
        assert!(
            result.is_ok(),
            "annotated non-ExternalName Service must be silently skipped"
        );
    }

    #[tokio::test]
    async fn reconcile_skips_service_targeted_at_other_deployment() {
        let ctx = Arc::new(test_ctx(FaultService::client(all_500)));
        let svc = Arc::new(egress_service(Some(
            r#"{"headscale-ref":"main","user":"alice","headscale-namespace":"other-ns"}"#,
        )));
        let result = reconcile(svc, ctx).await;
        assert!(
            result.is_ok(),
            "Service targeting another deployment must be silently skipped"
        );
    }

    #[tokio::test]
    async fn reconcile_processes_service_when_claim_default_true() {
        let ctx = Arc::new(test_ctx(FaultService::client(all_500)));
        let svc = Arc::new(egress_service(Some(
            r#"{"headscale-ref":"main","user":"alice","tailnet-fqdn":"x.ts.example.com"}"#,
        )));
        let result = reconcile(svc, ctx).await;
        assert!(
            result.is_err(),
            "default deployment must process annotated egress Services (K8s call expected)"
        );
    }
}
