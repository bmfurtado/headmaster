//! Tailnet exposure for Services — the ingress direction, without an
//! `Ingress` object. A non-ExternalName Service carrying the headmaster
//! config annotation gets its own proxy pod that joins the tailnet as its
//! own node (own MagicDNS name and tags), forwarding tailnet traffic to the
//! Service. Two forwarding modes, chosen by the annotation's `mode` field:
//!
//! - **tsnet** (default): userspace tailscaled (netstack) with a serve
//!   config of one raw TCP forward per declared Service port, dialing the
//!   Service's cluster DNS name. No privileges needed.
//! - **tun**: real tailscaled with a TUN device (`TS_USERSPACE=false`),
//!   DNAT-ing all tailnet traffic for the node to the Service's ClusterIP
//!   in-kernel (`TS_DEST_IP`). Built for high-bandwidth services; the pod
//!   needs `/dev/net/tun` (see [`crate::context::TunDeviceAccess`]). The
//!   pre-auth key is minted ephemeral so headscale garbage-collects the
//!   node if the operator's explicit delete on teardown ever fails.
//!
//! Shares the proxy building blocks (names, auth keys, cleanup, headscale
//! connection) with the Ingress and egress controllers via
//! [`crate::controllers::proxy`].

use std::sync::Arc;
use std::time::Duration;

use headscale_client::headscale::v1::SetTagsRequest;
use k8s_openapi::api::core::v1::{ConfigMap, Service};
use k8s_openapi::api::networking::v1::NetworkPolicy;
use kube::api::{Api, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::{Resource, ResourceExt};

use crate::context::Context;
use crate::controllers::applier::{ChildApplier, delete_ignoring_404};
use crate::controllers::proxy::{
    AuthKeyStatus, Error, ProxyNames, ProxyNetworking, apply_proxy_rbac, apply_proxy_statefulset,
    apply_serve_configmap, apply_tun_proxy_statefulset, apply_wireguard_service,
    deregister_and_cleanup, ensure_auth_key, ensure_state_secret, headscale_connect,
    namespace_is_deleting, read_secret_json, read_secret_string, reset_if_retargeted,
    rotate_stale_auth_key,
};
use crate::controllers::recorder::RecorderExt;
use crate::labels;
use crate::types::{HeadscaleInstance, IngressAnnotations, ProxyMode, ResourceStatus};

pub(super) async fn apply_expose(svc: Arc<Service>, ctx: &Context) -> Result<Action, Error> {
    let svc_ns = svc.namespace().unwrap_or_default();
    let svc_name = svc.name_any();
    let op_ns = &ctx.operator_namespace;
    let names = ProxyNames::for_service(&svc_ns, &svc_name);

    let annotations = IngressAnnotations::parse(&*svc)?;

    // tailnet-fqdn and consumers are egress Service knobs; on an exposed
    // Service they can only be a copy-paste mistake (or a Service the user
    // forgot to make ExternalName), and silently ignoring them would mislead.
    if annotations.tailnet_fqdn.is_some() || !annotations.consumers.is_empty() {
        let _ = ctx
            .recorder()
            .publish_warning(
                &svc.object_ref(&()),
                "InvalidConfig",
                "'tailnet-fqdn' and 'consumers' do not apply to exposed Services; \
                 they configure egress ExternalName Services",
            )
            .await;
        return Ok(Action::await_change());
    }

    // Access grants need the auto-tag + policy machinery the Ingress
    // controller runs; exposed Services don't have it (yet). Warn so the
    // field isn't silently dead, then continue.
    if !annotations.access.is_empty() {
        let _ = ctx
            .recorder()
            .publish_warning(
                &svc.object_ref(&()),
                "IgnoredConfig",
                "'access' is not supported on exposed Services; grant access to \
                 this proxy's tag in the tailnet ACL instead",
            )
            .await;
    }

    // A host-networked kernel tailscaled would put the TUN device and DNAT
    // rules in the node's own network namespace, fighting the node's
    // tailscaled. tun proxies always stay on the pod network.
    let host_network = match annotations.mode {
        ProxyMode::Tun if annotations.host_network => {
            let _ = ctx
                .recorder()
                .publish_warning(
                    &svc.object_ref(&()),
                    "IgnoredConfig",
                    "'host-network' does not apply to tun-mode proxies; ignored",
                )
                .await;
            false
        }
        _ => annotations.host_network,
    };

    let ports = collect_expose_tcp_ports(&svc);
    if annotations.mode == ProxyMode::Tsnet && ports.is_empty() {
        let _ = ctx
            .recorder()
            .publish_warning(
                &svc.object_ref(&()),
                "InvalidConfig",
                "exposed Service declares no TCP ports; add spec.ports so the \
                 tsnet proxy knows what to forward",
            )
            .await;
        return Ok(Action::await_change());
    }

    // tun mode DNATs to the ClusterIP, not a DNS name: headless Services
    // have nothing to DNAT to.
    let cluster_ip = svc
        .spec
        .as_ref()
        .and_then(|s| s.cluster_ip.clone())
        .filter(|ip| ip != "None" && !ip.is_empty());
    if annotations.mode == ProxyMode::Tun && cluster_ip.is_none() {
        let _ = ctx
            .recorder()
            .publish_warning(
                &svc.object_ref(&()),
                "InvalidConfig",
                "tun mode requires a ClusterIP to DNAT to; headless Services \
                 can only be exposed in tsnet mode",
            )
            .await;
        return Ok(Action::await_change());
    }

    if namespace_is_deleting(&ctx.client, &svc_ns).await? {
        tracing::info!(
            name = svc_name,
            namespace = svc_ns,
            "exposed Service: namespace is deleting; skipping"
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
        super::reconcile::release_service(ctx, &svc_ns, &svc_name).await?;
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
    reset_if_retargeted(ctx, op_ns, &names, &annotations.headscale_ref).await?;

    // A proxy that lost its headscale registration (or whose key expired
    // before it ever joined) is stuck on a dead key; clear the stale Secrets
    // so ensure_auth_key below mints a fresh one this same reconcile.
    rotate_stale_auth_key(
        ctx,
        op_ns,
        &svc.object_ref(&()),
        &mut headscale,
        &names,
        annotations.auth_key_expiry_secs,
    )
    .await?;

    // tun nodes register with an ephemeral key: if the explicit node delete
    // on teardown is ever missed, headscale garbage-collects the node once
    // it goes offline.
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
        annotations.mode == ProxyMode::Tun,
    )
    .await?
    {
        return Ok(Action::requeue(Duration::from_secs(30)));
    }

    let state_secret = ensure_state_secret(&child, &names, &annotations.headscale_ref).await?;

    let networking = apply_wireguard_service(&child, &names, host_network).await?;

    apply_proxy_rbac(&child, &names).await?;

    match annotations.mode {
        ProxyMode::Tsnet => {
            // Forward to the Service's cluster DNS name, not its ClusterIP:
            // the pod resolves it on every dial, so an IP change never needs
            // a pod roll in this mode.
            let backend_host = format!("{svc_name}.{svc_ns}.svc.cluster.local");
            let serve_json = build_expose_serve_json(&backend_host, &ports);
            apply_serve_configmap(&child, &names, &serve_json).await?;
            apply_proxy_statefulset(
                &child,
                &names,
                &ctx.proxy_image,
                &login_url,
                &annotations.hostname,
                &networking,
            )
            .await?;
        }
        ProxyMode::Tun => {
            let dest_ip = cluster_ip.expect("checked above for tun mode");
            let node_port = match networking {
                ProxyNetworking::NodePort { node_port } => node_port,
                ProxyNetworking::Host => {
                    panic!("BUG: tun proxies always request pod networking")
                }
            };
            apply_tun_proxy_statefulset(
                &child,
                &names,
                &ctx.proxy_image,
                &login_url,
                &annotations.hostname,
                &dest_ip,
                node_port,
                &ctx.tun_device,
            )
            .await?;
            // A leftover serve ConfigMap from a previous tsnet mode would
            // outlive every rebuild of the StatefulSet; drop it.
            delete_ignoring_404(
                Api::<ConfigMap>::namespaced(ctx.client.clone(), op_ns),
                &names.serve_configmap_name,
            )
            .await?;
        }
    }

    // Exposed Services never carry a consumers NetworkPolicy; drop one left
    // behind by a previous egress (ExternalName) shape of this Service.
    delete_ignoring_404(
        Api::<NetworkPolicy>::namespaced(ctx.client.clone(), op_ns),
        &names.proxy_name,
    )
    .await?;

    // Record ownership so observers can discover which operator deployment
    // manages this Service without inspecting finalizers.
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
                hostname = annotations.hostname,
                "exposed Service: proxy registered but waiting for IP assignment"
            );
        } else {
            let _ = ctx.recorder().publish_ready(&svc.object_ref(&())).await;
        }
    } else {
        tracing::info!(
            name = svc_name,
            hostname = annotations.hostname,
            "exposed Service: waiting for proxy to register"
        );
        let _ = ctx
            .recorder()
            .publish_warning(
                &svc.object_ref(&()),
                "ProxyNotRegistered",
                &format!(
                    "proxy for exposed Service '{svc_name}' has not registered with \
                     headscale; if this persists beyond the auth-key expiry window, \
                     delete the Secret '{}' to force key rotation",
                    names.config_secret_name
                ),
            )
            .await;
    }

    if set_tags_failed {
        return Ok(Action::requeue(Duration::from_secs(30)));
    }
    Ok(Action::await_change())
}

/// Collects the Service ports a tsnet-mode proxy forwards. Only TCP is
/// forwardable through the serve config; UDP/SCTP entries are skipped with a
/// warning (tun mode forwards them — its DNAT is protocol-agnostic). The
/// proxy dials the Service itself, so `targetPort` mapping stays kube-proxy's
/// job and only `port` matters here.
fn collect_expose_tcp_ports(svc: &Service) -> Vec<i32> {
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
                    "exposed Service: non-TCP port skipped in tsnet mode; \
                     use mode 'tun' to forward it"
                );
            }
            tcp
        })
        .map(|p| p.port)
        .collect()
}

/// Builds the serve.json for a tsnet-mode exposed Service: one raw TCP
/// forward per declared port, terminating nothing — TLS and protocol stay
/// end-to-end between the tailnet peer and the backend.
fn build_expose_serve_json(backend_host: &str, ports: &[i32]) -> serde_json::Value {
    let tcp: serde_json::Map<String, serde_json::Value> = ports
        .iter()
        .map(|port| {
            (
                port.to_string(),
                serde_json::json!({"TCPForward": format!("{backend_host}:{port}")}),
            )
        })
        .collect();
    serde_json::json!({ "TCP": tcp })
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::{ServicePort, ServiceSpec};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;

    fn expose_service(ports: Vec<ServicePort>) -> Service {
        Service {
            metadata: ObjectMeta {
                name: Some("my-app".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: Some(ServiceSpec {
                cluster_ip: Some("10.43.0.15".to_string()),
                ports: Some(ports),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn expose_serve_json_one_tcp_forward_per_port() {
        let json = build_expose_serve_json("my-app.default.svc.cluster.local", &[443, 8080]);
        assert_eq!(
            json,
            serde_json::json!({
                "TCP": {
                    "443": {"TCPForward": "my-app.default.svc.cluster.local:443"},
                    "8080": {"TCPForward": "my-app.default.svc.cluster.local:8080"},
                }
            })
        );
    }

    #[test]
    fn collect_expose_ports_skips_udp() {
        let svc = expose_service(vec![
            ServicePort {
                port: 53,
                protocol: Some("UDP".to_string()),
                ..Default::default()
            },
            ServicePort {
                port: 853,
                protocol: Some("TCP".to_string()),
                ..Default::default()
            },
        ]);
        assert_eq!(collect_expose_tcp_ports(&svc), vec![853]);
    }

    #[test]
    fn collect_expose_ports_ignores_target_port() {
        // The proxy dials the Service, so kube-proxy owns the port→targetPort
        // mapping; the serve config must use the declared Service port.
        let svc = expose_service(vec![ServicePort {
            port: 443,
            target_port: Some(IntOrString::Int(8443)),
            ..Default::default()
        }]);
        assert_eq!(collect_expose_tcp_ports(&svc), vec![443]);
    }
}
