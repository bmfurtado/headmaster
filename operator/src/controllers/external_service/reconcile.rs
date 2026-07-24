//! Main reconcile loop for ExternalName `Service` objects. Provisions a
//! Tailscale proxy for every ExternalName Service carrying the headmaster
//! config annotation, and cleans up all proxy resources on deletion.

use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use headscale_client::Code;
use headscale_client::headscale::v1::{DeleteNodeRequest, SetTagsRequest};
use k8s_openapi::api::core::v1::{Secret, Service};
use kube::api::{Api, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::runtime::finalizer::{Event as Finalizer, finalizer};
use kube::runtime::reflector::ObjectRef;
use kube::runtime::watcher;
use kube::{Resource, ResourceExt};

use crate::context::Context;
use crate::controllers::applier::ChildApplier;
use crate::controllers::proxy::{
    AuthKeyStatus, Error, ProxyNames, apply_proxy_rbac, apply_proxy_statefulset,
    apply_serve_configmap, apply_wireguard_service, cleanup_proxy_resources,
    deregister_and_cleanup, ensure_auth_key, ensure_state_secret, headscale_connect,
    namespace_is_deleting, read_secret_json, read_secret_string, service_auto_tag,
};
use crate::controllers::recorder::RecorderExt;
use crate::labels;
use crate::types::{ANNOTATION_CONFIG, HeadscaleInstance, IngressAnnotations, ResourceStatus};

const EXTERNAL_NAME_TYPE: &str = "ExternalName";

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
                tracing::warn!("ExternalName Service reconcile error: {e:?}");
            }
        })
}

// ── reconcile ─────────────────────────────────────────────────────────────────

fn error_policy(obj: Arc<Service>, e: &Error, _ctx: Arc<Context>) -> Action {
    tracing::warn!(
        name = obj.name_any(),
        "ExternalName Service reconcile failed: {e:?}"
    );
    Action::requeue(Duration::from_secs(30))
}

fn is_external_name(svc: &Service) -> bool {
    svc.spec.as_ref().and_then(|s| s.type_.as_deref()) == Some(EXTERNAL_NAME_TYPE)
}

async fn reconcile(svc: Arc<Service>, ctx: Arc<Context>) -> Result<Action, Error> {
    let our_finalizer = crate::finalizer(&ctx.operator_namespace);
    let has_our_finalizer = svc.finalizers().iter().any(|f| f == &our_finalizer);

    let is_ours_shape = is_external_name(&svc) && svc.annotations().contains_key(ANNOTATION_CONFIG);
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
    // ExternalName (e.g. converted to ClusterIP). Deregister and relinquish.
    if !is_external_name(&svc) || !svc.annotations().contains_key(ANNOTATION_CONFIG) {
        if let Some(headscale_ref) = IngressAnnotations::headscale_ref(&*svc) {
            deregister_and_cleanup(ctx, op_ns, &names, &svc.object_ref(&()), &headscale_ref)
                .await?;
        } else {
            cleanup_proxy_resources(ctx, op_ns, &names).await;
        }
        release_service(ctx, &svc_ns, &svc_name).await?;
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

    if namespace_is_deleting(&ctx.client, &svc_ns).await? {
        tracing::info!(
            name = svc_name,
            namespace = svc_ns,
            "ExternalName Service: namespace is deleting; skipping"
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

    let Some(external_name) = svc
        .spec
        .as_ref()
        .and_then(|s| s.external_name.clone())
        .filter(|n| !n.is_empty())
    else {
        let _ = ctx
            .recorder()
            .publish_warning(
                &svc.object_ref(&()),
                "InvalidConfig",
                "ExternalName Service has no spec.externalName",
            )
            .await;
        return Ok(Action::await_change());
    };

    let forwards = collect_tcp_forwards(&svc);
    if forwards.is_empty() {
        let _ = ctx
            .recorder()
            .publish_warning(
                &svc.object_ref(&()),
                "InvalidConfig",
                "ExternalName Service declares no TCP ports; add spec.ports to expose it",
            )
            .await;
        return Ok(Action::await_change());
    }

    let dns_base_domain = instance.spec.dns_base_domain.clone();
    let login_url = if instance.spec.external.is_some() {
        instance.spec.server_url.clone()
    } else {
        format!(
            "http://headscale-server-{}.{op_ns}.svc.cluster.local:8080",
            annotations.headscale_ref,
        )
    };
    let tailnet_fqdn = format!("{}.{dns_base_domain}", annotations.hostname);

    let child = ChildApplier::for_proxy(
        ctx,
        op_ns,
        &names.proxy_base,
        &instance,
        labels::PARENT_KIND_SERVICE,
        &svc_name,
        &svc_ns,
    );

    for grant in &annotations.access {
        if grant.from.is_empty() {
            let _ = ctx
                .recorder()
                .publish_warning(
                    &svc.object_ref(&()),
                    "InvalidConfig",
                    "access grant 'from' must not be empty",
                )
                .await;
            return Ok(Action::await_change());
        }
    }

    let auto_tag = if !annotations.access.is_empty() {
        Some(service_auto_tag(&svc_ns, &svc_name))
    } else {
        None
    };

    let mut headscale = headscale_connect(ctx, op_ns, &annotations.headscale_ref).await?;

    let networking = apply_wireguard_service(&child, &names, annotations.host_network).await?;

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
        crate::controllers::applier::delete_ignoring_404(
            Api::<Secret>::namespaced(ctx.client.clone(), op_ns),
            &names.config_secret_name,
        )
        .await?;
        crate::controllers::applier::delete_ignoring_404(
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
        auto_tag.as_deref(),
        annotations.auth_key_expiry_secs,
        annotations.auth_key_reusable,
    )
    .await?
    {
        return Ok(Action::requeue(Duration::from_secs(30)));
    }

    let state_secret = ensure_state_secret(&child, &names, &annotations.headscale_ref).await?;

    let serve_json = build_tcp_serve_json(&external_name, &forwards);
    apply_serve_configmap(&child, &names, &serve_json).await?;

    apply_proxy_rbac(&child, &names).await?;

    apply_proxy_statefulset(
        &child,
        &names,
        &ctx.proxy_image,
        &login_url,
        &annotations.hostname,
        &networking,
    )
    .await?;

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
        .chain(auto_tag.iter().cloned())
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
                fqdn = tailnet_fqdn,
                "ExternalName Service: proxy registered but waiting for IP assignment"
            );
        } else {
            let _ = ctx.recorder().publish_ready(&svc.object_ref(&())).await;
        }
    } else {
        tracing::info!(
            name = svc_name,
            hostname = annotations.hostname,
            "ExternalName Service: waiting for proxy to register"
        );
        let _ = ctx
            .recorder()
            .publish_warning(
                &svc.object_ref(&()),
                "ProxyNotRegistered",
                &format!(
                    "proxy for Service '{svc_name}' has not registered with headscale; \
                     if this persists beyond the auth-key expiry window, delete the \
                     Secret '{}' to force key rotation",
                    names.config_secret_name
                ),
            )
            .await;
    }

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

    if set_tags_failed {
        return Ok(Action::requeue(Duration::from_secs(30)));
    }
    Ok(Action::await_change())
}

/// Collects `(tailnet_port, backend_port)` pairs from the Service's declared
/// ports. Only TCP ports are usable — tailscale serve's TCPForward is TCP-only
/// — so UDP/SCTP entries are skipped with a warning. An integer `targetPort`
/// overrides the backend port; named target ports are meaningless for an
/// external host and fall back to `port`.
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
                    "ExternalName Service: non-TCP port skipped; \
                     tailscale serve only forwards TCP"
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

/// Builds the tailscale serve config: one raw TCP forward per declared port,
/// straight to the external hostname. No TLS termination, no HTTP handling —
/// bytes in, bytes out.
fn build_tcp_serve_json(external_name: &str, forwards: &[(i32, i32)]) -> serde_json::Value {
    let tcp: serde_json::Map<String, serde_json::Value> = forwards
        .iter()
        .map(|(listen, backend)| {
            (
                listen.to_string(),
                serde_json::json!({ "TCPForward": format!("{external_name}:{backend}") }),
            )
        })
        .collect();
    serde_json::json!({ "TCP": tcp })
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
    Ok(Action::await_change())
}

/// Removes our finalizer from the Service and clears the `claimed-by`
/// annotation. Same optimistic-lock dance as the Ingress controller's
/// `release_ingress`; Services carry no operator-written status to clear.
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
    use k8s_openapi::api::core::v1::{ServicePort, ServiceSpec};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
    use std::collections::BTreeMap;

    fn external_name_service(annotation: Option<&str>) -> Service {
        Service {
            metadata: ObjectMeta {
                name: Some("ext-db".to_string()),
                namespace: Some("apps".to_string()),
                uid: Some("00000000-0000-0000-0000-000000000002".to_string()),
                annotations: annotation
                    .map(|a| BTreeMap::from([(ANNOTATION_CONFIG.to_string(), a.to_string())])),
                ..Default::default()
            },
            spec: Some(ServiceSpec {
                type_: Some("ExternalName".to_string()),
                external_name: Some("db.example.net".to_string()),
                ports: Some(vec![ServicePort {
                    port: 5432,
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    // ── serve config tests ────────────────────────────────────────────────────

    #[test]
    fn tcp_serve_json_forwards_each_port() {
        let json = build_tcp_serve_json("db.example.net", &[(5432, 5432), (6432, 16432)]);
        assert_eq!(json["TCP"]["5432"]["TCPForward"], "db.example.net:5432");
        assert_eq!(json["TCP"]["6432"]["TCPForward"], "db.example.net:16432");
        assert!(
            json.get("Web").is_none(),
            "raw TCP forwards must not carry a Web section"
        );
    }

    #[test]
    fn collect_forwards_defaults_backend_to_port() {
        let svc = external_name_service(None);
        assert_eq!(collect_tcp_forwards(&svc), vec![(5432, 5432)]);
    }

    #[test]
    fn collect_forwards_honors_integer_target_port() {
        let mut svc = external_name_service(None);
        svc.spec.as_mut().unwrap().ports = Some(vec![ServicePort {
            port: 443,
            target_port: Some(IntOrString::Int(8443)),
            ..Default::default()
        }]);
        assert_eq!(collect_tcp_forwards(&svc), vec![(443, 8443)]);
    }

    #[test]
    fn collect_forwards_ignores_named_target_port() {
        let mut svc = external_name_service(None);
        svc.spec.as_mut().unwrap().ports = Some(vec![ServicePort {
            port: 443,
            target_port: Some(IntOrString::String("https".to_string())),
            ..Default::default()
        }]);
        assert_eq!(
            collect_tcp_forwards(&svc),
            vec![(443, 443)],
            "named targetPort is meaningless for an external host; use port"
        );
    }

    #[test]
    fn collect_forwards_skips_udp_ports() {
        let mut svc = external_name_service(None);
        svc.spec.as_mut().unwrap().ports = Some(vec![
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
        assert_eq!(collect_tcp_forwards(&svc), vec![(853, 853)]);
    }

    // ── adoption gate tests ───────────────────────────────────────────────────

    #[tokio::test]
    async fn reconcile_skips_service_without_annotation() {
        // ExternalName Service, no annotation, no finalizer → silently skipped
        // (all_500 client proves no K8s call is made).
        let ctx = Arc::new(test_ctx(FaultService::client(all_500)));
        let svc = Arc::new(external_name_service(None));
        let result = reconcile(svc, ctx).await;
        assert!(
            result.is_ok(),
            "Service without our annotation must be silently skipped"
        );
    }

    #[tokio::test]
    async fn reconcile_skips_non_external_name_service() {
        let ctx = Arc::new(test_ctx(FaultService::client(all_500)));
        let mut svc = external_name_service(Some(r#"{"headscale-ref":"main","user":"alice"}"#));
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
        let svc = Arc::new(external_name_service(Some(
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
        // Valid annotation + claim_default → Layer 2 proceeds to the
        // HeadscaleInstance lookup, which the all_500 mock fails — proving
        // adoption was attempted.
        let ctx = Arc::new(test_ctx(FaultService::client(all_500)));
        let svc = Arc::new(external_name_service(Some(
            r#"{"headscale-ref":"main","user":"alice"}"#,
        )));
        let result = reconcile(svc, ctx).await;
        assert!(
            result.is_err(),
            "default deployment must process annotated ExternalName Services (K8s call expected)"
        );
    }
}
