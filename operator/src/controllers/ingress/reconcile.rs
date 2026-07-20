//! Main reconcile loop for `Ingress`. Provisions a Tailscale proxy for every
//! `Ingress` annotated `ingressClassName: headmaster`, and cleans up all proxy
//! resources (StatefulSet, Service, RBAC, Secrets, ConfigMap) on deletion.

use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use headscale_client::headscale::v1::{DeleteNodeRequest, SetTagsRequest};
use headscale_client::{AuthenticatedClient, Code};
use k8s_ext::SecretGetExt;
use k8s_openapi::api::apps::v1::StatefulSet;
use k8s_openapi::api::core::v1::{ConfigMap, Namespace, Secret, Service, ServiceAccount};
use k8s_openapi::api::networking::v1::{Ingress, IngressClass, IngressClassSpec};
use k8s_openapi::api::rbac::v1::{Role, RoleBinding};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::{Api, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::runtime::finalizer::{Event as Finalizer, finalizer};
use kube::runtime::reflector::ObjectRef;
use kube::runtime::watcher;
use kube::{Client, Resource, ResourceExt};

use super::auth_key::{AuthKeyStatus, ensure_auth_key};
use super::error::Error;
use super::names::{ProxyNames, ingress_auto_tag};
use super::proxy::{
    apply_proxy_rbac, apply_proxy_statefulset, apply_serve_configmap, apply_wireguard_service,
    collect_ingress_routes, ensure_state_secret, patch_ingress_status,
};
use super::{CONTROLLER_NAME, INGRESS_CLASS_NAME};
use crate::context::Context;
use crate::controllers::applier::{ChildApplier, delete_ignoring_404};
use crate::controllers::recorder::RecorderExt;
use crate::labels;
use crate::types::{HeadscaleInstance, IngressAnnotations, ResourceStatus};

// ── public entrypoints ────────────────────────────────────────────────────────

/// Ensures the `headmaster` IngressClass exists and optionally claims it as the
/// default handler for un-annotated Ingresses. Called once on startup.
///
/// `claim` controls ownership of the `default-namespace` annotation:
/// - `None` — try to claim without force; a 409 (someone else already holds it)
///   is treated as graceful fallback: we do not adopt un-annotated Ingresses.
/// - `Some(true)` — claim with `.force()`, overwriting any stale owner. Use
///   when intentionally migrating the default handler.
/// - `Some(false)` — do not touch the annotation; never adopt un-annotated
///   Ingresses.
///
/// Returns `true` if we actively hold the default-handler claim after the call.
pub async fn ensure_ingress_class(
    client: &Client,
    operator_namespace: &str,
    claim: Option<bool>,
) -> Result<bool, kube::Error> {
    let ssa = PatchParams::apply(&crate::field_manager(operator_namespace)).force();
    let desired = IngressClass {
        metadata: ObjectMeta {
            name: Some(INGRESS_CLASS_NAME.to_string()),
            ..Default::default()
        },
        spec: Some(IngressClassSpec {
            controller: Some(CONTROLLER_NAME.to_string()),
            ..Default::default()
        }),
    };
    Api::<IngressClass>::all(client.clone())
        .patch(INGRESS_CLASS_NAME, &ssa, &Patch::Apply(&desired))
        .await?;

    let Some(force) = claim else {
        // None: try to claim; accept 409 as "someone else holds it" rather than failing.
        let claim_manager = format!("{}-claim-default", crate::field_manager(operator_namespace));
        return match Api::<IngressClass>::all(client.clone())
            .patch(
                INGRESS_CLASS_NAME,
                &PatchParams::apply(&claim_manager),
                &Patch::Apply(claim_annotation_manifest(operator_namespace)),
            )
            .await
        {
            Ok(_) => Ok(true),
            Err(kube::Error::Api(ref status)) if status.code == 409 => Ok(false),
            Err(e) => Err(e),
        };
    };

    if !force {
        return Ok(false);
    }

    // Some(true): forcibly take ownership, overwriting any stale claim.
    let claim_manager = format!("{}-claim-default", crate::field_manager(operator_namespace));
    Api::<IngressClass>::all(client.clone())
        .patch(
            INGRESS_CLASS_NAME,
            &PatchParams::apply(&claim_manager).force(),
            &Patch::Apply(claim_annotation_manifest(operator_namespace)),
        )
        .await?;
    Ok(true)
}

fn claim_annotation_manifest(operator_namespace: &str) -> serde_json::Value {
    serde_json::json!({
        "apiVersion": "networking.k8s.io/v1",
        "kind": "IngressClass",
        "metadata": {
            "name": INGRESS_CLASS_NAME,
            "annotations": {
                crate::ANNOTATION_DEFAULT_NAMESPACE: operator_namespace,
            }
        }
    })
}

pub fn stream(
    ingress_api: Api<Ingress>,
    ctx: Arc<Context>,
    shutdown: impl std::future::Future<Output = ()> + Send + Sync + 'static,
) -> impl std::future::Future<Output = ()> {
    let controller = kube::runtime::Controller::new(ingress_api, watcher::Config::default());
    let ingress_store = controller.store();
    controller
        .watches(
            Api::<Secret>::namespaced(ctx.client.clone(), &ctx.operator_namespace),
            watcher::Config::default().labels(&format!(
                "{}={}",
                labels::APP_MANAGED_BY,
                labels::MANAGED_BY_VALUE
            )),
            |secret| {
                let ingress_name = secret.labels().get(labels::INGRESS_NAME)?.clone();
                let ingress_ns = secret.labels().get(labels::INGRESS_NAMESPACE)?.clone();
                Some(ObjectRef::<Ingress>::new(&ingress_name).within(&ingress_ns))
            },
        )
        .watches(
            Api::<HeadscaleInstance>::namespaced(ctx.client.clone(), &ctx.operator_namespace),
            watcher::Config::default(),
            move |instance| {
                // ingress_store.state() may be empty during the initial list/watch cycle
                // (before InitDone). In that case this closure returns no ObjectRefs, but
                // kube-runtime's trigger_self mechanism queues every Ingress for an initial
                // reconcile once the store is ready, so no Ingress is permanently missed.
                // In steady state the store is always populated and this works correctly.
                let instance_name = instance.name_any();
                ingress_store
                    .state()
                    .into_iter()
                    .filter(move |ing| {
                        IngressAnnotations::headscale_ref(ing).as_deref() == Some(&instance_name)
                    })
                    .map(|ing| ObjectRef::from_obj(&*ing))
            },
        )
        .graceful_shutdown_on(shutdown)
        .run(reconcile, error_policy, ctx)
        .for_each(|res| async move {
            if let Err(e) = res {
                tracing::warn!("Ingress reconcile error: {e:?}");
            }
        })
}

// ── reconcile ─────────────────────────────────────────────────────────────────

fn error_policy(obj: Arc<Ingress>, e: &Error, _ctx: Arc<Context>) -> Action {
    tracing::warn!(name = obj.name_any(), "Ingress reconcile failed: {e:?}");
    Action::requeue(Duration::from_secs(30))
}

async fn reconcile(ingress: Arc<Ingress>, ctx: Arc<Context>) -> Result<Action, Error> {
    let class = ingress
        .spec
        .as_ref()
        .and_then(|s| s.ingress_class_name.as_deref())
        .or_else(|| {
            ingress
                .annotations()
                .get("kubernetes.io/ingress.class")
                .map(String::as_str)
        });
    let our_finalizer = crate::finalizer(&ctx.operator_namespace);
    let has_our_finalizer = ingress.finalizers().iter().any(|f| f == &our_finalizer);

    if class != Some(INGRESS_CLASS_NAME) && !has_our_finalizer {
        return Ok(Action::await_change());
    }

    let ns = ingress.namespace().ok_or(Error::MissingNamespace)?;

    // Layer 1: sharding gate — only adopt Ingresses targeted at this deployment.
    let target_namespace = IngressAnnotations::headscale_namespace(&ingress);
    let is_ours = match &target_namespace {
        Some(n) => n == &ctx.operator_namespace,
        None => ctx.claim_default,
    };
    if !is_ours && !has_our_finalizer {
        return Ok(Action::await_change());
    }

    // Layer 2: authorization gate — only runs pre-adoption. An Ingress without a
    // valid config annotation is not ours to manage; skip it rather than adopting
    // it and then failing forever in apply(). An excluded namespace must never
    // acquire our finalizer: we have nothing to clean up, and stamping a finalizer
    // we immediately remove would block re-adoption when watchedNamespaces is later
    // updated to include this namespace.
    if !has_our_finalizer {
        match IngressAnnotations::parse(&ingress) {
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

    let api: Api<Ingress> = Api::namespaced(ctx.client.clone(), &ns);

    finalizer(&api, &our_finalizer, ingress, |event| async {
        match event {
            Finalizer::Apply(ing) => apply(ing, &ctx).await,
            Finalizer::Cleanup(ing) => cleanup(ing, &ctx).await,
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

async fn apply(ingress: Arc<Ingress>, ctx: &Context) -> Result<Action, Error> {
    let ingress_ns = ingress.namespace().unwrap_or_default();
    let ingress_name = ingress.name_any();
    let op_ns = &ctx.operator_namespace;

    // Class release: if the ingressClassName no longer points at us (e.g. the
    // user changed it from "headmaster" to "nginx"), deregister resources and
    // relinquish ownership so the proxy doesn't outlive its controller.
    let class = ingress
        .spec
        .as_ref()
        .and_then(|s| s.ingress_class_name.as_deref())
        .or_else(|| {
            ingress
                .annotations()
                .get("kubernetes.io/ingress.class")
                .map(String::as_str)
        });
    if class != Some(INGRESS_CLASS_NAME) {
        let names = ProxyNames::new(&ingress_ns, &ingress_name);
        if let Some(headscale_ref) = IngressAnnotations::headscale_ref(&ingress) {
            deregister_and_cleanup(ctx, op_ns, &names, &ingress, &headscale_ref).await?;
        } else {
            cleanup_proxy_resources(ctx, op_ns, &names).await;
        }
        release_ingress(ctx, &ingress_ns, &ingress_name).await?;
        return Ok(Action::await_change());
    }

    // Sharding release: if the headscale-namespace annotation now points
    // elsewhere, deregister resources and relinquish ownership.
    let target_namespace = IngressAnnotations::headscale_namespace(&ingress);
    let is_ours = match &target_namespace {
        Some(n) => n == op_ns,
        None => ctx.claim_default,
    };
    if !is_ours {
        let names = ProxyNames::new(&ingress_ns, &ingress_name);
        if let Some(headscale_ref) = IngressAnnotations::headscale_ref(&ingress) {
            deregister_and_cleanup(ctx, op_ns, &names, &ingress, &headscale_ref).await?;
        } else {
            cleanup_proxy_resources(ctx, op_ns, &names).await;
        }
        release_ingress(ctx, &ingress_ns, &ingress_name).await?;
        return Ok(Action::await_change());
    }

    let annotations = IngressAnnotations::parse(&ingress)?;

    if namespace_is_deleting(&ctx.client, &ingress_ns).await? {
        tracing::info!(
            name = ingress_name,
            namespace = ingress_ns,
            "Ingress: namespace is deleting; skipping"
        );
        return Ok(Action::await_change());
    }

    // HeadscaleInstance lives in the operator namespace.
    let instance_api: Api<HeadscaleInstance> = Api::namespaced(ctx.client.clone(), op_ns);
    let instance = match instance_api.get(&annotations.headscale_ref).await {
        Ok(inst) => inst,
        Err(kube::Error::Api(ref e)) if e.code == 404 => {
            let recorder = ctx.recorder();
            let _ = recorder
                .publish_warning(
                    &ingress.object_ref(&()),
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
    // Proxy resource names are scoped to operator namespace using
    // {ingress_ns}-{ingress_name} as the base to avoid cross-namespace collisions.
    let names = ProxyNames::new(&ingress_ns, &ingress_name);

    // Authorization release: if watchedNamespaces no longer covers this
    // Ingress's namespace, deregister and relinquish ownership.
    if !instance.spec.namespace_allowed(&ingress_ns) {
        let _ = ctx
            .recorder()
            .publish_warning(
                &ingress.object_ref(&()),
                "NamespaceExcluded",
                &format!(
                    "namespace '{}' is not in HeadscaleInstance \
                     '{}' watchedNamespaces; this Ingress is now orphaned",
                    ingress_ns, annotations.headscale_ref,
                ),
            )
            .await;
        deregister_and_cleanup(ctx, op_ns, &names, &ingress, &annotations.headscale_ref).await?;
        release_ingress(ctx, &ingress_ns, &ingress_name).await?;
        return Ok(Action::await_change());
    }

    if !instance.status.as_ref().is_some_and(|s| s.is_ready()) {
        let recorder = ctx.recorder();
        let _ = recorder
            .publish_warning(
                &ingress.object_ref(&()),
                "Pending",
                &format!(
                    "HeadscaleInstance '{}' is not yet ready",
                    annotations.headscale_ref
                ),
            )
            .await;
        return Ok(Action::requeue(Duration::from_secs(5)));
    }

    let dns_base_domain = instance.spec.dns_base_domain.clone();
    // The login/control URL the proxy's tailscaled dials: the in-cluster
    // service for managed instances, the public server URL for external ones.
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
        &ingress_name,
        &ingress_ns,
    );

    for grant in &annotations.access {
        if grant.from.is_empty() {
            let recorder = ctx.recorder();
            let _ = recorder
                .publish_warning(
                    &ingress.object_ref(&()),
                    "InvalidConfig",
                    "access grant 'from' must not be empty",
                )
                .await;
            return Ok(Action::await_change());
        }
    }

    let auto_tag = if !annotations.access.is_empty() {
        Some(ingress_auto_tag(&ingress_ns, &ingress_name))
    } else {
        None
    };

    let cap_names: Vec<String> = {
        let mut unique_caps: std::collections::BTreeSet<String> = Default::default();
        for grant in &annotations.access {
            if let Some(caps) = &grant.capabilities {
                unique_caps.extend(caps.keys().cloned());
            }
        }
        unique_caps.into_iter().collect()
    };

    let routes = match collect_ingress_routes(&ctx.client, &ingress, &ingress_ns).await {
        Err(_) => {
            let _ = ctx
                .recorder()
                .publish_warning(
                    &ingress.object_ref(&()),
                    "NoPathRules",
                    "Ingress has no HTTP path rules; add spec.rules with at least one backend",
                )
                .await;
            deregister_and_cleanup(ctx, op_ns, &names, &ingress, &annotations.headscale_ref)
                .await?;
            return Ok(Action::await_change());
        }
        Ok(routes) if routes.is_empty() => {
            let _ = ctx
                .recorder()
                .publish_warning(
                    &ingress.object_ref(&()),
                    "Pending",
                    "backend Service not yet available; waiting for named port to resolve",
                )
                .await;
            return Ok(Action::requeue(Duration::from_secs(30)));
        }
        Ok(routes) => routes,
    };

    let mut headscale = headscale_connect(ctx, op_ns, &annotations.headscale_ref).await?;

    let wg_node_port = apply_wireguard_service(&child, &names).await?;

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
        &ingress,
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

    apply_serve_configmap(&child, &names, &tailnet_fqdn, &routes, &cap_names).await?;

    apply_proxy_rbac(&child, &names).await?;

    apply_proxy_statefulset(
        &child,
        &names,
        &ctx.proxy_image,
        &login_url,
        &annotations.hostname,
        wg_node_port,
    )
    .await?;

    let device_id = read_secret_string(&state_secret, "device_id");
    let device_ips =
        read_secret_json::<Vec<String>>(&state_secret, "device_ips").unwrap_or_default();

    // Keep the registered node's ACL tags in sync with the desired state on
    // every reconcile. ensure_auth_key returns early when the config secret
    // already exists, so without this call adding or removing access grants
    // after the proxy is registered would never update the node's tags.
    let mut set_tags_failed = false;
    if let Some(node_id) = device_id.as_ref().and_then(|s| s.parse::<u64>().ok()) {
        let desired_tags: Vec<String> = annotations
            .managed_key_tags
            .iter()
            .cloned()
            .chain(auto_tag.iter().cloned())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        if let Err(e) = headscale
            .set_tags(SetTagsRequest {
                node_id,
                tags: desired_tags,
            })
            .await
        {
            tracing::warn!(
                name = ingress_name,
                node_id,
                error = %e,
                "failed to set ACL tags on headscale node; will retry on next reconcile"
            );
            set_tags_failed = true;
        }
    }

    if device_id.is_some() {
        let tailnet_ip = device_ips.into_iter().next();
        if let Some(ref ip) = tailnet_ip {
            patch_ingress_status(ctx, &ingress, ip).await?;
            let recorder = ctx.recorder();
            let _ = recorder.publish_ready(&ingress.object_ref(&())).await;
        } else {
            tracing::info!(
                name = ingress_name,
                hostname = annotations.hostname,
                "Ingress: proxy registered but waiting for IP assignment"
            );
        }
    } else {
        tracing::info!(
            name = ingress_name,
            hostname = annotations.hostname,
            "Ingress: waiting for proxy to register"
        );
        let recorder = ctx.recorder();
        let _ = recorder
            .publish_warning(
                &ingress.object_ref(&()),
                "ProxyNotRegistered",
                &format!(
                    "proxy for Ingress '{ingress_name}' has not registered with headscale; \
                     if this persists beyond the auth-key expiry window, delete the \
                     Secret '{}' to force key rotation",
                    names.config_secret_name
                ),
            )
            .await;
    }

    // Record ownership so observers can discover which operator deployment
    // manages this Ingress without inspecting finalizers.
    Api::<Ingress>::namespaced(ctx.client.clone(), &ingress_ns)
        .patch(
            &ingress_name,
            &PatchParams::apply(&crate::field_manager(op_ns)).force(),
            &Patch::Apply(serde_json::json!({
                "apiVersion": "networking.k8s.io/v1",
                "kind": "Ingress",
                "metadata": {
                    "name": ingress_name,
                    "namespace": ingress_ns,
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

// ── cleanup ───────────────────────────────────────────────────────────────────

async fn cleanup(ingress: Arc<Ingress>, ctx: &Context) -> Result<Action, Error> {
    let ingress_ns = ingress.namespace().unwrap_or_default();
    let ingress_name = ingress.name_any();
    let op_ns = &ctx.operator_namespace;
    let names = ProxyNames::new(&ingress_ns, &ingress_name);
    let headscale_ref_fallback = IngressAnnotations::headscale_ref(&ingress);
    deregister_and_cleanup(
        ctx,
        op_ns,
        &names,
        &ingress,
        headscale_ref_fallback.as_deref().unwrap_or(""),
    )
    .await?;
    Ok(Action::await_change())
}

/// Deregisters the proxy's headscale node (if registered) and deletes all proxy
/// k8s resources. Called on both Ingress deletion and namespace exclusion.
///
/// State secret read errors are propagated so the caller requeues and retries,
/// ensuring the node is removed before k8s resources are cleaned up. All other
/// errors (headscale connection, node deletion, k8s resource deletion) are
/// best-effort: logged or published as events, then cleanup continues.
async fn deregister_and_cleanup(
    ctx: &Context,
    op_ns: &str,
    names: &ProxyNames,
    ingress: &Ingress,
    headscale_ref_fallback: &str,
) -> Result<(), Error> {
    let ingress_name = ingress.name_any();

    // Read node_id and headscale_ref from the state Secret. On non-404 errors
    // we propagate and requeue — this retries until the API recovers, ensuring
    // the headscale node is deleted before k8s resources are cleaned up.
    let state_secret = match Api::<Secret>::namespaced(ctx.client.clone(), op_ns)
        .get(&names.state_secret_name)
        .await
    {
        Ok(secret) => Some(secret),
        Err(kube::Error::Api(ref e)) if e.code == 404 => None,
        Err(e) => return Err(Error::Kube(e)),
    };

    let node_id = state_secret
        .as_ref()
        .and_then(|s| read_secret_string(s, "device_id"))
        .and_then(|s| s.parse::<u64>().ok());

    if let Some(id) = node_id {
        let headscale_ref = state_secret
            .as_ref()
            .and_then(|s| read_secret_string(s, "headscale_ref"))
            .unwrap_or_else(|| headscale_ref_fallback.to_string());
        match headscale_connect(ctx, op_ns, &headscale_ref).await {
            Err(e) => {
                let recorder = ctx.recorder();
                let _ = recorder
                    .publish_warning(
                        &ingress.object_ref(&()),
                        "NodeOrphaned",
                        &format!(
                            "could not connect to headscale to delete node {id}: {e}; \
                             the node may remain registered in headscale"
                        ),
                    )
                    .await;
            }
            Ok(mut headscale) => {
                match headscale
                    .delete_node(DeleteNodeRequest { node_id: id })
                    .await
                {
                    Ok(_) => tracing::debug!(
                        name = ingress_name,
                        node_id = id,
                        "deleted node from headscale"
                    ),
                    Err(e) if e.code() == Code::NotFound => tracing::debug!(
                        name = ingress_name,
                        "cleanup: node already gone from headscale"
                    ),
                    Err(e) => {
                        // Return an error so the finalizer stays in place and
                        // the reconciler retries. The state Secret must not be
                        // deleted until we have confirmed headscale no longer
                        // tracks the node — it holds the node_id we need to
                        // retry the deletion.
                        tracing::warn!(
                            name = ingress_name,
                            node_id = id,
                            error = %e,
                            "cleanup: failed to delete node from headscale; will retry"
                        );
                        return Err(Error::HeadscaleApi(e));
                    }
                }
                let recorder = ctx.recorder();
                let _ = recorder.publish_deleted(&ingress.object_ref(&())).await;
            }
        }
    }

    cleanup_proxy_resources(ctx, op_ns, names).await;
    Ok(())
}

/// Explicitly deletes all proxy resources created in the operator namespace.
///
/// Proxy resources are owned by their HeadscaleInstance (same namespace), so GC
/// handles cleanup on HeadscaleInstance deletion. For Ingress deletion the owner
/// is still alive, so this explicit cleanup is still required.
/// All deletes are best-effort: 404s are silently ignored; unexpected errors are
/// logged so leaked resources are discoverable, but cleanup continues regardless.
async fn cleanup_proxy_resources(ctx: &Context, op_ns: &str, names: &ProxyNames) {
    let c = ctx.client.clone();
    tokio::join!(
        del_warn(
            Api::<StatefulSet>::namespaced(c.clone(), op_ns),
            &names.proxy_name
        ),
        del_warn(
            Api::<Service>::namespaced(c.clone(), op_ns),
            &names.wg_service_name
        ),
        del_warn(
            Api::<Secret>::namespaced(c.clone(), op_ns),
            &names.config_secret_name
        ),
        del_warn(
            Api::<Secret>::namespaced(c.clone(), op_ns),
            &names.state_secret_name
        ),
        del_warn(
            Api::<ConfigMap>::namespaced(c.clone(), op_ns),
            &names.serve_configmap_name
        ),
        del_warn(
            Api::<RoleBinding>::namespaced(c.clone(), op_ns),
            &names.proxy_name
        ),
        del_warn(Api::<Role>::namespaced(c.clone(), op_ns), &names.proxy_name),
        del_warn(
            Api::<ServiceAccount>::namespaced(c, op_ns),
            &names.proxy_name
        ),
    );
}

/// Best-effort delete used by `cleanup_proxy_resources`: 404 is success,
/// any other error is logged and swallowed so the parallel cleanup of the
/// remaining resources continues.
async fn del_warn<K>(api: Api<K>, name: &str)
where
    K: Resource + serde::de::DeserializeOwned + Clone + std::fmt::Debug,
{
    if let Err(e) = delete_ignoring_404(api, name).await {
        tracing::warn!(resource = name, error = %e, "cleanup: failed to delete proxy resource");
    }
}

/// Removes our finalizer from the Ingress and clears the `claimed-by` annotation
/// and `status.loadBalancer`.
///
/// Used when this deployment relinquishes ownership due to a sharding change
/// or a `watchedNamespaces` revocation.
///
/// NOTE: kube::runtime::finalizer only removes finalizers during Cleanup (i.e.
/// when deletionTimestamp is set). Ownership release on a live object has no
/// framework support, so this function patches the finalizer array directly.
/// To avoid silently dropping concurrent finalizer additions, it re-fetches the
/// live object and includes its resourceVersion as an optimistic-lock precondition;
/// a 409 conflict causes the reconcile to requeue and retry.
async fn release_ingress(ctx: &Context, ingress_ns: &str, ingress_name: &str) -> Result<(), Error> {
    let api = Api::<Ingress>::namespaced(ctx.client.clone(), ingress_ns);

    // Clear status first so the tailnet IP does not outlive the proxy.
    api.patch_status(
        ingress_name,
        &PatchParams::apply(&crate::field_manager(&ctx.operator_namespace)).force(),
        &Patch::Apply(serde_json::json!({
            "apiVersion": "networking.k8s.io/v1",
            "kind": "Ingress",
            "metadata": { "name": ingress_name, "namespace": ingress_ns },
            "status": {}
        })),
    )
    .await
    .map_err(Error::Kube)?;

    // Re-fetch to get the live finalizer list and current resourceVersion.
    let live = api.get(ingress_name).await.map_err(Error::Kube)?;
    let our_finalizer = crate::finalizer(&ctx.operator_namespace);
    let remaining: Vec<String> = live
        .finalizers()
        .iter()
        .filter(|f| f.as_str() != our_finalizer)
        .cloned()
        .collect();
    let resource_version = live.resource_version().unwrap_or_default();
    api.patch(
        ingress_name,
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

// ── headscale connection ──────────────────────────────────────────────────────

pub(crate) async fn headscale_connect(
    ctx: &Context,
    namespace: &str,
    name: &str,
) -> Result<AuthenticatedClient, kube::Error> {
    // External instances carry their own gRPC endpoint and API-key Secret;
    // managed instances use the in-cluster service and the bootstrap-created
    // Secret. A 404 on the instance GET propagates exactly like the managed
    // path's missing-secret 404, which callers already treat as "instance
    // gone" during cleanup.
    let instance = Api::<HeadscaleInstance>::namespaced(ctx.client.clone(), namespace)
        .get(name)
        .await?;
    let (endpoint, secret_name) = match &instance.spec.external {
        Some(ext) => (ext.grpc_endpoint.clone(), ext.api_key_secret_ref.clone()),
        None => (
            format!("http://headscale-server-{name}.{namespace}.svc:50443"),
            format!("headscale-api-key-{name}"),
        ),
    };
    let api_key = Api::<Secret>::namespaced(ctx.client.clone(), namespace)
        .get(&secret_name)
        .await
        .map_err(|e| match e {
            kube::Error::Api(ref ae) if ae.code == 404 => kube::Error::Api(Box::new(
                kube::error::Status::failure(
                    &format!("Secret {secret_name} not found; is HeadscaleInstance ready?"),
                    "NotFound",
                )
                .with_code(404),
            )),
            other => other,
        })?
        .data
        .as_ref()
        .and_then(|d| d.get("HEADSCALE_API_KEY"))
        .map(|b| String::from_utf8_lossy(&b.0).into_owned())
        .ok_or_else(|| {
            kube::Error::Api(Box::new(
                kube::error::Status::failure(
                    "api-key secret has no 'HEADSCALE_API_KEY' field",
                    "InvalidSecret",
                )
                .with_code(500),
            ))
        })?;
    ctx.headscale
        .connect(&endpoint, &api_key)
        .await
        .map_err(|e| kube::Error::Service(Box::new(e)))
}

// ── namespace helper ──────────────────────────────────────────────────────────

async fn namespace_is_deleting(client: &Client, ns: &str) -> Result<bool, Error> {
    match Api::<Namespace>::all(client.clone()).get(ns).await {
        Ok(ns_obj) => Ok(ns_obj.metadata.deletion_timestamp.is_some()),
        Err(kube::Error::Api(ref e)) if e.code == 404 => Ok(true),
        Err(e) => Err(Error::Kube(e)),
    }
}

// ── secret helpers ────────────────────────────────────────────────────────────

fn read_secret_string(secret: &Secret, key: &str) -> Option<String> {
    String::from_utf8(secret.item(key)?.0.clone()).ok()
}

fn read_secret_json<T: serde::de::DeserializeOwned>(secret: &Secret, key: &str) -> Option<T> {
    serde_json::from_slice(&secret.item(key)?.0).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controllers::ingress::test_support::{headmaster_ingress, test_ctx, test_ingress};
    use crate::test_support::{FaultService, all_404, all_500};

    // ── ensure_ingress_class tests ────────────────────────────────────────────

    fn ingressclass_ok(_: &http::Method, _: &str) -> (u16, Vec<u8>) {
        (
            200,
            serde_json::json!({
                "apiVersion": "networking.k8s.io/v1",
                "kind": "IngressClass",
                "metadata": {"name": INGRESS_CLASS_NAME, "resourceVersion": "1"}
            })
            .to_string()
            .into_bytes(),
        )
    }

    fn ingressclass_claim_409(m: &http::Method, path: &str) -> (u16, Vec<u8>) {
        // The claim-default annotation patch uses a field manager name containing
        // "claim-default". Simulate a conflict on that call only.
        if *m == http::Method::PATCH && path.contains("claim-default") {
            (409, br#"{"code":409,"reason":"Conflict"}"#.to_vec())
        } else {
            ingressclass_ok(m, path)
        }
    }

    #[tokio::test]
    async fn ensure_ingress_class_none_claims_when_unclaimed() {
        let client = FaultService::client(ingressclass_ok);
        let result = ensure_ingress_class(&client, "default", None).await;
        assert!(
            result.unwrap(),
            "None must return true when the claim patch succeeds"
        );
    }

    #[tokio::test]
    async fn ensure_ingress_class_none_backs_off_when_contested() {
        let client = FaultService::client(ingressclass_claim_409);
        let result = ensure_ingress_class(&client, "default", None).await;
        assert!(
            !result.unwrap(),
            "None must return false (not Err) when the claim patch returns 409"
        );
    }

    #[tokio::test]
    async fn ensure_ingress_class_force_overwrites_existing_claim() {
        // force=true uses .force() on the claim patch; ingressclass_ok returns 200
        // for every PATCH so we verify it returns true.
        let (client, calls) = FaultService::tracked(ingressclass_ok);
        let result = ensure_ingress_class(&client, "default", Some(true)).await;
        assert!(result.unwrap(), "Some(true) must return true");
        let recorded = calls.lock().unwrap();
        let patch_count = recorded.iter().filter(|(m, _)| m == "PATCH").count();
        assert_eq!(
            patch_count, 2,
            "two PATCHes must be issued: spec then claim"
        );
    }

    #[tokio::test]
    async fn ensure_ingress_class_off_does_not_claim() {
        let (client, calls) = FaultService::tracked(ingressclass_ok);
        let result = ensure_ingress_class(&client, "default", Some(false)).await;
        assert!(!result.unwrap(), "Some(false) must return false");
        let recorded = calls.lock().unwrap();
        let patch_count = recorded.iter().filter(|(m, _)| m == "PATCH").count();
        assert_eq!(
            patch_count, 1,
            "only the spec PATCH must be issued; claim must not be touched"
        );
    }

    // ── namespace_is_deleting tests ───────────────────────────────────────────

    #[tokio::test]
    async fn namespace_is_deleting_returns_true_on_404() {
        let client = FaultService::client(all_404);
        let result = namespace_is_deleting(&client, "gone-ns").await.unwrap();
        assert!(
            result,
            "404 on namespace GET must be treated as namespace gone (deleting)"
        );
    }

    #[tokio::test]
    async fn namespace_is_deleting_propagates_non_404_error() {
        let client = FaultService::client(all_500);
        let result = namespace_is_deleting(&client, "any-ns").await;
        assert!(result.is_err(), "non-404 GET error must propagate");
    }

    // ── deregister_and_cleanup tests ──────────────────────────────────────────

    #[tokio::test]
    async fn deregister_and_cleanup_propagates_state_secret_error() {
        let (k8s, calls) = FaultService::tracked(all_500);
        let ctx = test_ctx(k8s);
        let names = ProxyNames::new("default", "test-ingress");

        let result = deregister_and_cleanup(&ctx, "default", &names, &test_ingress(), "main").await;

        assert!(result.is_err(), "state-secret GET error must propagate");
        let recorded = calls.lock().unwrap();
        assert!(
            recorded.iter().all(|(m, _)| m == "GET"),
            "no DELETE calls must be issued when state-secret read fails: {recorded:?}"
        );
    }

    #[tokio::test]
    async fn deregister_and_cleanup_continues_when_state_secret_absent() {
        // all_404: state-secret GET → 404 (None), proxy resource DELETEs → 404 (silently ignored).
        let ctx = test_ctx(FaultService::client(all_404));
        let names = ProxyNames::new("default", "test-ingress");

        let result = deregister_and_cleanup(&ctx, "default", &names, &test_ingress(), "main").await;

        assert!(
            result.is_ok(),
            "missing state secret must not abort cleanup"
        );
    }

    // ── sharding gate tests ───────────────────────────────────────────────────

    #[tokio::test]
    async fn reconcile_skips_ingress_targeted_at_other_deployment() {
        use crate::controllers::ingress::ANNOTATION_CONFIG;
        use k8s_openapi::api::networking::v1::IngressSpec;
        use std::collections::BTreeMap;

        // Ingress has headscale-namespace pointing to "other-ns", ctx is "default".
        // No finalizer from us → sharding gate fires → await_change (no K8s calls needed).
        let ingress = Arc::new(Ingress {
            metadata: ObjectMeta {
                name: Some("test-ingress".to_string()),
                namespace: Some("app-ns".to_string()),
                uid: Some("uid-1".to_string()),
                annotations: Some(BTreeMap::from([
                    (
                        "kubernetes.io/ingress.class".to_string(),
                        "headmaster".to_string(),
                    ),
                    (
                        ANNOTATION_CONFIG.to_string(),
                        r#"{"headscale-ref":"main","user":"alice","headscale-namespace":"other-ns"}"#
                            .to_string(),
                    ),
                ])),
                ..Default::default()
            },
            spec: Some(IngressSpec {
                ingress_class_name: Some(INGRESS_CLASS_NAME.to_string()),
                ..Default::default()
            }),
            ..Default::default()
        });

        let ctx = Arc::new(test_ctx(FaultService::client(all_500)));
        let result = super::reconcile(ingress, ctx).await;
        assert!(
            result.is_ok(),
            "Ingress targeting another deployment must be silently skipped"
        );
    }

    #[tokio::test]
    async fn reconcile_skips_when_claim_default_false_and_no_explicit_target() {
        // ctx has claim_default=false and the Ingress has no headscale-namespace annotation.
        // No finalizer → sharding gate fires → await_change.
        let ctx = Arc::new(Context {
            claim_default: false,
            ..test_ctx(FaultService::client(all_500))
        });
        let result = super::reconcile(Arc::new(headmaster_ingress("any-namespace")), ctx).await;
        assert!(
            result.is_ok(),
            "non-default deployment must skip Ingresses with no explicit target"
        );
    }

    #[tokio::test]
    async fn reconcile_processes_ingress_when_claim_default_true() {
        use crate::controllers::ingress::ANNOTATION_CONFIG;
        use std::collections::BTreeMap;

        // ctx has claim_default=true (test_ctx default). The Ingress has a valid config
        // annotation so Layer 2 proceeds to a K8s call (HeadscaleInstance lookup), which
        // the all_500 mock causes to fail with Err — proving adoption was attempted.
        let ingress = Arc::new(Ingress {
            metadata: ObjectMeta {
                name: Some("test-ingress".to_string()),
                namespace: Some("any-namespace".to_string()),
                uid: Some("uid-1".to_string()),
                annotations: Some(BTreeMap::from([(
                    ANNOTATION_CONFIG.to_string(),
                    r#"{"headscale-ref":"main","user":"alice"}"#.to_string(),
                )])),
                ..Default::default()
            },
            spec: Some(k8s_openapi::api::networking::v1::IngressSpec {
                ingress_class_name: Some(INGRESS_CLASS_NAME.to_string()),
                ..Default::default()
            }),
            ..Default::default()
        });

        let ctx = Arc::new(test_ctx(FaultService::client(all_500)));
        let result = super::reconcile(ingress, ctx).await;
        assert!(
            result.is_err(),
            "default deployment must process Ingresses with a valid config annotation (K8s call expected)"
        );
    }

    #[tokio::test]
    async fn reconcile_skips_ingress_with_no_config_annotation() {
        // Ingress has ingressClassName: headmaster but no headmaster config annotation.
        // Layer 2 parse fails → await_change (no finalizer stamped, no K8s calls after parse).
        let ctx = Arc::new(test_ctx(FaultService::client(all_500)));
        let result = super::reconcile(Arc::new(headmaster_ingress("any-namespace")), ctx).await;
        // headmaster_ingress has no config annotation → parse returns Err → gate skips adoption.
        // But the mock returns 500 for any K8s call, and layer 2 would need to call the instance
        // API if parse succeeded. Since parse fails first, no K8s calls are made → Ok.
        assert!(
            result.is_ok(),
            "Ingress without config annotation must be silently skipped (no finalizer stamped)"
        );
    }

    // ── class release tests ───────────────────────────────────────────────────

    fn class_changed_responder(m: &http::Method, path: &str) -> (u16, Vec<u8>) {
        if *m == http::Method::GET && path.contains("/ingresses/") {
            // Re-fetch in release_ingress: return Ingress with our finalizer and a resourceVersion.
            let our_finalizer = crate::finalizer("default");
            (
                200,
                serde_json::json!({
                    "apiVersion": "networking.k8s.io/v1",
                    "kind": "Ingress",
                    "metadata": {
                        "name": "test-ingress",
                        "namespace": "app-ns",
                        "resourceVersion": "42",
                        "finalizers": [our_finalizer]
                    }
                })
                .to_string()
                .into_bytes(),
            )
        } else if *m == http::Method::PATCH {
            (
                200,
                serde_json::json!({
                    "apiVersion": "networking.k8s.io/v1",
                    "kind": "Ingress",
                    "metadata": {"name": "test-ingress", "namespace": "app-ns", "resourceVersion": "43"}
                })
                .to_string()
                .into_bytes(),
            )
        } else {
            // State secret, StatefulSet, etc. — 404 so cleanup_proxy_resources proceeds cleanly.
            (404, br#"{"code":404}"#.to_vec())
        }
    }

    #[tokio::test]
    async fn apply_releases_ingress_when_ingressclass_changes() {
        use k8s_openapi::api::networking::v1::IngressSpec;

        // Ingress previously had ingressClassName: headmaster (so we own it),
        // but the user changed it to "nginx". Our finalizer is still present.
        let our_finalizer = crate::finalizer("default");
        let ingress = Arc::new(Ingress {
            metadata: ObjectMeta {
                name: Some("test-ingress".to_string()),
                namespace: Some("app-ns".to_string()),
                uid: Some("uid-class-change-1".to_string()),
                finalizers: Some(vec![our_finalizer]),
                ..Default::default()
            },
            spec: Some(IngressSpec {
                ingress_class_name: Some("nginx".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        });

        let (k8s, calls) = FaultService::tracked(class_changed_responder);
        let ctx = test_ctx(k8s);

        let result = apply(ingress, &ctx).await;
        assert!(
            result.is_ok(),
            "apply must succeed when ingressClassName changes away from headmaster"
        );

        let recorded = calls.lock().unwrap();
        let has_ingress_patch = recorded
            .iter()
            .any(|(m, p)| m == "PATCH" && p.contains("/ingresses/test-ingress"));
        assert!(
            has_ingress_patch,
            "a PATCH to release the finalizer must be issued when class changes: {recorded:?}"
        );
    }

    // ── watchedNamespaces release tests ──────────────────────────────────────

    fn instance_with_watched_namespaces_responder(m: &http::Method, path: &str) -> (u16, Vec<u8>) {
        use crate::types::{
            HeadscaleInstance, HeadscaleInstanceSpec, HeadscaleInstanceStatus, StorageSpec,
        };
        use k8s_openapi::api::core::v1::Namespace as K8sNamespace;
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};

        if *m == http::Method::GET && path.contains("headscaleinstances") {
            let instance = HeadscaleInstance {
                metadata: ObjectMeta {
                    name: Some("main".to_string()),
                    namespace: Some("default".to_string()),
                    uid: Some("uid-1".to_string()),
                    ..Default::default()
                },
                spec: HeadscaleInstanceSpec {
                    server_url: "https://headscale.example.com".to_string(),
                    dns_base_domain: "ts.example.com".to_string(),
                    storage: StorageSpec {
                        size: "1Gi".to_string(),
                        ..Default::default()
                    },
                    watched_namespaces: vec!["prod".to_string()],
                    ..Default::default()
                },
                status: Some(HeadscaleInstanceStatus {
                    conditions: vec![Condition {
                        type_: "Ready".to_string(),
                        status: "True".to_string(),
                        reason: "Ready".to_string(),
                        message: "ready".to_string(),
                        last_transition_time: Time(k8s_openapi::jiff::Timestamp::UNIX_EPOCH),
                        observed_generation: None,
                    }],
                    ..Default::default()
                }),
            };
            (200, serde_json::to_vec(&instance).unwrap())
        } else if *m == http::Method::GET && path.contains("/ingresses/") {
            // Return a plausible Ingress with resourceVersion for the release_ingress re-fetch.
            (
                200,
                serde_json::json!({
                    "apiVersion": "networking.k8s.io/v1",
                    "kind": "Ingress",
                    "metadata": {
                        "name": "test-ingress",
                        "namespace": "staging",
                        "resourceVersion": "2",
                        "finalizers": ["headmaster.potatonode.github.io/cleanup-default"]
                    }
                })
                .to_string()
                .into_bytes(),
            )
        } else if *m == http::Method::GET && path.contains("/namespaces/staging") {
            // Return a live namespace without deletionTimestamp so namespace_is_deleting returns false.
            let ns = K8sNamespace {
                metadata: ObjectMeta {
                    name: Some("staging".to_string()),
                    ..Default::default()
                },
                ..Default::default()
            };
            (200, serde_json::to_vec(&ns).unwrap())
        } else if *m == http::Method::PATCH {
            // Return a plausible Ingress JSON for the finalizer patch.
            (200, serde_json::json!({
                "apiVersion": "networking.k8s.io/v1",
                "kind": "Ingress",
                "metadata": {"name": "test-ingress", "namespace": "staging", "resourceVersion": "2"}
            }).to_string().into_bytes())
        } else {
            // GETs for secrets, statefulsets, etc. — 404 so cleanup proceeds cleanly.
            (404, br#"{"code":404}"#.to_vec())
        }
    }

    #[tokio::test]
    async fn apply_removes_finalizer_when_namespace_excluded_from_watched_namespaces() {
        use crate::controllers::ingress::ANNOTATION_CONFIG;
        use k8s_openapi::api::networking::v1::IngressSpec;
        use std::collections::BTreeMap;

        let our_finalizer = crate::finalizer("default");
        let ingress = Arc::new(Ingress {
            metadata: ObjectMeta {
                name: Some("test-ingress".to_string()),
                namespace: Some("staging".to_string()),
                uid: Some("uid-ing-1".to_string()),
                finalizers: Some(vec![our_finalizer.clone()]),
                annotations: Some(BTreeMap::from([(
                    ANNOTATION_CONFIG.to_string(),
                    r#"{"headscale-ref":"main","user":"alice"}"#.to_string(),
                )])),
                ..Default::default()
            },
            spec: Some(IngressSpec {
                ingress_class_name: Some(INGRESS_CLASS_NAME.to_string()),
                ..Default::default()
            }),
            ..Default::default()
        });

        let (k8s, calls) = FaultService::tracked(instance_with_watched_namespaces_responder);
        let ctx = test_ctx(k8s);

        let result = apply(ingress, &ctx).await;
        assert!(
            result.is_ok(),
            "apply must succeed when namespace is excluded from watchedNamespaces"
        );

        let recorded = calls.lock().unwrap();
        let has_ingress_patch = recorded
            .iter()
            .any(|(m, p)| m == "PATCH" && p.contains("/ingresses/test-ingress"));
        assert!(
            has_ingress_patch,
            "a PATCH to remove the finalizer must be issued: {recorded:?}"
        );
    }
}
