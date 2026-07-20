//! Main reconcile loop for `HeadscaleInstance`. Drives the apply/cleanup
//! lifecycle: ensures the headscale StatefulSet, Service, ConfigMap, API-key
//! Secret, optional SCIM sidecar, and policy are all in the desired state.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use headscale_client::headscale::v1::ListUsersRequest;
use k8s_ext::{ServiceExt, ServicePortExt, StatefulSetGetExt};
use k8s_openapi::api::apps::v1::StatefulSet;
use k8s_openapi::api::core::v1::{
    ConfigMap, PersistentVolumeClaim, Service, ServicePort, ServiceSpec,
};
use k8s_openapi::api::networking::v1::Ingress;
use kube::api::{Api, ListParams, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::runtime::finalizer::{Event as Finalizer, finalizer};
use kube::runtime::reflector::ObjectRef;
use kube::runtime::watcher;
use kube::{Resource, ResourceExt};

use super::bootstrap::ensure_api_key;
use super::builders::{build_configmap, desired_statefulset};
use super::policy::{policy_has_groups_with_members, sync_policy};
use super::scim::{delete_scim_if_exists, ensure_scim};
use super::{Error, PORT_GRPC, PORT_HTTP, PORT_METRICS};
use crate::context::Context;
use crate::controllers::applier::{Applier, ChildApplier, delete_ignoring_404};
use crate::controllers::ingress::headscale_connect;
use crate::controllers::recorder::RecorderExt;
use crate::labels;
use crate::types::{HeadscaleInstance, IngressAnnotations, ResourceStatus};

/// Runs the `HeadscaleInstance` controller until `shutdown` resolves.
pub fn stream(
    api: Api<HeadscaleInstance>,
    ctx: Arc<Context>,
    shutdown: impl Future<Output = ()> + Send + Sync + 'static,
) -> impl Future<Output = ()> {
    let ns = api
        .namespace()
        .expect("HeadscaleInstance API must be namespaced")
        .to_owned();
    let owns_cfg = watcher::Config::default().labels(&labels::managed_by_selector());

    kube::runtime::Controller::new(api, Default::default())
        .owns(
            Api::<StatefulSet>::namespaced(ctx.client.clone(), &ns),
            owns_cfg.clone(),
        )
        .owns(
            Api::<ConfigMap>::namespaced(ctx.client.clone(), &ns),
            owns_cfg.clone(),
        )
        .owns(
            Api::<Service>::namespaced(ctx.client.clone(), &ns),
            owns_cfg,
        )
        .watches(
            Api::<Ingress>::all(ctx.client.clone()),
            watcher::Config::default(),
            {
                let op_ns = ns.clone();
                move |ing| {
                    IngressAnnotations::headscale_ref(&ing)
                        .map(|href| {
                            ObjectRef::<HeadscaleInstance>::new(href.as_str()).within(&op_ns)
                        })
                        .into_iter()
                }
            },
        )
        .graceful_shutdown_on(shutdown)
        .run(reconcile, error_policy, ctx)
        .for_each(|res| async move {
            if let Err(e) = res {
                tracing::warn!(error = ?e, "HeadscaleInstance reconcile error");
            }
        })
}

async fn reconcile(obj: Arc<HeadscaleInstance>, ctx: Arc<Context>) -> Result<Action, Error> {
    let ns = obj.namespace().ok_or(Error::MissingNamespace)?;
    let api: Api<HeadscaleInstance> = Api::namespaced(ctx.client.clone(), &ns);
    let our_finalizer = crate::finalizer(&ctx.operator_namespace);
    finalizer(&api, &our_finalizer, obj, |event| async {
        match event {
            Finalizer::Apply(obj) => apply(obj, &ctx).await,
            Finalizer::Cleanup(obj) => cleanup(obj, &ctx).await,
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

fn error_policy(_obj: Arc<HeadscaleInstance>, e: &Error, _ctx: Arc<Context>) -> Action {
    tracing::warn!("HeadscaleInstance reconcile failed: {e:?}");
    Action::requeue(Duration::from_secs(30))
}

async fn apply(obj: Arc<HeadscaleInstance>, ctx: &Context) -> Result<Action, Error> {
    if obj.spec.external.is_some() {
        return apply_external(&obj, ctx).await;
    }

    let ns = obj.namespace().ok_or(Error::MissingNamespace)?;
    let name = obj.name_any();
    let client = &ctx.client;

    let old_status = obj.status.clone().unwrap_or_default();
    let generation = obj.metadata.generation.unwrap_or(0);

    let child = ChildApplier::from_parent(ctx, &obj);
    let headscale_name = format!("headscale-server-{name}");

    let a = Applier::from_ctx(ctx);

    if let Err(e) = ensure_headscale(ctx, &child, &obj).await {
        let mut error_status = old_status.clone();
        error_status.update_ready(
            false,
            "ChildApplyFailed",
            format!("failed to apply child resource: {e}"),
            generation,
        );
        let _ = a.apply_status(&*obj, &error_status).await;
        return Err(e);
    }

    let live_sts = Api::<StatefulSet>::namespaced(client.clone(), &ns)
        .get(&headscale_name)
        .await?;
    let is_ready = live_sts.ready_replicas().unwrap_or(0) > 0;

    if !is_ready {
        let mut new_status = old_status.clone();
        new_status.update_ready(
            false,
            "StatefulSetNotReady",
            "headscale StatefulSet is not yet ready",
            generation,
        );
        a.apply_status(&*obj, &new_status).await?;
        let obj_ref = obj.object_ref(&());
        ctx.recorder()
            .publish_transitions(&old_status, &new_status, &obj_ref)
            .await;
        return Ok(Action::requeue(Duration::from_secs(10)));
    }

    // Run all post-readiness operations in a single block so that any failure
    // is caught once and reflected in the status before propagating. Without
    // this, a failure here after a previously-successful reconcile leaves the
    // status stale at Ready=True while the reconciler loops on error.
    let result: Result<(), Error> = async {
        ensure_api_key(ctx, &child).await?;

        // The webhook blocks this at admission, but guard again here in case it
        // is bypassed: SCIM owns the groups section; a non-empty groups key in
        // spec.policy.inline would be clobbered by sync_policy's full replacement.
        if obj.spec.scim.is_some() && policy_has_groups_with_members(obj.spec.policy.as_ref()) {
            return Err(Error::ScimPolicyConflict);
        }
        let contributing_ingresses =
            list_contributing_ingresses(&ctx.client, &name, &obj.spec.watched_namespaces).await?;
        sync_policy(
            ctx,
            &ns,
            &name,
            obj.spec.policy.as_ref(),
            obj.spec.scim.is_some(),
            &contributing_ingresses,
        )
        .await?;

        match &obj.spec.scim {
            Some(scim) => ensure_scim(ctx, &child, scim).await,
            None => delete_scim_if_exists(ctx, &ns, &name).await,
        }
    }
    .await;

    if let Err(e) = result {
        let reason = match &e {
            Error::ScimPolicyConflict => "ScimPolicyConflict",
            _ => "ReconcileFailed",
        };
        let mut error_status = old_status.clone();
        error_status.update_ready(false, reason, e.to_string(), generation);
        let _ = a.apply_status(&*obj, &error_status).await;
        return Err(e);
    }

    let mut new_status = old_status.clone();
    new_status.update_ready(
        true,
        "StatefulSetReady",
        "headscale StatefulSet is ready",
        generation,
    );
    a.apply_status(&*obj, &new_status).await?;
    let obj_ref = obj.object_ref(&());
    ctx.recorder()
        .publish_transitions(&old_status, &new_status, &obj_ref)
        .await;

    // Periodic requeue so that WaitingForGroup grants are retried after SCIM
    // syncs new groups to headscale. SCIM is k8s-agnostic and does not touch
    // any watched resource, so watch events alone are not sufficient.
    Ok(Action::requeue(Duration::from_secs(60)))
}

/// Reconciles an instance whose headscale runs outside the cluster. No child
/// resources exist: readiness is purely "an authenticated gRPC call to the
/// external server succeeds". API-key bootstrap, policy sync, and SCIM never
/// run here — the external server's operator owns configuration and policy,
/// so a `SetPolicy` from us (including the allow-all reset for `policy:
/// None`) would clobber state we do not own.
async fn apply_external(obj: &Arc<HeadscaleInstance>, ctx: &Context) -> Result<Action, Error> {
    let ns = obj.namespace().ok_or(Error::MissingNamespace)?;
    let name = obj.name_any();
    let old_status = obj.status.clone().unwrap_or_default();
    let generation = obj.metadata.generation.unwrap_or(0);
    let a = Applier::from_ctx(ctx);

    // Webhook-enforced, but guard again in case admission was bypassed.
    if obj.spec.policy.is_some() || obj.spec.scim.is_some() || !obj.spec.extra_config.is_empty() {
        let e = Error::ExternalSpecConflict;
        let mut error_status = old_status.clone();
        error_status.update_ready(false, "ExternalSpecConflict", e.to_string(), generation);
        let _ = a.apply_status(&**obj, &error_status).await;
        return Err(e);
    }

    let probe: Result<(), String> = async {
        let mut client = headscale_connect(ctx, &ns, &name)
            .await
            .map_err(|e| e.to_string())?;
        client
            .list_users(ListUsersRequest::default())
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }
    .await;

    let mut new_status = old_status.clone();
    let (ready, requeue_secs) = match &probe {
        Ok(()) => {
            new_status.update_ready(
                true,
                "ExternalReachable",
                "external headscale answered an authenticated gRPC call",
                generation,
            );
            // Periodic re-probe so a dead server flips the instance (and
            // with it new Ingress provisioning) to not-ready.
            (true, 60)
        }
        Err(e) => {
            new_status.update_ready(
                false,
                "ExternalUnreachable",
                format!("external headscale probe failed: {e}"),
                generation,
            );
            (false, 15)
        }
    };
    a.apply_status(&**obj, &new_status).await?;
    let obj_ref = obj.object_ref(&());
    ctx.recorder()
        .publish_transitions(&old_status, &new_status, &obj_ref)
        .await;

    if !ready {
        tracing::warn!(
            name = name,
            "HeadscaleInstance (external): probe failed, requeueing"
        );
    }
    Ok(Action::requeue(Duration::from_secs(requeue_secs)))
}

/// Cleans up a `HeadscaleInstance` before the finalizer is removed.
///
/// Ingresses that still reference this instance are orphaned: their
/// `status.loadBalancer.ingress` is cleared and a warning event is posted so
/// operators can see what happened. The Ingress controller will keep requeueing
/// them and publishing "Pending" events until the user re-points or deletes them.
/// Built-in children (StatefulSet, ConfigMap, Service, Secret) are operator-owned
/// via ownerReferences and are garbage-collected automatically.
/// PVCs from volumeClaimTemplates are NOT garbage-collected automatically; see
/// the explicit deletion block below.
async fn cleanup(obj: Arc<HeadscaleInstance>, ctx: &Context) -> Result<Action, Error> {
    let instance_name = obj.name_any();

    let allow_all = vec!["*".to_string()];
    let referencing = list_contributing_ingresses(&ctx.client, &instance_name, &allow_all).await?;

    let recorder = ctx.recorder();
    let ssa = PatchParams::apply(&crate::field_manager(&ctx.operator_namespace)).force();
    for ing in &referencing {
        let ing_ns = ing.namespace().unwrap_or_default();
        let ing_name = ing.name_any();
        let _ = recorder
            .publish_warning(
                &ing.object_ref(&()),
                "InstanceDeleted",
                &format!(
                    "HeadscaleInstance '{instance_name}' was deleted; \
                     this Ingress is now orphaned and will stop functioning"
                ),
            )
            .await;
        let _ = Api::<Ingress>::namespaced(ctx.client.clone(), &ing_ns)
            .patch_status(
                &ing_name,
                &ssa,
                &Patch::Apply(serde_json::json!({
                    "apiVersion": "networking.k8s.io/v1",
                    "kind": "Ingress",
                    "metadata": { "name": ing_name, "namespace": ing_ns },
                    "status": {}
                })),
            )
            .await;
    }

    if !referencing.is_empty() {
        tracing::info!(
            name = instance_name,
            count = referencing.len(),
            "HeadscaleInstance cleanup: orphaned referencing Ingresses"
        );
    }

    tracing::info!(
        name = instance_name,
        "HeadscaleInstance cleanup: proceeding"
    );

    // Explicitly delete PVCs created from volumeClaimTemplates. Kubernetes does
    // not garbage-collect these automatically because they have no ownerReference
    // to the HeadscaleInstance.
    //
    // TODO: remove this block and set persistentVolumeClaimRetentionPolicy
    // whenDeleted=Delete on both StatefulSets once k3s fixes the bug where that
    // policy prevents readyReplicas from being updated (k3s 1.32.5).
    let ns = obj.namespace().ok_or(Error::MissingNamespace)?;
    let pvc_api: Api<PersistentVolumeClaim> = Api::namespaced(ctx.client.clone(), &ns);
    for pvc_name in [
        format!("data-headscale-server-{instance_name}-0"),
        format!("data-headscale-scim-{instance_name}-0"),
    ] {
        delete_ignoring_404(pvc_api.clone(), &pvc_name).await?;
    }

    let _ = ctx.recorder().publish_deleted(&obj.object_ref(&())).await;
    Ok(Action::await_change())
}

/// Lists all Ingresses across all namespaces that reference the named
/// HeadscaleInstance. Used to enumerate contributing Ingresses for policy grants.
async fn list_contributing_ingresses(
    client: &kube::Client,
    instance_name: &str,
    watched_namespaces: &[String],
) -> Result<Vec<Ingress>, Error> {
    let ingress_api = Api::<Ingress>::all(client.clone());
    let all_ingresses = ingress_api
        .list(&ListParams::default())
        .await
        .map_err(Error::Kube)?
        .items;
    Ok(all_ingresses
        .into_iter()
        .filter(|ing| {
            let class = ing
                .spec
                .as_ref()
                .and_then(|s| s.ingress_class_name.as_deref())
                .or_else(|| {
                    ing.annotations()
                        .get("kubernetes.io/ingress.class")
                        .map(String::as_str)
                });
            class == Some(crate::controllers::ingress::INGRESS_CLASS_NAME)
        })
        .filter(|ing| IngressAnnotations::headscale_ref(ing).as_deref() == Some(instance_name))
        .filter(|ing| {
            let ns = ing.namespace().unwrap_or_default();
            watched_namespaces.iter().any(|w| w == "*" || w == &ns)
        })
        .collect())
}

async fn ensure_headscale(
    ctx: &Context,
    child: &ChildApplier<'_>,
    obj: &HeadscaleInstance,
) -> Result<(), Error> {
    let headscale_name = format!("headscale-server-{}", child.instance);
    let (config_map, hash) = build_configmap(
        &headscale_name,
        &obj.spec.server_url,
        &obj.spec.dns_base_domain,
        &obj.spec.extra_config,
    )?;
    child.apply("headscale", config_map).await?;
    child
        .apply_service(
            "headscale",
            Service::new(&headscale_name).spec(ServiceSpec {
                ports: Some(vec![
                    ServicePort::tcp("http", PORT_HTTP).target_port("http"),
                    ServicePort::tcp("metrics", PORT_METRICS).target_port("metrics"),
                    ServicePort::tcp("grpc", PORT_GRPC).target_port("grpc"),
                ]),
                ..Default::default()
            }),
        )
        .await?;
    child
        .apply_statefulset(
            "headscale",
            desired_statefulset(
                &headscale_name,
                &ctx.headscale_image,
                &obj.spec.storage,
                obj.spec.resources.as_ref(),
                &hash,
            ),
        )
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controllers::headscale_instance::test_support::{minimal_instance, test_ctx};
    use crate::test_support::FaultService;
    use crate::types::ExternalSpec;
    use headscale_client::fake::{FakeHeadscaleServer, spawn_fake_channel};
    use headscale_client::{
        AuthInterceptor, Channel, HeadscaleConnector, HeadscaleServiceClient, TransportError,
    };
    use k8s_openapi::ByteString;
    use k8s_openapi::api::core::v1::Secret;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    fn external_instance() -> HeadscaleInstance {
        let mut instance = minimal_instance("ext");
        instance.spec.external = Some(ExternalSpec {
            grpc_endpoint: "http://100.64.0.3:50443".to_string(),
            api_key_secret_ref: "external-api-key".to_string(),
        });
        instance
    }

    struct FakeConnector(Channel);

    #[async_trait::async_trait]
    impl HeadscaleConnector for FakeConnector {
        async fn connect(
            &self,
            _endpoint: &str,
            api_key: &str,
        ) -> Result<headscale_client::AuthenticatedClient, TransportError> {
            Ok(HeadscaleServiceClient::with_interceptor(
                self.0.clone(),
                AuthInterceptor::bearer(api_key),
            ))
        }
    }

    /// K8s responder for the external path: the instance GET (issued by
    /// headscale_connect), the referenced API-key Secret, and status PATCHes.
    fn external_responder(m: &http::Method, path: &str) -> (u16, Vec<u8>) {
        if path.contains("headscaleinstances") && *m == http::Method::GET {
            return (200, serde_json::to_vec(&external_instance()).unwrap());
        }
        if path.contains("/secrets/external-api-key") {
            let secret = Secret {
                metadata: ObjectMeta {
                    name: Some("external-api-key".to_string()),
                    namespace: Some("default".to_string()),
                    resource_version: Some("1".to_string()),
                    ..Default::default()
                },
                data: Some(std::collections::BTreeMap::from([(
                    "HEADSCALE_API_KEY".to_string(),
                    ByteString(b"test-api-key".to_vec()),
                )])),
                ..Default::default()
            };
            return (200, serde_json::to_vec(&secret).unwrap());
        }
        if *m == http::Method::PATCH {
            return (200, serde_json::to_vec(&external_instance()).unwrap());
        }
        (404, br#"{"code":404}"#.to_vec())
    }

    #[tokio::test]
    async fn apply_external_ready_when_probe_succeeds() {
        let server = FakeHeadscaleServer::default();
        let channel = spawn_fake_channel(server).await;
        let (k8s, calls) = FaultService::tracked(external_responder);
        let ctx = Context {
            headscale: std::sync::Arc::new(FakeConnector(channel)),
            ..test_ctx(k8s)
        };

        let result = apply_external(&Arc::new(external_instance()), &ctx).await;

        assert!(result.is_ok(), "probe success must reconcile cleanly");
        let recorded = calls.lock().unwrap();
        assert!(
            recorded
                .iter()
                .any(|(m, p)| m == "PATCH" && p.contains("/status")),
            "a Ready status patch must be issued: {recorded:?}"
        );
    }

    #[tokio::test]
    async fn apply_external_not_ready_when_secret_missing() {
        // Responder without the API-key Secret: headscale_connect fails, the
        // instance must go not-ready (status patch) without erroring out.
        fn responder(m: &http::Method, path: &str) -> (u16, Vec<u8>) {
            if path.contains("headscaleinstances") && *m == http::Method::GET {
                return (200, serde_json::to_vec(&external_instance()).unwrap());
            }
            if *m == http::Method::PATCH {
                return (200, serde_json::to_vec(&external_instance()).unwrap());
            }
            (404, br#"{"code":404}"#.to_vec())
        }
        let server = FakeHeadscaleServer::default();
        let channel = spawn_fake_channel(server).await;
        let (k8s, calls) = FaultService::tracked(responder);
        let ctx = Context {
            headscale: std::sync::Arc::new(FakeConnector(channel)),
            ..test_ctx(k8s)
        };

        let result = apply_external(&Arc::new(external_instance()), &ctx).await;

        assert!(result.is_ok(), "probe failure must requeue, not error");
        let recorded = calls.lock().unwrap();
        assert!(
            recorded
                .iter()
                .any(|(m, p)| m == "PATCH" && p.contains("/status")),
            "a not-ready status patch must be issued: {recorded:?}"
        );
    }

    #[tokio::test]
    async fn apply_external_rejects_operator_owned_fields() {
        let mut instance = external_instance();
        instance.spec.policy = Some(crate::types::HeadscaleInstancePolicy::Inline {
            inline: r#"{"acls":[]}"#.to_string(),
        });
        let server = FakeHeadscaleServer::default();
        let channel = spawn_fake_channel(server).await;
        let ctx = Context {
            headscale: std::sync::Arc::new(FakeConnector(channel)),
            ..test_ctx(FaultService::client(external_responder))
        };

        let result = apply_external(&Arc::new(instance), &ctx).await;

        assert!(
            matches!(result, Err(Error::ExternalSpecConflict)),
            "external + policy must be rejected even past the webhook"
        );
    }
}
