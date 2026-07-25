//! Shared reconcile support for proxy parents: connecting to the parent's
//! headscale instance, deregistering + deleting a proxy's resources, and the
//! small helpers both controllers need around namespaces and state Secrets.

use headscale_client::headscale::v1::DeleteNodeRequest;
use headscale_client::{AuthenticatedClient, Code};
use k8s_ext::SecretGetExt;
use k8s_openapi::api::apps::v1::StatefulSet;
use k8s_openapi::api::core::v1::{
    ConfigMap, Namespace, ObjectReference, Secret, Service, ServiceAccount,
};
use k8s_openapi::api::rbac::v1::{Role, RoleBinding};
use kube::api::Api;
use kube::{Client, Resource};

use super::Error;
use super::names::ProxyNames;
use crate::context::Context;
use crate::controllers::applier::delete_ignoring_404;
use crate::controllers::recorder::RecorderExt;
use crate::types::HeadscaleInstance;

/// Deregisters the proxy's headscale node (if registered) and deletes all proxy
/// k8s resources. Called on parent deletion, namespace exclusion, and ownership
/// release.
///
/// State secret read errors are propagated so the caller requeues and retries,
/// ensuring the node is removed before k8s resources are cleaned up. All other
/// errors (headscale connection, node deletion, k8s resource deletion) are
/// best-effort: logged or published as events, then cleanup continues.
pub(crate) async fn deregister_and_cleanup(
    ctx: &Context,
    op_ns: &str,
    names: &ProxyNames,
    parent_ref: &ObjectReference,
    headscale_ref_fallback: &str,
) -> Result<(), Error> {
    let parent_name = parent_ref.name.clone().unwrap_or_default();

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
                        parent_ref,
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
                        name = parent_name,
                        node_id = id,
                        "deleted node from headscale"
                    ),
                    Err(e) if e.code() == Code::NotFound => tracing::debug!(
                        name = parent_name,
                        "cleanup: node already gone from headscale"
                    ),
                    Err(e) => {
                        // Return an error so the finalizer stays in place and
                        // the reconciler retries. The state Secret must not be
                        // deleted until we have confirmed headscale no longer
                        // tracks the node — it holds the node_id we need to
                        // retry the deletion.
                        tracing::warn!(
                            name = parent_name,
                            node_id = id,
                            error = %e,
                            "cleanup: failed to delete node from headscale; will retry"
                        );
                        return Err(Error::HeadscaleApi(e));
                    }
                }
                let recorder = ctx.recorder();
                let _ = recorder.publish_deleted(parent_ref).await;
            }
        }
    }

    cleanup_proxy_resources(ctx, op_ns, names).await;
    Ok(())
}

/// Explicitly deletes all proxy resources created in the operator namespace.
///
/// Proxy resources are owned by their HeadscaleInstance (same namespace), so GC
/// handles cleanup on HeadscaleInstance deletion. For parent deletion the owner
/// is still alive, so this explicit cleanup is still required.
/// All deletes are best-effort: 404s are silently ignored; unexpected errors are
/// logged so leaked resources are discoverable, but cleanup continues regardless.
pub(crate) async fn cleanup_proxy_resources(ctx: &Context, op_ns: &str, names: &ProxyNames) {
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
            // Egress consumers allowlist; ingress proxies never create one,
            // for them this is a no-op 404.
            Api::<k8s_openapi::api::networking::v1::NetworkPolicy>::namespaced(c.clone(), op_ns),
            &names.proxy_name
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

pub(crate) async fn namespace_is_deleting(client: &Client, ns: &str) -> Result<bool, Error> {
    match Api::<Namespace>::all(client.clone()).get(ns).await {
        Ok(ns_obj) => Ok(ns_obj.metadata.deletion_timestamp.is_some()),
        Err(kube::Error::Api(ref e)) if e.code == 404 => Ok(true),
        Err(e) => Err(Error::Kube(e)),
    }
}

pub(crate) fn read_secret_string(secret: &Secret, key: &str) -> Option<String> {
    String::from_utf8(secret.item(key)?.0.clone()).ok()
}

pub(crate) fn read_secret_json<T: serde::de::DeserializeOwned>(
    secret: &Secret,
    key: &str,
) -> Option<T> {
    serde_json::from_slice(&secret.item(key)?.0).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controllers::ingress::test_support::{test_ctx, test_ingress};
    use crate::test_support::{FaultService, all_404, all_500};

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

    #[tokio::test]
    async fn deregister_and_cleanup_propagates_state_secret_error() {
        let (k8s, calls) = FaultService::tracked(all_500);
        let ctx = test_ctx(k8s);
        let names = ProxyNames::new("default", "test-ingress");

        let result = deregister_and_cleanup(
            &ctx,
            "default",
            &names,
            &test_ingress().object_ref(&()),
            "main",
        )
        .await;

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

        let result = deregister_and_cleanup(
            &ctx,
            "default",
            &names,
            &test_ingress().object_ref(&()),
            "main",
        )
        .await;

        assert!(
            result.is_ok(),
            "missing state secret must not abort cleanup"
        );
    }
}
