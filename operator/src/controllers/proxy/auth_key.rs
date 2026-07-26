//! Manages the headscale pre-auth key lifecycle for proxy registration.
//! Creates a short-lived key before the proxy pod starts, and revokes the old
//! key when the proxy re-registers (the new key is only needed until the proxy
//! joins the tailnet for the first time).
//!
//! The key's job is over once the proxy has joined — but "joined" is not a
//! permanent state: the headscale node can be deleted or expire server-side,
//! and then the proxy needs a *working* key again to get back on the tailnet.
//! `rotate_stale_auth_key` detects both dead-end states (registration lost,
//! key expired before first join) and clears the stale Secret so
//! `ensure_auth_key` mints a fresh key on the same reconcile. Without it a
//! proxy that loses its registration crash-loops on the dead key forever
//! while the operator, seeing a Secret present, believes all is well.

use std::time::Duration;

use headscale_client::headscale::v1::{
    CreatePreAuthKeyRequest, DeletePreAuthKeyRequest, GetNodeRequest, ListUsersRequest,
};
use headscale_client::{AuthenticatedClient, Code, Status};
use k8s_ext::{SecretExt, SecretGetExt};
use k8s_openapi::ByteString;
use k8s_openapi::api::core::v1::ObjectReference;
use k8s_openapi::api::core::v1::Secret;
use kube::api::Api;
use prost_types::Timestamp;

use super::Error;
use super::names::ProxyNames;
use super::support::read_secret_string;
use crate::context::Context;
use crate::controllers::applier::{ChildApplier, delete_ignoring_404};
use crate::controllers::recorder::RecorderExt;

/// Detects a proxy whose auth key can never work again and deletes the stale
/// Secrets so the `ensure_auth_key` call that follows mints a fresh key.
/// Call before `ensure_auth_key` on every reconcile. Two dead-end states:
///
/// - **Registration lost** — the state Secret records a `device_id`, but
///   headscale no longer has that node (deleted out-of-band) or the node's
///   key has expired. tailscaled falls back to the auth key from the config
///   Secret, which was spent (and likely expired) at first join. Both the
///   config and state Secrets are deleted: the fresh key lets the proxy
///   re-register, and dropping the state makes that a clean first boot
///   instead of a fight over a dead node identity.
/// - **Never joined, key expired** — no `device_id` yet and the config
///   Secret has outlived the key's expiry window, so the key inside cannot
///   register anyone. Only the config Secret is deleted.
///
/// Recovery relies on the kubelet re-resolving `TS_AUTHKEY` (a secretKeyRef
/// env var) when it restarts the proxy container: a proxy in either dead-end
/// state is crash-looping, so the next backoff restart picks up the fresh
/// key. A proxy whose container keeps *running* while logged out won't reload
/// the key until something restarts it — acceptable, because the observed
/// failure mode is containerboot exiting on auth failure.
pub(crate) async fn rotate_stale_auth_key(
    ctx: &Context,
    ns: &str,
    parent_ref: &ObjectReference,
    headscale: &mut AuthenticatedClient,
    names: &ProxyNames,
    expiry_secs: u64,
) -> Result<(), Error> {
    let secrets: Api<Secret> = Api::namespaced(ctx.client.clone(), ns);

    let device_id = match secrets.get(&names.state_secret_name).await {
        Ok(secret) => read_secret_string(&secret, "device_id").and_then(|s| s.parse::<u64>().ok()),
        Err(kube::Error::Api(ref e)) if e.code == 404 => None,
        Err(e) => return Err(Error::Kube(e)),
    };

    if let Some(node_id) = device_id {
        let now = now_epoch_secs();
        let lost = match headscale.get_node(GetNodeRequest { node_id }).await {
            // expiry unset or zero means "never expires" in headscale.
            Ok(resp) => resp
                .into_inner()
                .node
                .and_then(|n| n.expiry)
                .is_some_and(|t| t.seconds > 0 && t.seconds < now),
            Err(e) if e.code() == Code::NotFound => true,
            Err(e) => return Err(e.into()),
        };
        if !lost {
            return Ok(());
        }
        let recorder = ctx.recorder();
        let _ = recorder
            .publish_warning(
                parent_ref,
                "ProxyRegistrationLost",
                &format!(
                    "headscale no longer accepts node {node_id}; rotating the \
                     auth key and resetting proxy state so it can re-register"
                ),
            )
            .await;
        delete_ignoring_404(secrets.clone(), &names.config_secret_name).await?;
        delete_ignoring_404(secrets, &names.state_secret_name).await?;
        return Ok(());
    }

    // Not registered yet: the key in the config Secret is the only way onto
    // the tailnet, and it self-destructs on a clock. Once the Secret has
    // outlived the expiry window the key was minted with, waiting longer
    // cannot help anyone.
    let config_secret = match secrets.get(&names.config_secret_name).await {
        Ok(secret) => secret,
        Err(kube::Error::Api(ref e)) if e.code == 404 => return Ok(()),
        Err(e) => return Err(Error::Kube(e)),
    };
    let minted_at = config_secret
        .metadata
        .creation_timestamp
        .as_ref()
        .map(|t| t.0.as_second());
    let expired = minted_at.is_some_and(|created| {
        created.saturating_add(i64::try_from(expiry_secs).unwrap_or(i64::MAX)) < now_epoch_secs()
    });
    if !expired {
        return Ok(());
    }
    let recorder = ctx.recorder();
    let _ = recorder
        .publish_warning(
            parent_ref,
            "AuthKeyExpired",
            &format!(
                "auth key in Secret '{}' expired before the proxy ever \
                 registered; rotating it",
                names.config_secret_name
            ),
        )
        .await;
    delete_ignoring_404(secrets, &names.config_secret_name).await?;
    Ok(())
}

fn now_epoch_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or_default()
}

/// Outcome of `ensure_auth_key`: either the key is available and provisioning
/// can continue, or the required headscale user doesn't exist yet.
#[derive(Debug, PartialEq)]
pub(crate) enum AuthKeyStatus {
    Ready,
    WaitingForUser,
}

/// Returns [`AuthKeyStatus::Ready`] when a key is available and provisioning
/// can continue, or [`AuthKeyStatus::WaitingForUser`] when the named headscale
/// user does not exist yet (warning event already published; caller should requeue).
///
/// Both `user` and `managed_key_tags` may be set simultaneously. When
/// `auto_tag` is `Some`, it is appended to the pre-auth key's `acl_tags` so
/// the proxy registers with the operator-assigned tag required for access grants.
/// `ephemeral` mints a key whose node headscale garbage-collects after it
/// goes offline — the backstop for tun-mode proxies, whose node the operator
/// also deletes explicitly on teardown.
///
/// Creates the pre-auth key in headscale and immediately persists it to
/// Kubernetes in a single function. If the Kubernetes save fails, the key is
/// deleted from headscale to avoid leaking it.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn ensure_auth_key(
    ctx: &Context,
    ns: &str,
    parent_ref: &ObjectReference,
    headscale: &mut AuthenticatedClient,
    child: &ChildApplier<'_>,
    names: &ProxyNames,
    user: Option<&str>,
    managed_key_tags: &[String],
    auto_tag: Option<&str>,
    expiry_secs: u64,
    reusable: bool,
    ephemeral: bool,
) -> Result<AuthKeyStatus, Error> {
    if existing_auth_key(ctx, ns, &names.config_secret_name)
        .await?
        .is_some()
    {
        return Ok(AuthKeyStatus::Ready);
    }

    let expiration_secs = std::time::SystemTime::now()
        .checked_add(Duration::from_secs(expiry_secs))
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .unwrap_or(i64::MAX);

    let user_id = if let Some(user_name) = user {
        let existing_user = headscale
            .list_users(ListUsersRequest {
                name: user_name.to_string(),
                ..Default::default()
            })
            .await?
            .into_inner()
            .users
            .into_iter()
            .next();
        match existing_user {
            Some(u) => u.id,
            None => {
                let recorder = ctx.recorder();
                let _ = recorder
                    .publish_warning(
                        parent_ref,
                        "UserNotFound",
                        &format!(
                            "headscale user '{user_name}' does not exist; \
                             create it in headscale before this proxy can be provisioned"
                        ),
                    )
                    .await;
                return Ok(AuthKeyStatus::WaitingForUser);
            }
        }
    } else {
        0
    };

    let mut acl_tags = managed_key_tags.to_vec();
    if let Some(tag) = auto_tag {
        acl_tags.push(tag.to_string());
    }

    let pre_auth_key = headscale
        .create_pre_auth_key(CreatePreAuthKeyRequest {
            user: user_id,
            reusable,
            ephemeral,
            expiration: Some(Timestamp {
                seconds: expiration_secs,
                nanos: 0,
            }),
            acl_tags,
        })
        .await?
        .into_inner()
        .pre_auth_key
        .ok_or_else(|| Status::internal("CreatePreAuthKey returned no key"))?;

    if let Err(e) = apply_config_secret(child, names, &pre_auth_key.key).await {
        if let Err(cleanup_err) = headscale
            .delete_pre_auth_key(DeletePreAuthKeyRequest {
                id: pre_auth_key.id,
            })
            .await
        {
            tracing::warn!(
                key_id = pre_auth_key.id,
                error = %cleanup_err,
                "failed to delete pre-auth key after K8s secret save failed; \
                 key may be leaked in headscale"
            );
        }
        return Err(e);
    }

    Ok(AuthKeyStatus::Ready)
}

pub(crate) async fn existing_auth_key(
    ctx: &Context,
    ns: &str,
    config_secret_name: &str,
) -> Result<Option<String>, Error> {
    match Api::<Secret>::namespaced(ctx.client.clone(), ns)
        .get(config_secret_name)
        .await
    {
        Ok(secret) => Ok(extract_auth_key(&secret)),
        Err(kube::Error::Api(ref e)) if e.code == 404 => Ok(None),
        Err(e) => Err(Error::Kube(e)),
    }
}

async fn apply_config_secret(
    child: &ChildApplier<'_>,
    names: &ProxyNames,
    auth_key: &str,
) -> Result<(), Error> {
    child
        .apply(
            "tailscale-proxy",
            Secret::new(&names.config_secret_name)
                .data([("key", ByteString(auth_key.as_bytes().to_vec()))]),
        )
        .await?;
    Ok(())
}

pub(crate) fn extract_auth_key(secret: &Secret) -> Option<String> {
    let key = String::from_utf8(secret.item("key")?.0.clone()).ok()?;
    if key.is_empty() { None } else { Some(key) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controllers::ingress::test_support::{test_ctx, test_ingress};
    use crate::test_support::{FaultService, all_500};
    use headscale_client::AuthInterceptor;
    use headscale_client::HeadscaleServiceClient;
    use headscale_client::fake::{FakeHeadscaleServer, spawn_fake_channel};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use kube::Resource;
    use std::sync::Arc;

    fn patch_500_else_404(m: &http::Method, _: &str) -> (u16, Vec<u8>) {
        if *m == http::Method::PATCH {
            (500, br#"{"code":500}"#.to_vec())
        } else {
            (404, br#"{"code":404}"#.to_vec())
        }
    }

    fn get_existing_secret(_: &http::Method, _: &str) -> (u16, Vec<u8>) {
        let secret = Secret {
            metadata: ObjectMeta {
                name: Some("proxy-authkey-default-test-ingress".to_string()),
                namespace: Some("default".to_string()),
                resource_version: Some("1".to_string()),
                ..Default::default()
            },
            data: Some(std::collections::BTreeMap::from([(
                "key".to_string(),
                ByteString(b"existing-auth-key".to_vec()),
            )])),
            ..Default::default()
        };
        (200, serde_json::to_vec(&secret).unwrap())
    }

    fn get_404_patch_ok(m: &http::Method, _: &str) -> (u16, Vec<u8>) {
        if *m == http::Method::PATCH {
            (
                200,
                br#"{"apiVersion":"v1","kind":"Secret","metadata":{"name":"t","namespace":"default","resourceVersion":"1"}}"#
                    .to_vec(),
            )
        } else {
            (404, br#"{"code":404}"#.to_vec())
        }
    }

    #[tokio::test]
    async fn pre_auth_key_deleted_when_k8s_secret_save_fails() {
        let server = FakeHeadscaleServer::default();
        let state = Arc::clone(&server.state);
        let channel = spawn_fake_channel(server).await;
        let mut headscale =
            HeadscaleServiceClient::with_interceptor(channel, AuthInterceptor::bearer("test"));

        let ctx = test_ctx(FaultService::client(patch_500_else_404));
        let child = ChildApplier::for_test(&ctx.client, "default", "test-proxy");
        let names = ProxyNames::new("default", "test-ingress");

        let result = ensure_auth_key(
            &ctx,
            "default",
            &test_ingress().object_ref(&()),
            &mut headscale,
            &child,
            &names,
            None,
            &["tag:server".to_string()],
            None,
            600,
            false,
            false,
        )
        .await;

        assert!(result.is_err(), "must propagate the K8s save error");
        assert!(
            state.lock().unwrap().pre_auth_keys.is_empty(),
            "pre-auth key must be deleted from headscale when K8s secret save fails"
        );
    }

    #[tokio::test]
    async fn pre_auth_key_retained_when_k8s_secret_save_succeeds() {
        let server = FakeHeadscaleServer::default();
        let state = Arc::clone(&server.state);
        let channel = spawn_fake_channel(server).await;
        let mut headscale =
            HeadscaleServiceClient::with_interceptor(channel, AuthInterceptor::bearer("test"));

        let ctx = test_ctx(FaultService::client(get_404_patch_ok));
        let child = ChildApplier::for_test(&ctx.client, "default", "test-proxy");
        let names = ProxyNames::new("default", "test-ingress");

        let result = ensure_auth_key(
            &ctx,
            "default",
            &test_ingress().object_ref(&()),
            &mut headscale,
            &child,
            &names,
            None,
            &["tag:server".to_string()],
            None,
            600,
            false,
            false,
        )
        .await;

        assert_eq!(result.unwrap(), AuthKeyStatus::Ready);
        assert_eq!(
            state.lock().unwrap().pre_auth_keys.len(),
            1,
            "pre-auth key must be kept in headscale when K8s secret save succeeds"
        );
    }

    #[tokio::test]
    async fn ensure_auth_key_skips_headscale_when_secret_already_exists() {
        let server = FakeHeadscaleServer::default();
        let state = Arc::clone(&server.state);
        let channel = spawn_fake_channel(server).await;
        let mut headscale =
            HeadscaleServiceClient::with_interceptor(channel, AuthInterceptor::bearer("test"));

        // GET returns a valid Secret → ensure_auth_key must return early without
        // calling headscale at all.
        let ctx = test_ctx(FaultService::client(get_existing_secret));
        let child = ChildApplier::for_test(&ctx.client, "default", "test-proxy");
        let names = ProxyNames::new("default", "test-ingress");

        let result = ensure_auth_key(
            &ctx,
            "default",
            &test_ingress().object_ref(&()),
            &mut headscale,
            &child,
            &names,
            None,
            &["tag:server".to_string()],
            None,
            600,
            false,
            false,
        )
        .await;

        assert_eq!(result.unwrap(), AuthKeyStatus::Ready);
        assert!(
            state.lock().unwrap().pre_auth_keys.is_empty(),
            "headscale must not be called when the auth-key secret already exists"
        );
    }

    #[tokio::test]
    async fn existing_auth_key_propagates_non_404_error() {
        let ctx = test_ctx(FaultService::client(all_500));
        let result = existing_auth_key(&ctx, "default", "any-secret").await;
        assert!(result.is_err(), "non-404 GET error must propagate");
    }

    #[tokio::test]
    async fn existing_auth_key_returns_key_when_secret_exists() {
        let ctx = test_ctx(FaultService::client(get_existing_secret));
        let key = existing_auth_key(&ctx, "default", "proxy-authkey-default-test-ingress")
            .await
            .unwrap();
        assert_eq!(key.as_deref(), Some("existing-auth-key"));
    }

    #[tokio::test]
    async fn auto_tag_appended_to_acl_tags() {
        use headscale_client::headscale::v1::User;

        let server = FakeHeadscaleServer::default();
        server.state.lock().unwrap().users.push(User {
            id: 1,
            name: "alice".to_string(),
            ..Default::default()
        });
        let state = Arc::clone(&server.state);
        let channel = spawn_fake_channel(server).await;
        let mut headscale =
            HeadscaleServiceClient::with_interceptor(channel, AuthInterceptor::bearer("test"));

        let ctx = test_ctx(FaultService::client(get_404_patch_ok));
        let child = ChildApplier::for_test(&ctx.client, "default", "test-proxy");
        let names = ProxyNames::new("default", "test-ingress");

        let result = ensure_auth_key(
            &ctx,
            "default",
            &test_ingress().object_ref(&()),
            &mut headscale,
            &child,
            &names,
            Some("alice"),
            &["tag:server".to_string()],
            Some("tag:hm-default-test-ingress"),
            600,
            false,
            false,
        )
        .await;

        assert_eq!(result.unwrap(), AuthKeyStatus::Ready);
        let keys = state.lock().unwrap().pre_auth_keys.clone();
        assert_eq!(keys.len(), 1);
        assert_eq!(
            keys[0].acl_tags,
            vec!["tag:server", "tag:hm-default-test-ingress"],
            "auto-tag must be appended after managed-key-tags"
        );
    }

    #[tokio::test]
    async fn ephemeral_flag_reaches_headscale() {
        let server = FakeHeadscaleServer::default();
        let state = Arc::clone(&server.state);
        let channel = spawn_fake_channel(server).await;
        let mut headscale =
            HeadscaleServiceClient::with_interceptor(channel, AuthInterceptor::bearer("test"));

        let ctx = test_ctx(FaultService::client(get_404_patch_ok));
        let child = ChildApplier::for_test(&ctx.client, "default", "test-proxy");
        let names = ProxyNames::new("default", "test-ingress");

        let result = ensure_auth_key(
            &ctx,
            "default",
            &test_ingress().object_ref(&()),
            &mut headscale,
            &child,
            &names,
            None,
            &["tag:server".to_string()],
            None,
            600,
            false,
            true,
        )
        .await;

        assert_eq!(result.unwrap(), AuthKeyStatus::Ready);
        let keys = state.lock().unwrap().pre_auth_keys.clone();
        assert_eq!(keys.len(), 1);
        assert!(
            keys[0].ephemeral,
            "ephemeral=true must be forwarded to CreatePreAuthKey"
        );
    }

    // ── rotate_stale_auth_key ─────────────────────────────────────────────

    /// Responds as if the proxy is registered: state Secret carries
    /// device_id 1 (the fake server's first allocated node id), config
    /// Secret exists, deletes succeed.
    fn registered_proxy(m: &http::Method, p: &str) -> (u16, Vec<u8>) {
        if *m == http::Method::DELETE {
            return (
                200,
                br#"{"kind":"Status","apiVersion":"v1","status":"Success"}"#.to_vec(),
            );
        }
        if p.contains("proxy-state") {
            // base64("1") == "MQ=="
            return (
                200,
                br#"{"apiVersion":"v1","kind":"Secret","metadata":{"name":"s","namespace":"default","resourceVersion":"1"},"data":{"device_id":"MQ=="}}"#.to_vec(),
            );
        }
        if p.contains("proxy-authkey") {
            return (
                200,
                br#"{"apiVersion":"v1","kind":"Secret","metadata":{"name":"k","namespace":"default","resourceVersion":"1","creationTimestamp":"2020-01-01T00:00:00Z"},"data":{"key":"a2V5"}}"#.to_vec(),
            );
        }
        (201, br#"{}"#.to_vec())
    }

    /// No state Secret; config Secret minted in 2020 (long past any expiry).
    fn unregistered_stale_key(m: &http::Method, p: &str) -> (u16, Vec<u8>) {
        if *m == http::Method::DELETE {
            return (
                200,
                br#"{"kind":"Status","apiVersion":"v1","status":"Success"}"#.to_vec(),
            );
        }
        if p.contains("proxy-state") {
            return (404, br#"{"code":404}"#.to_vec());
        }
        if p.contains("proxy-authkey") {
            return (
                200,
                br#"{"apiVersion":"v1","kind":"Secret","metadata":{"name":"k","namespace":"default","resourceVersion":"1","creationTimestamp":"2020-01-01T00:00:00Z"},"data":{"key":"a2V5"}}"#.to_vec(),
            );
        }
        (201, br#"{}"#.to_vec())
    }

    /// No state Secret; config Secret creationTimestamp far enough in the
    /// future that the expiry window cannot have elapsed.
    fn unregistered_fresh_key(m: &http::Method, p: &str) -> (u16, Vec<u8>) {
        if *m == http::Method::DELETE {
            return (
                200,
                br#"{"kind":"Status","apiVersion":"v1","status":"Success"}"#.to_vec(),
            );
        }
        if p.contains("proxy-state") {
            return (404, br#"{"code":404}"#.to_vec());
        }
        if p.contains("proxy-authkey") {
            return (
                200,
                br#"{"apiVersion":"v1","kind":"Secret","metadata":{"name":"k","namespace":"default","resourceVersion":"1","creationTimestamp":"2100-01-01T00:00:00Z"},"data":{"key":"a2V5"}}"#.to_vec(),
            );
        }
        (201, br#"{}"#.to_vec())
    }

    fn deletes_of(calls: &crate::test_support::Calls) -> Vec<String> {
        calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(m, _)| m == "DELETE")
            .map(|(_, p)| p.clone())
            .collect()
    }

    async fn fake_headscale_with_state() -> (
        std::sync::Arc<std::sync::Mutex<headscale_client::fake::FakeState>>,
        AuthenticatedClient,
    ) {
        let server = FakeHeadscaleServer::default();
        let state = Arc::clone(&server.state);
        let channel = spawn_fake_channel(server).await;
        let client =
            HeadscaleServiceClient::with_interceptor(channel, AuthInterceptor::bearer("test"));
        (state, client)
    }

    #[tokio::test]
    async fn rotate_keeps_secrets_while_registration_is_healthy() {
        use headscale_client::headscale::v1::User;

        let (state, mut headscale) = fake_headscale_with_state().await;
        state
            .lock()
            .unwrap()
            .nodes
            .push(headscale_client::headscale::v1::Node {
                id: 1,
                user: Some(User::default()),
                expiry: None,
                ..Default::default()
            });

        let (client, calls) = FaultService::tracked(registered_proxy);
        let ctx = test_ctx(client);
        let names = ProxyNames::new("default", "test-ingress");

        rotate_stale_auth_key(
            &ctx,
            "default",
            &test_ingress().object_ref(&()),
            &mut headscale,
            &names,
            600,
        )
        .await
        .unwrap();

        assert!(
            deletes_of(&calls).is_empty(),
            "healthy registration must not delete anything"
        );
    }

    #[tokio::test]
    async fn rotate_resets_both_secrets_when_node_is_gone() {
        // No node seeded: get_node(1) returns NotFound.
        let (_state, mut headscale) = fake_headscale_with_state().await;

        let (client, calls) = FaultService::tracked(registered_proxy);
        let ctx = test_ctx(client);
        let names = ProxyNames::new("default", "test-ingress");

        rotate_stale_auth_key(
            &ctx,
            "default",
            &test_ingress().object_ref(&()),
            &mut headscale,
            &names,
            600,
        )
        .await
        .unwrap();

        let deletes = deletes_of(&calls);
        assert!(
            deletes.iter().any(|p| p.contains("proxy-authkey")),
            "config Secret must be deleted when the node is gone: {deletes:?}"
        );
        assert!(
            deletes.iter().any(|p| p.contains("proxy-state")),
            "state Secret must be deleted when the node is gone: {deletes:?}"
        );
    }

    #[tokio::test]
    async fn rotate_resets_both_secrets_when_node_is_expired() {
        use headscale_client::headscale::v1::User;

        let (state, mut headscale) = fake_headscale_with_state().await;
        state
            .lock()
            .unwrap()
            .nodes
            .push(headscale_client::headscale::v1::Node {
                id: 1,
                user: Some(User::default()),
                // Long in the past, and nonzero (zero means "never expires").
                expiry: Some(prost_types::Timestamp {
                    seconds: 1,
                    nanos: 0,
                }),
                ..Default::default()
            });

        let (client, calls) = FaultService::tracked(registered_proxy);
        let ctx = test_ctx(client);
        let names = ProxyNames::new("default", "test-ingress");

        rotate_stale_auth_key(
            &ctx,
            "default",
            &test_ingress().object_ref(&()),
            &mut headscale,
            &names,
            600,
        )
        .await
        .unwrap();

        let deletes = deletes_of(&calls);
        assert!(
            deletes.iter().any(|p| p.contains("proxy-authkey"))
                && deletes.iter().any(|p| p.contains("proxy-state")),
            "expired node must rotate like a deleted one: {deletes:?}"
        );
    }

    #[tokio::test]
    async fn rotate_drops_config_secret_when_key_expired_before_first_join() {
        let (_state, mut headscale) = fake_headscale_with_state().await;

        let (client, calls) = FaultService::tracked(unregistered_stale_key);
        let ctx = test_ctx(client);
        let names = ProxyNames::new("default", "test-ingress");

        rotate_stale_auth_key(
            &ctx,
            "default",
            &test_ingress().object_ref(&()),
            &mut headscale,
            &names,
            600,
        )
        .await
        .unwrap();

        let deletes = deletes_of(&calls);
        assert!(
            deletes.iter().any(|p| p.contains("proxy-authkey")),
            "expired never-used key must be dropped: {deletes:?}"
        );
        assert!(
            !deletes.iter().any(|p| p.contains("proxy-state")),
            "state Secret must be left alone when nothing registered: {deletes:?}"
        );
    }

    #[tokio::test]
    async fn rotate_leaves_fresh_unused_key_alone() {
        let (_state, mut headscale) = fake_headscale_with_state().await;

        let (client, calls) = FaultService::tracked(unregistered_fresh_key);
        let ctx = test_ctx(client);
        let names = ProxyNames::new("default", "test-ingress");

        rotate_stale_auth_key(
            &ctx,
            "default",
            &test_ingress().object_ref(&()),
            &mut headscale,
            &names,
            600,
        )
        .await
        .unwrap();

        assert!(
            deletes_of(&calls).is_empty(),
            "a key still inside its expiry window must not be rotated"
        );
    }

    #[tokio::test]
    async fn no_auto_tag_when_none() {
        let server = FakeHeadscaleServer::default();
        let state = Arc::clone(&server.state);
        let channel = spawn_fake_channel(server).await;
        let mut headscale =
            HeadscaleServiceClient::with_interceptor(channel, AuthInterceptor::bearer("test"));

        let ctx = test_ctx(FaultService::client(get_404_patch_ok));
        let child = ChildApplier::for_test(&ctx.client, "default", "test-proxy");
        let names = ProxyNames::new("default", "test-ingress");

        let result = ensure_auth_key(
            &ctx,
            "default",
            &test_ingress().object_ref(&()),
            &mut headscale,
            &child,
            &names,
            None,
            &["tag:server".to_string()],
            None,
            600,
            false,
            false,
        )
        .await;

        assert_eq!(result.unwrap(), AuthKeyStatus::Ready);
        let keys = state.lock().unwrap().pre_auth_keys.clone();
        assert_eq!(keys[0].acl_tags, vec!["tag:server"]);
    }
}
