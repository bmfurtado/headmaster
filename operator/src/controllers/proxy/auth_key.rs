//! Manages the headscale pre-auth key lifecycle for proxy registration.
//! Creates a short-lived key before the proxy pod starts, and revokes the old
//! key when the proxy re-registers (the new key is only needed until the proxy
//! joins the tailnet for the first time).

use std::time::Duration;

use headscale_client::headscale::v1::{
    CreatePreAuthKeyRequest, DeletePreAuthKeyRequest, ListUsersRequest,
};
use headscale_client::{AuthenticatedClient, Status};
use k8s_ext::{SecretExt, SecretGetExt};
use k8s_openapi::ByteString;
use k8s_openapi::api::core::v1::ObjectReference;
use k8s_openapi::api::core::v1::Secret;
use kube::api::Api;
use prost_types::Timestamp;

use super::Error;
use super::names::ProxyNames;
use crate::context::Context;
use crate::controllers::applier::ChildApplier;
use crate::controllers::recorder::RecorderExt;

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
            ephemeral: false,
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
        )
        .await;

        assert_eq!(result.unwrap(), AuthKeyStatus::Ready);
        let keys = state.lock().unwrap().pre_auth_keys.clone();
        assert_eq!(keys[0].acl_tags, vec!["tag:server"]);
    }
}
