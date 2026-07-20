//! Syncs the headscale ACL policy with the current state of `Ingress` grants
//! and SCIM groups. Merges operator-managed entries into the live policy while
//! preserving all other keys (acls, hosts, tagOwners, etc.).

use std::collections::HashSet;

use headscale_client::headscale::v1::{GetPolicyRequest, SetPolicyRequest};
use headscale_client::policy::{PolicyEditor, policies_are_semantically_equal};
use jsonc_parser::cst::CstInputValue;
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::api::networking::v1::Ingress;
use kube::api::Api;
use kube::{Resource, ResourceExt};

use super::Error;
use crate::context::Context;
use crate::controllers::ingress::{headscale_connect, ingress_auto_tag};
use crate::controllers::recorder::RecorderExt;
use crate::types::HeadscaleInstancePolicy;
use crate::types::IngressAnnotations;

/// Applies `policy` to headscale via the gRPC `SetPolicy` call when the live
/// policy differs. Requires `policy.mode: database` in the headscale config.
///
/// When `scim_enabled` is true the `groups` key is owned by the SCIM service
/// and must not be overwritten. The live groups section is preserved in the
/// value written to headscale so that a spec change (which triggers a reconcile)
/// cannot clobber SCIM-managed group membership.
///
/// `ingresses` lists all Ingresses that reference this HeadscaleInstance. Those
/// with non-empty `access` contribute operator-managed `grants` entries. Grants
/// whose `from` references a group not yet in the live policy are skipped and a
/// `WaitingForGroup` warning event is posted on the Ingress.
///
/// When `policy` is `None`, the operator sets headscale to allow-all by calling
/// `SetPolicy("")`. This is idempotent: the call is skipped when the live policy
/// is already empty.
pub(super) async fn sync_policy(
    ctx: &Context,
    namespace: &str,
    instance: &str,
    policy: Option<&HeadscaleInstancePolicy>,
    scim_enabled: bool,
    ingresses: &[Ingress],
) -> Result<(), Error> {
    let mut client = headscale_connect(ctx, namespace, instance)
        .await
        .map_err(Error::Kube)?;
    let current = match client.get_policy(GetPolicyRequest {}).await {
        Ok(resp) => resp.into_inner().policy,
        Err(s) if s.message().contains("policy not found") => String::new(),
        Err(s) => return Err(Error::HeadscaleApi(s)),
    };

    let desired = match policy {
        Some(HeadscaleInstancePolicy::Inline { inline }) => inline.as_str(),
        None => {
            if !current.is_empty() {
                client
                    .set_policy(SetPolicyRequest {
                        policy: String::new(),
                    })
                    .await?;
            }
            return Ok(());
        }
    };

    // All CST work is done synchronously before any .await so that the
    // PolicyEditor (which wraps an Rc-backed CstRootNode) never crosses an
    // await point — PolicyEditor is !Send.
    let policy_before_grants = {
        let mut editor = match PolicyEditor::parse(desired) {
            Ok(e) => e,
            Err(e) => return Err(Error::InvalidPolicy(e)),
        };

        // When SCIM is enabled, copy the live groups section into the desired
        // policy so we never overwrite what the SCIM service manages.
        if scim_enabled && let Ok(current_editor) = PolicyEditor::parse(&current) {
            editor.copy_groups_from(&current_editor);
        }

        // Ensure tag:headmaster exists in tagOwners (headscale rejects grants
        // that reference an undeclared tag). Empty owners list matches the
        // examples chart default and is accepted by all headscale versions.
        editor.set_tag_owner(HEADMASTER_TAG, &[]);

        editor.to_string()
        // editor (and current_editor) dropped here — no CstRootNode in scope
    };

    // Merge operator-managed grants from contributing Ingresses. This is async
    // (publishes WaitingForGroup warnings) but returns a plain String; CST work
    // inside it happens after all .awaits.
    let effective_desired = merge_ingress_grants(ctx, &policy_before_grants, ingresses).await;

    // Compare semantically: headscale normalises whitespace and strips comments
    // when it stores the policy, so a textual diff may not mean the policy
    // actually changed.
    if policies_are_semantically_equal(current.trim(), effective_desired.trim()) {
        return Ok(());
    }

    client
        .set_policy(SetPolicyRequest {
            policy: effective_desired,
        })
        .await?;
    tracing::debug!(
        name = instance,
        "HeadscaleInstance: applied policy via gRPC"
    );

    // Notify SCIM to re-apply its group membership immediately so that the
    // operator's SetPolicy and SCIM's groups section stay in sync. Best-effort:
    // SCIM will self-heal on the next SCIM protocol operation if unreachable.
    if scim_enabled {
        notify_scim(ctx, namespace, instance).await;
    }

    Ok(())
}

const HEADMASTER_TAG: &str = "tag:headmaster";

/// Collects operator-owned `grants` from contributing Ingresses, publishes
/// `WaitingForGroup` warnings for unresolved groups, then appends the grants
/// to `policy_str` and returns the updated policy. CST mutations happen only
/// after all async calls so that no `PolicyEditor` ever crosses an `.await`.
async fn merge_ingress_grants(ctx: &Context, policy_str: &str, ingresses: &[Ingress]) -> String {
    // Extract known groups synchronously before any await.
    let known_groups: HashSet<String> = PolicyEditor::parse(policy_str)
        .map(|e| e.known_groups())
        .unwrap_or_default();
    // PolicyEditor dropped immediately after known_groups is computed.

    let mut sorted_ingresses: Vec<&Ingress> = ingresses.iter().collect();
    sorted_ingresses.sort_by_key(|ing| (ing.namespace().unwrap_or_default(), ing.name_any()));

    // Accumulate (grant, auto_tag) pairs. CstInputValue is Send so these are
    // safe to hold across the async publish_warning calls below.
    let mut ingress_grants: Vec<(CstInputValue, String)> = Vec::new();

    for ing in sorted_ingresses {
        let annotations = match IngressAnnotations::parse(ing) {
            Ok(a) if !a.access.is_empty() => a,
            _ => continue,
        };

        let ing_ns = ing.namespace().unwrap_or_default();
        let ing_name = ing.name_any();
        let auto_tag = ingress_auto_tag(&ing_ns, &ing_name);

        for grant in &annotations.access {
            let missing_groups: Vec<&str> = grant
                .from
                .iter()
                .filter(|s| s.starts_with("group:") && !known_groups.contains(*s))
                .map(String::as_str)
                .collect();

            if !missing_groups.is_empty() {
                // Async warning publish — no PolicyEditor in scope here.
                if let Err(e) = ctx
                    .recorder()
                    .publish_warning(
                        &ing.object_ref(&()),
                        "WaitingForGroup",
                        &format!(
                            "access grant references groups not yet synced: {}; \
                             the grant will be applied once these groups are available",
                            missing_groups.join(", ")
                        ),
                    )
                    .await
                {
                    tracing::warn!(
                        ingress = %ing.name_any(),
                        error = ?e,
                        "failed to publish WaitingForGroup event"
                    );
                }
                continue;
            }

            let src = CstInputValue::Array(
                grant
                    .from
                    .iter()
                    .map(|s| CstInputValue::String(s.clone()))
                    .collect(),
            );
            let dst = CstInputValue::Array(vec![CstInputValue::String(auto_tag.clone())]);

            let grant_cst = if let Some(caps) = &grant.capabilities {
                CstInputValue::Object(vec![
                    ("src".to_string(), src),
                    ("dst".to_string(), dst),
                    (
                        "app".to_string(),
                        serde_val_to_cst(&serde_json::json!(caps)),
                    ),
                ])
            } else {
                CstInputValue::Object(vec![
                    ("src".to_string(), src),
                    ("dst".to_string(), dst),
                    (
                        "ip".to_string(),
                        CstInputValue::Array(vec![CstInputValue::String("*:*".to_string())]),
                    ),
                ])
            };

            ingress_grants.push((grant_cst, auto_tag.clone()));
        }
    }

    // No more .awaits after this point. Apply grants with a fresh PolicyEditor.
    if ingress_grants.is_empty() {
        return policy_str.to_string();
    }
    let mut editor = match PolicyEditor::parse(policy_str) {
        Ok(e) => e,
        Err(_) => return policy_str.to_string(),
    };
    for (grant, auto_tag) in ingress_grants {
        editor.set_tag_owner(&auto_tag, &[HEADMASTER_TAG]);
        editor.append_grants(&[grant]);
    }
    editor.to_string()
}

fn serde_val_to_cst(v: &serde_json::Value) -> CstInputValue {
    match v {
        serde_json::Value::Null => CstInputValue::Null,
        serde_json::Value::Bool(b) => CstInputValue::Bool(*b),
        serde_json::Value::Number(n) => CstInputValue::Number(n.to_string()),
        serde_json::Value::String(s) => CstInputValue::String(s.clone()),
        serde_json::Value::Array(a) => {
            CstInputValue::Array(a.iter().map(serde_val_to_cst).collect())
        }
        serde_json::Value::Object(o) => CstInputValue::Object(
            o.iter()
                .map(|(k, v)| (k.clone(), serde_val_to_cst(v)))
                .collect(),
        ),
    }
}

/// Sends `POST /internal/reconcile` to the SCIM sidecar for `instance`.
/// Best-effort: logs on failure, never propagates the error.
async fn notify_scim(ctx: &Context, namespace: &str, instance: &str) {
    let token = match read_scim_token(ctx, namespace, instance).await {
        Ok(token) => token,
        Err(e) => {
            tracing::warn!(
                name = instance,
                error = %e,
                "HeadscaleInstance: failed to read SCIM token; SCIM will resync on next operation"
            );
            return;
        }
    };
    let url = format!(
        "http://headscale-scim-{instance}.{namespace}.svc:{}/internal/reconcile",
        super::PORT_SCIM,
    );
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap_or_default();
    match client.post(&url).bearer_auth(&token).send().await {
        Ok(r) if r.status().is_success() => {
            tracing::debug!(
                name = instance,
                "HeadscaleInstance: notified SCIM to reconcile"
            );
        }
        Ok(r) => tracing::warn!(
            name = instance,
            status = %r.status(),
            "HeadscaleInstance: SCIM reconcile notification returned non-success"
        ),
        Err(e) => tracing::warn!(
            name = instance,
            error = %e,
            "HeadscaleInstance: failed to reach SCIM; it will resync on next SCIM operation"
        ),
    }
}

async fn read_scim_token(
    ctx: &Context,
    namespace: &str,
    instance: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let secret_name = format!("headscale-scim-token-{instance}");
    let secret = Api::<Secret>::namespaced(ctx.client.clone(), namespace)
        .get(&secret_name)
        .await?;
    let token = secret
        .data
        .as_ref()
        .and_then(|secret_data| secret_data.get("SCIM_BEARER_TOKEN"))
        .map(|byte_string| String::from_utf8_lossy(&byte_string.0).into_owned())
        .ok_or("SCIM_BEARER_TOKEN key not found in secret")?;
    Ok(token)
}

/// Returns `true` when the inline policy contains at least one `groups` entry
/// with members. An empty `groups: {}` or groups with empty arrays do not
/// conflict with SCIM — SCIM will populate or remove them. Only non-empty
/// member lists indicate the user is managing groups manually.
pub(crate) fn policy_has_groups_with_members(policy: Option<&HeadscaleInstancePolicy>) -> bool {
    let Some(HeadscaleInstancePolicy::Inline { inline }) = policy else {
        return false;
    };
    if inline.trim().is_empty() {
        return false;
    }
    use jsonc_parser::ParseOptions;
    jsonc_parser::parse_to_serde_value::<serde_json::Value>(inline, &ParseOptions::default())
        .ok()
        .and_then(|v| {
            v.get("groups").and_then(|g| g.as_object()).map(|g| {
                g.values()
                    .any(|v| v.as_array().is_some_and(|a| !a.is_empty()))
            })
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controllers::headscale_instance::test_support::test_ctx;
    use crate::controllers::ingress::ANNOTATION_CONFIG;
    use crate::test_support::FaultService;
    use headscale_client::fake::{FakeHeadscaleServer, spawn_fake_channel};
    use headscale_client::{
        AuthInterceptor, Channel, HeadscaleConnector, HeadscaleServiceClient, TransportError,
    };
    use k8s_openapi::ByteString;
    use k8s_openapi::api::core::v1::Secret;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use std::sync::Arc;

    fn inline_policy(json: &str) -> Option<HeadscaleInstancePolicy> {
        Some(HeadscaleInstancePolicy::Inline {
            inline: json.to_string(),
        })
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

    /// Returns the managed HeadscaleInstance for instance GETs (which
    /// headscale_connect performs first) and the API-key Secret otherwise.
    fn api_key_secret(_: &http::Method, path: &str) -> (u16, Vec<u8>) {
        if path.contains("headscaleinstances") {
            let instance = crate::types::HeadscaleInstance {
                metadata: ObjectMeta {
                    name: Some("test-instance".to_string()),
                    namespace: Some("default".to_string()),
                    uid: Some("uid-hi-1".to_string()),
                    ..Default::default()
                },
                spec: crate::types::HeadscaleInstanceSpec {
                    server_url: "https://headscale.example.com".to_string(),
                    dns_base_domain: "ts.example.com".to_string(),
                    ..Default::default()
                },
                status: None,
            };
            return (200, serde_json::to_vec(&instance).unwrap());
        }
        let secret = Secret {
            metadata: ObjectMeta {
                name: Some("headscale-api-key-test-instance".to_string()),
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
        (200, serde_json::to_vec(&secret).unwrap())
    }

    // ── policy_has_groups_with_members ────────────────────────────────────────

    #[test]
    fn policy_has_groups_with_members_detects_groups() {
        let policy = inline_policy(r#"{"groups":{"group:eng":["alice@example.com"]},"acls":[]}"#);
        assert!(policy_has_groups_with_members(policy.as_ref()));
    }

    #[test]
    fn policy_has_groups_with_members_false_when_no_groups() {
        let policy = inline_policy(r#"{"acls":[],"tagOwners":{}}"#);
        assert!(!policy_has_groups_with_members(policy.as_ref()));
    }

    #[test]
    fn policy_has_groups_with_members_false_when_none() {
        assert!(!policy_has_groups_with_members(None));
    }

    #[test]
    fn policy_has_groups_with_members_false_when_empty_object() {
        assert!(!policy_has_groups_with_members(
            inline_policy("{}").as_ref()
        ));
    }

    #[test]
    fn policy_has_groups_with_members_false_on_invalid_json() {
        assert!(!policy_has_groups_with_members(
            inline_policy("not-valid-json").as_ref()
        ));
    }

    #[test]
    fn policy_has_groups_with_members_false_when_groups_empty_object() {
        assert!(!policy_has_groups_with_members(
            inline_policy(r#"{"groups":{}}"#).as_ref()
        ));
    }

    #[test]
    fn policy_has_groups_with_members_true_for_hujson() {
        let policy = inline_policy(
            r#"{
                // engineering team
                "groups": { "group:eng": ["alice@example.com"] },
                "acls": []
            }"#,
        );
        assert!(policy_has_groups_with_members(policy.as_ref()));
    }

    #[test]
    fn policy_has_groups_with_members_false_when_all_groups_are_empty_arrays() {
        assert!(!policy_has_groups_with_members(
            inline_policy(r#"{"groups":{"group:eng":[],"group:ops":[]}}"#).as_ref()
        ));
    }

    #[test]
    fn policy_has_groups_with_members_true_when_one_group_has_members() {
        assert!(policy_has_groups_with_members(
            inline_policy(r#"{"groups":{"group:ops":[],"group:eng":["alice@example.com"]}}"#)
                .as_ref()
        ));
    }

    // ── sync_policy end-to-end tests ─────────────────────────────────────────

    #[tokio::test]
    async fn sync_policy_skips_set_policy_when_hujson_semantically_equal() {
        let initial_policy =
            r#"{"groups":{"group:eng":["alice@example.com"]},"tagOwners":{"tag:headmaster":[]}}"#;
        let server = FakeHeadscaleServer::default();
        *server.policy.lock().unwrap() = initial_policy.to_string();
        let policy_store = Arc::clone(&server.policy);
        let channel = spawn_fake_channel(server).await;

        let ctx = Context {
            client: FaultService::client(api_key_secret),
            headscale: Arc::new(FakeConnector(channel)),
            ..test_ctx(FaultService::client(api_key_secret))
        };

        let hujson_policy = inline_policy(
            r#"{
                // engineering team
                "groups": { "group:eng": ["alice@example.com"] }
            }"#,
        );

        sync_policy(
            &ctx,
            "default",
            "test-instance",
            hujson_policy.as_ref(),
            false,
            &[],
        )
        .await
        .expect("sync_policy must succeed");

        assert_eq!(
            *policy_store.lock().unwrap(),
            initial_policy,
            "SetPolicy must not be called when the HuJSON policy is semantically equal to the live policy"
        );
    }

    #[tokio::test]
    async fn sync_policy_calls_set_policy_when_policy_differs() {
        let server = FakeHeadscaleServer::default();
        *server.policy.lock().unwrap() =
            r#"{"groups":{"group:eng":["alice@example.com"]}}"#.to_string();
        let policy_store = Arc::clone(&server.policy);
        let channel = spawn_fake_channel(server).await;

        let ctx = Context {
            client: FaultService::client(api_key_secret),
            headscale: Arc::new(FakeConnector(channel)),
            ..test_ctx(FaultService::client(api_key_secret))
        };

        let new_policy = inline_policy(r#"{"groups":{"group:ops":["bob@example.com"]}}"#);

        sync_policy(
            &ctx,
            "default",
            "test-instance",
            new_policy.as_ref(),
            false,
            &[],
        )
        .await
        .expect("sync_policy must succeed");

        let stored: serde_json::Value =
            serde_json::from_str(&policy_store.lock().unwrap()).unwrap();
        assert_eq!(
            stored["groups"]["group:ops"][0], "bob@example.com",
            "SetPolicy must be called when the policy genuinely differs"
        );
        assert_eq!(
            stored["tagOwners"]["tag:headmaster"]
                .as_array()
                .map(|a| a.len()),
            Some(0),
            "tag:headmaster must always be declared with an empty owners list"
        );
    }

    #[tokio::test]
    async fn sync_policy_preserves_scim_groups_when_scim_enabled() {
        let server = FakeHeadscaleServer::default();
        *server.policy.lock().unwrap() =
            r#"{"acls":[{"action":"accept"}],"groups":{"group:eng":["alice@example.com"]}}"#
                .to_string();
        let policy_store = Arc::clone(&server.policy);
        let channel = spawn_fake_channel(server).await;

        let ctx = Context {
            client: FaultService::client(api_key_secret),
            headscale: Arc::new(FakeConnector(channel)),
            ..test_ctx(FaultService::client(api_key_secret))
        };

        let new_policy = inline_policy(r#"{"acls":[{"action":"accept","src":["group:eng"]}]}"#);

        sync_policy(
            &ctx,
            "default",
            "test-instance",
            new_policy.as_ref(),
            true,
            &[],
        )
        .await
        .expect("sync_policy must succeed");

        let live: serde_json::Value = serde_json::from_str(&policy_store.lock().unwrap()).unwrap();
        assert_eq!(
            live["acls"][0]["src"][0], "group:eng",
            "inline ACL change must be applied"
        );
        assert_eq!(
            live["groups"]["group:eng"][0], "alice@example.com",
            "SCIM-managed groups must be preserved when SCIM is enabled"
        );
    }

    #[tokio::test]
    async fn sync_policy_no_op_when_inline_matches_live_minus_groups() {
        let initial = r#"{"acls":[{"action":"accept"}],"groups":{"group:eng":["alice@example.com"]},"tagOwners":{"tag:headmaster":[]}}"#;
        let server = FakeHeadscaleServer::default();
        *server.policy.lock().unwrap() = initial.to_string();
        let policy_store = Arc::clone(&server.policy);
        let channel = spawn_fake_channel(server).await;

        let ctx = Context {
            client: FaultService::client(api_key_secret),
            headscale: Arc::new(FakeConnector(channel)),
            ..test_ctx(FaultService::client(api_key_secret))
        };

        let policy = inline_policy(r#"{"acls":[{"action":"accept"}]}"#);

        sync_policy(&ctx, "default", "test-instance", policy.as_ref(), true, &[])
            .await
            .expect("sync_policy must succeed");

        assert_eq!(
            *policy_store.lock().unwrap(),
            initial,
            "SetPolicy must not be called when only the SCIM-managed groups differ"
        );
    }

    #[tokio::test]
    async fn sync_policy_clears_groups_when_scim_disabled() {
        let server = FakeHeadscaleServer::default();
        *server.policy.lock().unwrap() =
            r#"{"acls":[{"action":"accept"}],"groups":{"group:eng":["alice@example.com"]}}"#
                .to_string();
        let policy_store = Arc::clone(&server.policy);
        let channel = spawn_fake_channel(server).await;

        let ctx = Context {
            client: FaultService::client(api_key_secret),
            headscale: Arc::new(FakeConnector(channel)),
            ..test_ctx(FaultService::client(api_key_secret))
        };

        let new_policy = inline_policy(r#"{"acls":[{"action":"accept","src":["*"]}]}"#);

        sync_policy(
            &ctx,
            "default",
            "test-instance",
            new_policy.as_ref(),
            false,
            &[],
        )
        .await
        .expect("sync_policy must succeed");

        let live: serde_json::Value = serde_json::from_str(&policy_store.lock().unwrap()).unwrap();
        assert_eq!(live["acls"][0]["src"][0], "*");
        assert!(
            live["groups"].is_null(),
            "groups must not be preserved when SCIM is disabled"
        );
    }

    #[tokio::test]
    async fn sync_policy_none_clears_headscale_policy_when_non_empty() {
        let server = FakeHeadscaleServer::default();
        *server.policy.lock().unwrap() = r#"{"acls":[{"action":"accept"}]}"#.to_string();
        let policy_store = Arc::clone(&server.policy);
        let channel = spawn_fake_channel(server).await;

        let ctx = Context {
            client: FaultService::client(api_key_secret),
            headscale: Arc::new(FakeConnector(channel)),
            ..test_ctx(FaultService::client(api_key_secret))
        };

        sync_policy(&ctx, "default", "test-instance", None, false, &[])
            .await
            .expect("sync_policy must succeed with None policy");

        assert_eq!(
            *policy_store.lock().unwrap(),
            "",
            "SetPolicy(\"\") must be called to restore allow-all when current policy is non-empty"
        );
    }

    #[tokio::test]
    async fn sync_policy_none_is_idempotent_when_policy_already_empty() {
        let server = FakeHeadscaleServer::with_set_policy_fails();
        let channel = spawn_fake_channel(server).await;

        let ctx = Context {
            client: FaultService::client(api_key_secret),
            headscale: Arc::new(FakeConnector(channel)),
            ..test_ctx(FaultService::client(api_key_secret))
        };

        sync_policy(&ctx, "default", "test-instance", None, false, &[])
            .await
            .expect("sync_policy must not call SetPolicy when current policy is already empty");
    }

    // ── sync_policy with contributing ingresses ───────────────────────────────

    fn headmaster_ingress_with_access(
        ns: &str,
        name: &str,
        headscale_ref: &str,
        user: &str,
        access: serde_json::Value,
    ) -> Ingress {
        use std::collections::BTreeMap;
        let config = serde_json::json!({
            "headscale-ref": headscale_ref,
            "user": user,
            "access": access,
        });
        Ingress {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(ns.to_string()),
                annotations: Some(BTreeMap::from([(
                    ANNOTATION_CONFIG.to_string(),
                    config.to_string(),
                )])),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn sync_policy_writes_grants_from_contributing_ingress() {
        let server = FakeHeadscaleServer::default();
        *server.policy.lock().unwrap() =
            r#"{"groups":{"group:eng":["alice@example.com"]},"acls":[]}"#.to_string();
        let policy_store = Arc::clone(&server.policy);
        let channel = spawn_fake_channel(server).await;

        let ctx = crate::context::Context {
            client: FaultService::client(api_key_secret),
            headscale: Arc::new(FakeConnector(channel)),
            ..test_ctx(FaultService::client(api_key_secret))
        };

        let ingress = headmaster_ingress_with_access(
            "default",
            "my-app",
            "test-instance",
            "alice",
            serde_json::json!([{
                "from": ["group:eng"],
                "capabilities": {"myapp/cap/admin": [{"role": "admin"}]}
            }]),
        );

        sync_policy(
            &ctx,
            "default",
            "test-instance",
            inline_policy(r#"{"acls":[],"groups":{"group:eng":["alice@example.com"]}}"#).as_ref(),
            false,
            &[ingress],
        )
        .await
        .expect("sync_policy must succeed");

        let expected_tag = ingress_auto_tag("default", "my-app");
        let stored: serde_json::Value =
            serde_json::from_str(&policy_store.lock().unwrap()).unwrap();
        assert_eq!(
            stored["tagOwners"][&expected_tag][0], "tag:headmaster",
            "auto-tag must be owned by tag:headmaster"
        );
        let grants = stored["grants"].as_array().expect("grants must be present");
        assert_eq!(grants.len(), 1, "exactly one grant must be generated");
        assert_eq!(grants[0]["src"][0], "group:eng");
        assert_eq!(grants[0]["dst"][0], expected_tag);
        assert_eq!(
            grants[0]["app"]["myapp/cap/admin"][0]["role"], "admin",
            "capability args must be preserved in the grant"
        );
    }

    #[tokio::test]
    async fn sync_policy_skips_grant_when_group_not_in_policy() {
        let server = FakeHeadscaleServer::default();
        *server.policy.lock().unwrap() = r#"{"acls":[]}"#.to_string();
        let policy_store = Arc::clone(&server.policy);
        let channel = spawn_fake_channel(server).await;

        let ctx = crate::context::Context {
            client: FaultService::client(api_key_secret),
            headscale: Arc::new(FakeConnector(channel)),
            ..test_ctx(FaultService::client(api_key_secret))
        };

        let ingress = headmaster_ingress_with_access(
            "default",
            "my-app",
            "test-instance",
            "alice",
            serde_json::json!([{"from": ["group:missing"]}]),
        );

        sync_policy(
            &ctx,
            "default",
            "test-instance",
            inline_policy(r#"{"acls":[]}"#).as_ref(),
            false,
            &[ingress],
        )
        .await
        .expect("sync_policy must succeed even when group is absent");

        let stored: serde_json::Value =
            serde_json::from_str(&policy_store.lock().unwrap()).unwrap();
        assert!(
            stored["grants"].is_null(),
            "no grant must be written when the referenced group is not in the desired policy"
        );
    }

    #[tokio::test]
    async fn sync_policy_writes_grant_when_group_added_simultaneously() {
        let server = FakeHeadscaleServer::default();
        *server.policy.lock().unwrap() = r#"{"acls":[]}"#.to_string();
        let policy_store = Arc::clone(&server.policy);
        let channel = spawn_fake_channel(server).await;

        let ctx = crate::context::Context {
            client: FaultService::client(api_key_secret),
            headscale: Arc::new(FakeConnector(channel)),
            ..test_ctx(FaultService::client(api_key_secret))
        };

        let ingress = headmaster_ingress_with_access(
            "default",
            "my-app",
            "test-instance",
            "alice",
            serde_json::json!([{"from": ["group:eng"]}]),
        );

        sync_policy(
            &ctx,
            "default",
            "test-instance",
            inline_policy(r#"{"acls":[],"groups":{"group:eng":["alice@example.com"]}}"#).as_ref(),
            false,
            &[ingress],
        )
        .await
        .expect("sync_policy must succeed");

        let stored: serde_json::Value =
            serde_json::from_str(&policy_store.lock().unwrap()).unwrap();
        let grants = stored["grants"]
            .as_array()
            .expect("grant must be written in the same reconcile as the group");
        assert_eq!(grants[0]["src"][0], "group:eng");
    }

    #[tokio::test]
    async fn sync_policy_removes_stale_grants_when_no_ingresses_contribute() {
        let server = FakeHeadscaleServer::default();
        *server.policy.lock().unwrap() = r#"{
            "grants": [{"src": ["group:eng"], "dst": ["tag:hm-default-old-app"], "ip": ["*:*"]}]
        }"#
        .to_string();
        let policy_store = Arc::clone(&server.policy);
        let channel = spawn_fake_channel(server).await;

        let ctx = crate::context::Context {
            client: FaultService::client(api_key_secret),
            headscale: Arc::new(FakeConnector(channel)),
            ..test_ctx(FaultService::client(api_key_secret))
        };

        sync_policy(
            &ctx,
            "default",
            "test-instance",
            inline_policy(r#"{"acls":[]}"#).as_ref(),
            false,
            &[],
        )
        .await
        .expect("sync_policy must succeed");

        let stored: serde_json::Value =
            serde_json::from_str(&policy_store.lock().unwrap()).unwrap();
        assert!(
            stored["grants"].is_null(),
            "stale hm- grant must be removed when no ingresses contribute"
        );
    }
}
