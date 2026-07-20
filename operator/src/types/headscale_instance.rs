use std::collections::BTreeMap;

use k8s_openapi::api::core::v1::ResourceRequirements;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::{CustomResource, KubeSchema};
use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::condition::ResourceStatus;

/// A headscale control-plane instance managed by headmaster.
///
/// Creating a `HeadscaleInstance` causes the operator to deploy a headscale StatefulSet,
/// a Service, and a ConfigMap containing the rendered headscale configuration. Child
/// resources are owned by the instance and are garbage-collected when it is deleted.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "headmaster.potatonode.github.io",
    version = "v1alpha1",
    kind = "HeadscaleInstance",
    namespaced,
    status = "HeadscaleInstanceStatus",
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type==\"Ready\")].status"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct HeadscaleInstanceSpec {
    /// Publicly-reachable URL of this headscale server, used for Magic DNS and DERP
    /// configuration (e.g. `https://headscale.example.com`).
    #[schemars(length(min = 1))]
    pub server_url: String,
    /// Base domain for Magic DNS node hostnames (e.g. `ts.example.com`).
    ///
    /// Nodes will be reachable at `<hostname>.<dns_base_domain>` via the tailnet.
    #[schemars(length(min = 1))]
    pub dns_base_domain: String,
    /// Connection details for a headscale server running *outside* the
    /// cluster. When set, the operator provisions no headscale resources —
    /// it only verifies reachability and lets Ingress proxies register
    /// against the external server (via `serverUrl`). Mutually exclusive
    /// with `policy`, `scim`, `extraConfig`, and `resources`: the external
    /// server's configuration and ACL policy belong to whoever operates it.
    /// `storage` is ignored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external: Option<ExternalSpec>,
    /// Persistent storage for the headscale SQLite database.
    /// Ignored when `external` is set.
    #[serde(default)]
    pub storage: StorageSpec,
    /// Headscale access-control policy applied to this instance.
    /// When omitted, headscale allows all traffic by default.
    pub policy: Option<HeadscaleInstancePolicy>,
    /// SCIM 2.0 server configuration. When set, the operator deploys a SCIM sidecar
    /// and validates that `spec.policy.inline` contains no `groups` key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scim: Option<ScimSpec>,
    /// Namespaces from which `headmaster` Ingresses may reference this instance.
    /// `["*"]` (the default) allows Ingresses from any namespace; `[]` denies all;
    /// a specific list restricts to those namespaces only.
    #[serde(default = "default_watched_namespaces")]
    pub watched_namespaces: Vec<String>,
    /// Arbitrary extra configuration merged into the headscale config file.
    ///
    /// The admission webhook rejects entries that would collide with operator-managed keys:
    /// top-level `server_url`, `listen_addr`, `grpc_listen_addr`, `grpc_allow_insecure`,
    /// `metrics_listen_addr`, `unix_socket`, `unix_socket_permission`, `noise`, `database`,
    /// `policy`, and the `dns.magic_dns` / `dns.base_domain` subkeys. Other `dns.*` keys
    /// (e.g. `nameservers`, `split_dns`, `extra_records`) are deep-merged into the operator
    /// defaults. Omit this field to use defaults only.
    #[serde(default)]
    #[schemars(schema_with = "preserve_unknown_fields_schema")]
    pub extra_config: BTreeMap<String, Value>,
    /// Resource requests and limits for the headscale container.
    /// Defaults to `50m`/`64Mi` requests and `500m`/`512Mi` limits when omitted.
    /// The entire block is replaced when provided — partial overrides (e.g. only
    /// `requests` without `limits`) leave the unset half empty, not defaulted.
    pub resources: Option<ResourceRequirements>,
    /// Extra labels applied to all child resources (ConfigMap, Service, StatefulSet).
    /// Operator-managed labels (`app.kubernetes.io/name`, `instance`, `managed-by`) always win.
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

impl Default for HeadscaleInstanceSpec {
    fn default() -> Self {
        Self {
            server_url: String::new(),
            dns_base_domain: String::new(),
            external: None,
            storage: StorageSpec::default(),
            policy: None,
            scim: None,
            watched_namespaces: default_watched_namespaces(),
            extra_config: BTreeMap::new(),
            resources: None,
            labels: BTreeMap::new(),
        }
    }
}

/// Connection details for an externally-managed headscale server.
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExternalSpec {
    /// gRPC endpoint of the external headscale server, as a URI
    /// (e.g. `http://100.64.0.1:50443` for h2c over a private network).
    #[schemars(length(min = 1))]
    pub grpc_endpoint: String,
    /// Name of an existing Secret in the operator namespace whose
    /// `HEADSCALE_API_KEY` key holds an API key for the external server.
    /// The operator never creates or rotates this Secret.
    #[schemars(length(min = 1))]
    pub api_key_secret_ref: String,
}

/// SCIM 2.0 server configuration for this instance.
#[derive(Serialize, Deserialize, Clone, Debug, KubeSchema)]
#[serde(rename_all = "camelCase")]
#[x_kube(validation = Rule::new("!has(self.policyUserKey) || self.policyUserKey != 'external_id' || has(self.oidcIssuer)").message("oidcIssuer is required when policyUserKey is 'external_id'"))]
pub struct ScimSpec {
    /// Controls which identifier is written into headscale policy group entries
    /// and used to locate a user's headscale nodes for session management.
    /// Values: `"email"` (default), `"username"`, `"external_id"`.
    /// Use `"external_id"` with Pocket ID or Authentik for the most stable
    /// identifier (maps to the OIDC `sub` claim / headscale `ProviderIdentifier`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "policy_user_key_schema")]
    pub policy_user_key: Option<String>,

    /// OIDC issuer URL (e.g. `"https://pocket-id.example.com"`).
    /// Required when `policyUserKey` is `"external_id"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc_issuer: Option<String>,

    /// Persistent storage for the external-ID mapping file.
    #[serde(default)]
    pub storage: StorageSpec,

    /// When true, expire all of a user's headscale nodes when the identifier
    /// used by `policyUserKey` changes (e.g. email change in `email` mode,
    /// username rename in `username` mode). Forces immediate OIDC re-authentication.
    /// Not needed for `external_id` mode — the ProviderIdentifier never changes.
    /// Default: false.
    #[serde(default)]
    pub expire_nodes_on_change: bool,
}

/// Persistent-volume claim template for the headscale SQLite database.
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct StorageSpec {
    /// PVC storage request (e.g. `1Gi`).
    #[serde(default = "default_storage_size")]
    #[schemars(length(min = 1))]
    pub size: String,
    /// StorageClass to use. Omit to use the cluster default.
    #[serde(default)]
    #[schemars(length(min = 1))]
    pub storage_class: Option<String>,
}

/// Access-control policy for headscale.
///
/// Currently only inline HuJSON/JSON policies are supported. Additional variants
/// may be added in future versions.
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase", untagged)]
pub enum HeadscaleInstancePolicy {
    /// A raw HuJSON/JSON policy string applied directly to headscale.
    Inline {
        /// The policy document as a HuJSON or JSON string.
        /// Omit the entire `policy` field to use headscale's default allow-all mode.
        inline: String,
    },
}

/// Observed state of a `HeadscaleInstance`.
#[derive(Serialize, Deserialize, Clone, Debug, Default, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HeadscaleInstanceStatus {
    /// Generation of the spec this status was computed from.
    #[serde(default)]
    pub observed_generation: i64,
    /// Current conditions for this instance.
    #[serde(default)]
    pub conditions: Vec<Condition>,
}

impl ResourceStatus for HeadscaleInstanceStatus {
    fn conditions(&self) -> &[Condition] {
        &self.conditions
    }

    fn conditions_mut(&mut self) -> &mut Vec<Condition> {
        &mut self.conditions
    }

    fn set_observed_generation(&mut self, generation: i64) {
        self.observed_generation = generation;
    }
}

fn default_storage_size() -> String {
    "1Gi".to_string()
}

fn default_watched_namespaces() -> Vec<String> {
    vec!["*".to_string()]
}

impl HeadscaleInstanceSpec {
    pub fn namespace_allowed(&self, ns: &str) -> bool {
        self.watched_namespaces.iter().any(|w| w == "*" || w == ns)
    }
}

impl Default for StorageSpec {
    fn default() -> Self {
        Self {
            size: default_storage_size(),
            storage_class: None,
        }
    }
}

/// Schema function for `extra_config`: emits `x-kubernetes-preserve-unknown-fields: true`
/// so the API server stores arbitrary YAML without validating it.
fn preserve_unknown_fields_schema(_generator: &mut SchemaGenerator) -> Schema {
    serde_json::from_value(serde_json::json!({
        "x-kubernetes-preserve-unknown-fields": true
    }))
    .unwrap()
}

/// Schema function for `policyUserKey`: constrains to the three valid values so
/// typos are rejected at the API server before the SCIM container ever starts.
fn policy_user_key_schema(_generator: &mut SchemaGenerator) -> Schema {
    serde_json::from_value(serde_json::json!({
        "type": "string",
        "enum": ["email", "username", "external_id"],
        "nullable": true,
        "description": "Controls which identifier is written into headscale policy group entries. Values: \"email\" (default), \"username\", \"external_id\"."
    }))
    .unwrap()
}

#[cfg(test)]
mod tests {
    use indoc::indoc;

    use super::*;

    // ── tests ─────────────────────────────────────────────────────────────────

    #[test]
    fn spec_round_trips() {
        let spec: HeadscaleInstanceSpec = serde_saphyr::from_str(indoc! {r#"
            serverUrl: https://headscale.example.com
            dnsBaseDomain: ts.example.com
            storage:
              size: 5Gi
              storageClass: fast
            policy:
              inline: '{"acls":[]}'
            labels:
              env: prod
            extraConfig:
              log:
                level: debug
            resources:
              requests:
                cpu: 100m
                memory: 128Mi
        "#})
        .unwrap();
        assert_eq!(
            serde_json::to_value(&spec).unwrap(),
            serde_json::json!({
                "serverUrl": "https://headscale.example.com",
                "dnsBaseDomain": "ts.example.com",
                "storage": { "size": "5Gi", "storageClass": "fast" },
                "policy": { "inline": r#"{"acls":[]}"# },
                "labels": { "env": "prod" },
                "extraConfig": { "log": { "level": "debug" } },
                "resources": { "requests": { "cpu": "100m", "memory": "128Mi" } },
                "watchedNamespaces": ["*"]
            })
        );
    }

    #[test]
    fn external_omitted_is_none() {
        let spec: HeadscaleInstanceSpec = serde_saphyr::from_str(indoc! {"
            serverUrl: https://headscale.example.com
            dnsBaseDomain: ts.example.com
            storage:
              size: 1Gi
        "})
        .unwrap();
        assert!(spec.external.is_none());
    }

    #[test]
    fn external_round_trips_and_storage_may_be_omitted() {
        let spec: HeadscaleInstanceSpec = serde_saphyr::from_str(indoc! {"
            serverUrl: https://headscale.example.com
            dnsBaseDomain: ts.example.com
            external:
              grpcEndpoint: http://100.64.0.1:50443
              apiKeySecretRef: headscale-api-key
        "})
        .unwrap();
        let ext = spec.external.as_ref().expect("external must be present");
        assert_eq!(ext.grpc_endpoint, "http://100.64.0.1:50443");
        assert_eq!(ext.api_key_secret_ref, "headscale-api-key");
        assert_eq!(
            spec.storage.size, "1Gi",
            "storage must default when omitted (external instances don't need it)"
        );
    }

    #[test]
    fn extra_config_omitted_is_empty() {
        let spec: HeadscaleInstanceSpec = serde_saphyr::from_str(indoc! {"
            serverUrl: https://headscale.example.com
            dnsBaseDomain: ts.example.com
            storage:
              size: 1Gi
        "})
        .unwrap();
        assert!(spec.extra_config.is_empty());
    }

    #[test]
    fn policy_omitted_is_none() {
        let spec: HeadscaleInstanceSpec = serde_saphyr::from_str(indoc! {"
            serverUrl: https://headscale.example.com
            dnsBaseDomain: ts.example.com
            storage:
              size: 1Gi
        "})
        .unwrap();
        assert!(spec.policy.is_none());
    }

    #[test]
    fn watched_namespaces_defaults_to_star() {
        let spec: HeadscaleInstanceSpec = serde_saphyr::from_str(indoc! {"
            serverUrl: https://headscale.example.com
            dnsBaseDomain: ts.example.com
            storage:
              size: 1Gi
        "})
        .unwrap();
        assert_eq!(spec.watched_namespaces, vec!["*"]);
        assert!(
            spec.namespace_allowed("any-namespace"),
            "default must allow all namespaces"
        );
    }

    #[test]
    fn watched_namespaces_empty_denies_all() {
        let spec: HeadscaleInstanceSpec = serde_saphyr::from_str(indoc! {"
            serverUrl: https://headscale.example.com
            dnsBaseDomain: ts.example.com
            storage:
              size: 1Gi
            watchedNamespaces: []
        "})
        .unwrap();
        assert!(
            !spec.namespace_allowed("any-namespace"),
            "empty list must deny all namespaces"
        );
    }

    #[test]
    fn watched_namespaces_specific_list_filters() {
        let spec: HeadscaleInstanceSpec = serde_saphyr::from_str(indoc! {"
            serverUrl: https://headscale.example.com
            dnsBaseDomain: ts.example.com
            storage:
              size: 1Gi
            watchedNamespaces: [prod, staging]
        "})
        .unwrap();
        assert!(spec.namespace_allowed("prod"), "prod must be allowed");
        assert!(spec.namespace_allowed("staging"), "staging must be allowed");
        assert!(
            !spec.namespace_allowed("dev"),
            "dev must be denied when not in list"
        );
    }

    #[test]
    fn resources_round_trips() {
        let spec: HeadscaleInstanceSpec = serde_saphyr::from_str(indoc! {r#"
            serverUrl: https://headscale.example.com
            dnsBaseDomain: ts.example.com
            storage:
              size: 1Gi
            resources:
              requests:
                cpu: 100m
                memory: 128Mi
              limits:
                cpu: "1"
                memory: 1Gi
        "#})
        .unwrap();
        let res = spec.resources.as_ref().expect("resources must be present");
        let req = res.requests.as_ref().unwrap();
        assert_eq!(req["cpu"].0, "100m");
        assert_eq!(req["memory"].0, "128Mi");
        let lim = res.limits.as_ref().unwrap();
        assert_eq!(lim["memory"].0, "1Gi");
    }
}
