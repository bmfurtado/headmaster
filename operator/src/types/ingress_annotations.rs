//! Parsed representation of the `headmaster.potatonode.github.io/config` annotation.
//! Carried by `Ingress` objects (HTTP apps behind a proxy) and by ExternalName
//! `Service` objects (TCP forwards to an external host); the schema is shared,
//! so the parser is generic over the annotated resource.

use std::collections::BTreeMap;

use kube::ResourceExt;
use serde::Deserialize;

pub const ANNOTATION_CONFIG: &str = "headmaster.potatonode.github.io/config";

const DEFAULT_AUTH_KEY_EXPIRY_SECS: u64 = 600;

fn default_auth_key_expiry_secs() -> u64 {
    DEFAULT_AUTH_KEY_EXPIRY_SECS
}

#[derive(Debug, thiserror::Error)]
pub enum AnnotationError {
    #[error("required annotation '{0}' is missing")]
    Missing(&'static str),
    #[error("invalid annotation '{0}': {1}")]
    Invalid(&'static str, String),
    #[error("invalid annotations: {0}")]
    InvalidAnnotations(&'static str),
}

/// One entry in the `access` list of the headmaster ingress annotation.
///
/// Each grant specifies a set of source principals and an optional map of
/// app capabilities. When `capabilities` is absent, the grant allows plain
/// IP connectivity (`ip: ["*:*"]`); when present, the grant forwards the
/// listed capabilities to the upstream app via the `Tailscale-App-Capabilities`
/// HTTP header.
#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct IngressAccessGrant {
    /// Source principals: `group:*`, `tag:*`, `autogroup:*`, `*`, or a user email.
    pub from: Vec<String>,
    /// Capability name → JSON argument list. If `None`, emits `ip: ["*:*"]`.
    #[serde(default)]
    pub capabilities: Option<BTreeMap<String, Vec<serde_json::Value>>>,
}

/// How an exposed Service's proxy forwards traffic onto the tailnet node.
#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ProxyMode {
    /// Userspace tailscaled (netstack): traffic is forwarded via the proxy's
    /// serve config. No special privileges, works everywhere. The default.
    #[default]
    Tsnet,
    /// Kernel forwarding: real tailscaled with a TUN device, DNAT-ing tailnet
    /// traffic to the Service's ClusterIP. Much higher throughput; the proxy
    /// pod needs access to /dev/net/tun (see the operator's tunDevice config).
    /// Only meaningful on exposed ClusterIP Services.
    Tun,
}

/// One entry in the `consumers` list of an egress Service annotation: pods
/// allowed to reach the egress proxy. Enforced as an operator-generated
/// NetworkPolicy on the proxy pods.
#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct EgressConsumer {
    /// Namespace the consumer pods live in.
    pub namespace: String,
    /// Pod label selector within that namespace. Absent or empty means every
    /// pod in the namespace.
    #[serde(default)]
    pub pods: Option<BTreeMap<String, String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct IngressAnnotations {
    pub headscale_ref: String,
    /// Operator deployment namespace this Ingress targets. `None` means use the
    /// default deployment (the one with `claim_default = true`).
    #[serde(default)]
    pub headscale_namespace: Option<String>,
    pub user: Option<String>,
    #[serde(default)]
    pub managed_key_tags: Vec<String>,
    #[serde(default)]
    pub hostname: String,
    #[serde(default = "default_auth_key_expiry_secs")]
    pub auth_key_expiry_secs: u64,
    #[serde(default)]
    pub auth_key_reusable: bool,
    /// Run the proxy pod with `hostNetwork: true`. tailscaled then binds the
    /// node's own network stack on an auto-selected UDP port and discovers
    /// its endpoints natively — the node's IPv6 addresses included — instead
    /// of advertising the WireGuard NodePort. Trades the pod's network
    /// isolation for direct peer connections from off-LAN devices.
    /// Ignored on ExternalName Services (egress proxies).
    #[serde(default)]
    pub host_network: bool,
    /// Tailnet FQDN an ExternalName Service egresses to (e.g.
    /// `qbittorrent.ts.example.com`). Required on ExternalName Services,
    /// rejected on Ingresses. The operator owns `spec.externalName` on the
    /// annotated Service and points it at the egress proxy; this field is the
    /// actual tailnet destination.
    #[serde(default)]
    pub tailnet_fqdn: Option<String>,
    /// Egress only: pods allowed to reach the egress proxy, enforced as an
    /// operator-generated NetworkPolicy. Absent means no policy — any pod in
    /// the cluster may use the egress (the pre-feature behavior). Rejected
    /// on Ingresses.
    #[serde(default)]
    pub consumers: Vec<EgressConsumer>,
    #[serde(default)]
    pub access: Vec<IngressAccessGrant>,
    /// Exposed ClusterIP Services only: how the proxy forwards traffic.
    /// `tsnet` (default) runs a userspace proxy; `tun` runs a kernel-mode
    /// tailscaled with a TUN device for high-bandwidth workloads. Ignored on
    /// Ingresses and egress (ExternalName) Services.
    #[serde(default)]
    pub mode: ProxyMode,
}

impl IngressAnnotations {
    pub fn parse<K: ResourceExt>(obj: &K) -> Result<Self, AnnotationError> {
        let json = obj
            .annotations()
            .get(ANNOTATION_CONFIG)
            .ok_or(AnnotationError::Missing(ANNOTATION_CONFIG))?;
        let mut parsed: Self = serde_json::from_str(json)
            .map_err(|e| AnnotationError::Invalid(ANNOTATION_CONFIG, e.to_string()))?;
        if parsed.user.is_none() && parsed.managed_key_tags.is_empty() {
            return Err(AnnotationError::InvalidAnnotations(
                "at least one of 'user' or 'managed-key-tags' must be set",
            ));
        }
        if parsed.hostname.is_empty() {
            parsed.hostname = obj.name_any();
        }
        Ok(parsed)
    }

    /// Cheaply extracts `headscale-ref` without full validation. Used in
    /// contexts where `parse()` hasn't run (watch triggers, pre-finalizer gate).
    pub fn headscale_ref<K: ResourceExt>(obj: &K) -> Option<String> {
        let json = obj.annotations().get(ANNOTATION_CONFIG)?;
        serde_json::from_str::<serde_json::Value>(json)
            .ok()
            .and_then(|v| v.get("headscale-ref")?.as_str().map(String::from))
    }

    /// Cheaply extracts `headscale-namespace` without full validation. Used in
    /// the sharding gate before `parse()` runs.
    pub fn headscale_namespace<K: ResourceExt>(obj: &K) -> Option<String> {
        let json = obj.annotations().get(ANNOTATION_CONFIG)?;
        serde_json::from_str::<serde_json::Value>(json)
            .ok()
            .and_then(|v| v.get("headscale-namespace")?.as_str().map(String::from))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::networking::v1::Ingress;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    fn make_test_ingress(user: Option<&str>, tags: Option<&[&str]>) -> Ingress {
        let mut config = serde_json::json!({ "headscale-ref": "headscale" });
        if let Some(u) = user {
            config["user"] = serde_json::Value::String(u.to_string());
        }
        if let Some(t) = tags {
            config["managed-key-tags"] = serde_json::json!(t);
        }
        Ingress {
            metadata: ObjectMeta {
                name: Some("test".to_string()),
                namespace: Some("default".to_string()),
                annotations: Some(BTreeMap::from([(
                    ANNOTATION_CONFIG.to_string(),
                    config.to_string(),
                )])),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn ingress_with_config(extra: serde_json::Value) -> Ingress {
        let mut config = serde_json::json!({ "headscale-ref": "main", "user": "alice" });
        if let serde_json::Value::Object(map) = extra {
            for (k, v) in map {
                config[k] = v;
            }
        }
        Ingress {
            metadata: ObjectMeta {
                name: Some("test".to_string()),
                namespace: Some("default".to_string()),
                annotations: Some(BTreeMap::from([(
                    ANNOTATION_CONFIG.to_string(),
                    config.to_string(),
                )])),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn annotation_parse_rejects_neither_user_nor_tags() {
        let ing = make_test_ingress(None, None);
        assert!(
            matches!(
                IngressAnnotations::parse(&ing),
                Err(AnnotationError::InvalidAnnotations(_))
            ),
            "parse must fail when neither user nor managed-key-tags is set"
        );
    }

    #[test]
    fn annotation_parse_accepts_tags_without_user() {
        let ing = make_test_ingress(None, Some(&["tag:server"]));
        let parsed = IngressAnnotations::parse(&ing).expect("tags-only must be valid");
        assert!(parsed.user.is_none());
        assert_eq!(parsed.managed_key_tags, vec!["tag:server"]);
    }

    #[test]
    fn annotation_parse_accepts_user_without_tags() {
        let ing = make_test_ingress(Some("alice"), None);
        let parsed = IngressAnnotations::parse(&ing).expect("user-only must be valid");
        assert_eq!(parsed.user.as_deref(), Some("alice"));
        assert!(parsed.managed_key_tags.is_empty());
    }

    #[test]
    fn annotation_parse_accepts_user_and_tags() {
        let ing = make_test_ingress(Some("alice"), Some(&["tag:server"]));
        let parsed = IngressAnnotations::parse(&ing).expect("user+tags must be valid");
        assert_eq!(parsed.user.as_deref(), Some("alice"));
        assert_eq!(parsed.managed_key_tags, vec!["tag:server"]);
    }

    #[test]
    fn annotation_parse_invalid_expiry_is_rejected() {
        let ingress =
            ingress_with_config(serde_json::json!({"auth-key-expiry-secs": "ten-minutes"}));
        assert!(
            matches!(
                IngressAnnotations::parse(&ingress),
                Err(AnnotationError::Invalid(_, _))
            ),
            "non-numeric auth-key-expiry-secs must be rejected"
        );
    }

    #[test]
    fn annotation_parse_valid_expiry_is_respected() {
        let ingress = ingress_with_config(serde_json::json!({"auth-key-expiry-secs": 3600}));
        let parsed = IngressAnnotations::parse(&ingress).expect("must parse with valid expiry");
        assert_eq!(parsed.auth_key_expiry_secs, 3600);
    }

    #[test]
    fn annotation_parse_defaults_expiry_when_absent() {
        let ingress = ingress_with_config(serde_json::json!({}));
        let parsed = IngressAnnotations::parse(&ingress).expect("must parse without expiry");
        assert_eq!(parsed.auth_key_expiry_secs, DEFAULT_AUTH_KEY_EXPIRY_SECS);
    }

    #[test]
    fn annotation_parse_host_network_defaults_false_when_absent() {
        let ingress = ingress_with_config(serde_json::json!({}));
        let parsed = IngressAnnotations::parse(&ingress).expect("must parse without host-network");
        assert!(
            !parsed.host_network,
            "host-network must default to false when the field is omitted"
        );
    }

    #[test]
    fn annotation_parse_host_network_true_is_respected() {
        let ingress = ingress_with_config(serde_json::json!({"host-network": true}));
        let parsed = IngressAnnotations::parse(&ingress).expect("must parse with host-network");
        assert!(parsed.host_network);
    }

    #[test]
    fn annotation_parse_consumers_default_empty() {
        let ingress = ingress_with_config(serde_json::json!({}));
        let parsed = IngressAnnotations::parse(&ingress).expect("must parse");
        assert!(parsed.consumers.is_empty());
    }

    #[test]
    fn annotation_parse_consumers_entries() {
        let ingress = ingress_with_config(serde_json::json!({
            "consumers": [
                {"namespace": "media", "pods": {"app": "sonarr"}},
                {"namespace": "media"}
            ]
        }));
        let parsed = IngressAnnotations::parse(&ingress).expect("must parse");
        assert_eq!(parsed.consumers.len(), 2);
        assert_eq!(parsed.consumers[0].namespace, "media");
        assert_eq!(
            parsed.consumers[0]
                .pods
                .as_ref()
                .unwrap()
                .get("app")
                .unwrap(),
            "sonarr"
        );
        assert!(parsed.consumers[1].pods.is_none(), "namespace-wide entry");
    }

    #[test]
    fn annotation_parse_consumer_unknown_field_rejected() {
        let ingress = ingress_with_config(serde_json::json!({
            "consumers": [{"namespace": "media", "unknown": true}]
        }));
        assert!(matches!(
            IngressAnnotations::parse(&ingress),
            Err(AnnotationError::Invalid(_, _))
        ));
    }

    #[test]
    fn annotation_parse_mode_defaults_to_tsnet_when_absent() {
        let ingress = ingress_with_config(serde_json::json!({}));
        let parsed = IngressAnnotations::parse(&ingress).expect("must parse without mode");
        assert_eq!(
            parsed.mode,
            ProxyMode::Tsnet,
            "mode must default to tsnet when the field is omitted"
        );
    }

    #[test]
    fn annotation_parse_mode_tun_is_respected() {
        let ingress = ingress_with_config(serde_json::json!({"mode": "tun"}));
        let parsed = IngressAnnotations::parse(&ingress).expect("must parse with mode tun");
        assert_eq!(parsed.mode, ProxyMode::Tun);
    }

    #[test]
    fn annotation_parse_mode_unknown_value_rejected() {
        let ingress = ingress_with_config(serde_json::json!({"mode": "wireguard"}));
        assert!(
            matches!(
                IngressAnnotations::parse(&ingress),
                Err(AnnotationError::Invalid(_, _))
            ),
            "unknown mode value must be rejected"
        );
    }

    #[test]
    fn headscale_ref_extracts_from_config() {
        let ing = make_test_ingress(Some("alice"), None);
        assert_eq!(
            IngressAnnotations::headscale_ref(&ing).as_deref(),
            Some("headscale")
        );
    }

    #[test]
    fn headscale_namespace_extracts_from_config() {
        let ingress = ingress_with_config(serde_json::json!({"headscale-namespace": "infra-prod"}));
        assert_eq!(
            IngressAnnotations::headscale_namespace(&ingress).as_deref(),
            Some("infra-prod")
        );
    }

    #[test]
    fn headscale_namespace_absent_returns_none() {
        let ing = make_test_ingress(Some("alice"), None);
        assert!(IngressAnnotations::headscale_namespace(&ing).is_none());
    }

    #[test]
    fn annotation_parse_access_empty_by_default() {
        let ing = make_test_ingress(Some("alice"), None);
        let parsed = IngressAnnotations::parse(&ing).expect("must parse");
        assert!(parsed.access.is_empty(), "access must default to empty");
    }

    #[test]
    fn annotation_parse_access_plain_grant() {
        let ingress = ingress_with_config(serde_json::json!({
            "access": [{"from": ["group:eng"]}]
        }));
        let parsed = IngressAnnotations::parse(&ingress).expect("must parse");
        assert_eq!(parsed.access.len(), 1);
        assert_eq!(parsed.access[0].from, vec!["group:eng"]);
        assert!(
            parsed.access[0].capabilities.is_none(),
            "capabilities must be None when absent"
        );
    }

    #[test]
    fn annotation_parse_access_capability_grant() {
        let ingress = ingress_with_config(serde_json::json!({
            "access": [{
                "from": ["group:eng", "alice@example.com"],
                "capabilities": { "myapp/cap/admin": [{"role": "admin"}] }
            }]
        }));
        let parsed = IngressAnnotations::parse(&ingress).expect("must parse");
        assert_eq!(parsed.access.len(), 1);
        assert_eq!(parsed.access[0].from.len(), 2);
        let caps = parsed.access[0]
            .capabilities
            .as_ref()
            .expect("capabilities must be Some");
        assert!(caps.contains_key("myapp/cap/admin"));
    }

    #[test]
    fn annotation_parse_access_unknown_field_rejected() {
        let ingress = ingress_with_config(serde_json::json!({
            "access": [{"from": ["group:eng"], "unknown-field": true}]
        }));
        assert!(
            matches!(
                IngressAnnotations::parse(&ingress),
                Err(AnnotationError::Invalid(_, _))
            ),
            "unknown field in access grant must be rejected"
        );
    }
}
