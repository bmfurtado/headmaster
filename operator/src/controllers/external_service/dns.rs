//! Operator-managed in-cluster DNS for tailnet egress. When enabled
//! (`egressDns.corednsCustom` chart value), the operator owns one key in the
//! `kube-system/coredns-custom` ConfigMap — the hook k3s (and AKS) CoreDNS
//! imports into its main server block — holding one `rewrite` per egress
//! Service. Pods then resolve each `tailnet-fqdn` to that egress's proxy
//! ClusterIP Service directly, so clients dial the real tailnet hostname
//! with correct SNI and full certificate validation, from any namespace.
//!
//! The tailnet FQDN is treated as cluster-unique: a rewrite can only point
//! at one target. On duplicates, the first Service in (namespace, name)
//! order wins and the losers get a warning event.

use k8s_openapi::api::core::v1::{ConfigMap, Service};
use kube::api::{Api, ListParams, Patch, PatchParams};
use kube::{Resource, ResourceExt};

use super::reconcile::is_egress_shape;
use crate::context::Context;
use crate::controllers::proxy::{Error, ProxyNames};
use crate::controllers::recorder::RecorderExt;
use crate::types::IngressAnnotations;

const COREDNS_CUSTOM_NAMESPACE: &str = "kube-system";
const COREDNS_CUSTOM_NAME: &str = "coredns-custom";
const OVERRIDE_KEY: &str = "headmaster-egress.override";

/// Regenerates the CoreDNS override from the full set of egress Services
/// this deployment owns, and SSA-applies it. Field ownership makes the
/// shared ConfigMap safe: only the operator's key is touched, and applying
/// with no entries removes it. No-op unless the feature is enabled.
pub(super) async fn sync_egress_dns(ctx: &Context) -> Result<(), Error> {
    if !ctx.egress_dns_coredns_custom {
        return Ok(());
    }

    let services = Api::<Service>::all(ctx.client.clone())
        .list(&ListParams::default())
        .await
        .map_err(Error::Kube)?
        .items;

    let (rewrites, duplicates) = collect_rewrites(&services, ctx);

    for dup in &duplicates {
        let _ = ctx
            .recorder()
            .publish_warning(
                &dup.service.object_ref(&()),
                "DuplicateTailnetFqdn",
                &format!(
                    "tailnet-fqdn '{}' is already rewritten to the egress proxy of \
                     Service '{}/{}'; a tailnet FQDN must be cluster-unique — this \
                     Service's egress works, but in-cluster DNS resolves the name \
                     to the other proxy",
                    dup.fqdn, dup.winner_ns, dup.winner_name,
                ),
            )
            .await;
    }

    let mut cm = ConfigMap::default();
    cm.meta_mut().name = Some(COREDNS_CUSTOM_NAME.to_string());
    cm.meta_mut().namespace = Some(COREDNS_CUSTOM_NAMESPACE.to_string());
    if !rewrites.is_empty() {
        cm.data = Some(std::collections::BTreeMap::from([(
            OVERRIDE_KEY.to_string(),
            build_override(&rewrites),
        )]));
    }
    Api::<ConfigMap>::namespaced(ctx.client.clone(), COREDNS_CUSTOM_NAMESPACE)
        .patch(
            COREDNS_CUSTOM_NAME,
            &PatchParams::apply(&crate::field_manager(&ctx.operator_namespace)).force(),
            &Patch::Apply(&cm),
        )
        .await
        .map_err(Error::Kube)?;
    Ok(())
}

struct Duplicate<'a> {
    service: &'a Service,
    fqdn: String,
    winner_ns: String,
    winner_name: String,
}

/// Collects `(fqdn, rewrite_target)` pairs from the egress Services owned by
/// this deployment, sorted by FQDN, first (namespace, name) winning on
/// duplicates. Services mid-deletion are excluded so a removed egress drops
/// out of DNS during its own cleanup.
fn collect_rewrites<'a>(
    services: &'a [Service],
    ctx: &Context,
) -> (Vec<(String, String)>, Vec<Duplicate<'a>>) {
    let mut candidates: Vec<(&Service, String, String)> = services
        .iter()
        .filter(|svc| is_egress_shape(svc) && svc.meta().deletion_timestamp.is_none())
        .filter(|svc| match IngressAnnotations::headscale_namespace(*svc) {
            Some(n) => n == ctx.operator_namespace,
            None => ctx.claim_default,
        })
        .filter_map(|svc| {
            let fqdn = IngressAnnotations::parse(svc)
                .ok()?
                .tailnet_fqdn
                .filter(|f| !f.is_empty())?;
            let names =
                ProxyNames::for_service(&svc.namespace().unwrap_or_default(), &svc.name_any());
            let target = format!(
                "{}.{}.svc.cluster.local",
                names.wg_service_name, ctx.operator_namespace
            );
            Some((svc, fqdn, target))
        })
        .collect();
    candidates.sort_by_key(|(svc, _, _)| (svc.namespace().unwrap_or_default(), svc.name_any()));

    let mut rewrites: Vec<(String, String)> = Vec::new();
    let mut winners: std::collections::BTreeMap<String, (String, String)> = Default::default();
    let mut duplicates: Vec<Duplicate<'a>> = Vec::new();
    for (svc, fqdn, target) in candidates {
        if let Some((winner_ns, winner_name)) = winners.get(&fqdn) {
            duplicates.push(Duplicate {
                service: svc,
                fqdn,
                winner_ns: winner_ns.clone(),
                winner_name: winner_name.clone(),
            });
            continue;
        }
        winners.insert(
            fqdn.clone(),
            (svc.namespace().unwrap_or_default(), svc.name_any()),
        );
        rewrites.push((fqdn, target));
    }
    rewrites.sort();
    (rewrites, duplicates)
}

fn build_override(rewrites: &[(String, String)]) -> String {
    rewrites
        .iter()
        .map(|(fqdn, target)| format!("rewrite name {fqdn} {target}\n"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controllers::ingress::test_support::test_ctx;
    use crate::test_support::{FaultService, all_404};
    use crate::types::ANNOTATION_CONFIG;
    use k8s_openapi::api::core::v1::ServiceSpec;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use std::collections::BTreeMap;

    fn egress_svc(ns: &str, name: &str, fqdn: &str) -> Service {
        Service {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(ns.to_string()),
                annotations: Some(BTreeMap::from([(
                    ANNOTATION_CONFIG.to_string(),
                    format!(r#"{{"headscale-ref":"main","user":"alice","tailnet-fqdn":"{fqdn}"}}"#),
                )])),
                ..Default::default()
            },
            spec: Some(ServiceSpec {
                type_: Some("ExternalName".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn dns_test_ctx() -> Context {
        let mut ctx = test_ctx(FaultService::client(all_404));
        ctx.egress_dns_coredns_custom = true;
        ctx
    }

    #[tokio::test]
    async fn rewrites_sorted_and_target_the_proxy_service() {
        let ctx = dns_test_ctx();
        let services = vec![
            egress_svc("media", "qbittorrent", "qbittorrent.ts.example.com"),
            egress_svc("apps", "nas", "nas.ts.example.com"),
        ];
        let (rewrites, dups) = collect_rewrites(&services, &ctx);
        assert!(dups.is_empty());
        assert_eq!(rewrites.len(), 2);
        assert_eq!(rewrites[0].0, "nas.ts.example.com", "must be FQDN-sorted");
        let names = ProxyNames::for_service("media", "qbittorrent");
        assert_eq!(
            rewrites[1].1,
            format!("{}.default.svc.cluster.local", names.wg_service_name),
            "rewrite must target the proxy ClusterIP Service directly"
        );
    }

    #[tokio::test]
    async fn duplicate_fqdn_first_by_ns_name_wins() {
        let ctx = dns_test_ctx();
        let services = vec![
            egress_svc("zzz", "late", "qbittorrent.ts.example.com"),
            egress_svc("media", "qbittorrent", "qbittorrent.ts.example.com"),
        ];
        let (rewrites, dups) = collect_rewrites(&services, &ctx);
        assert_eq!(rewrites.len(), 1);
        let names = ProxyNames::for_service("media", "qbittorrent");
        assert!(
            rewrites[0].1.starts_with(&names.wg_service_name),
            "(media, qbittorrent) sorts before (zzz, late) and must win"
        );
        assert_eq!(dups.len(), 1);
        assert_eq!(dups[0].winner_ns, "media");
        assert_eq!(dups[0].winner_name, "qbittorrent");
    }

    #[tokio::test]
    async fn deleting_and_foreign_services_are_excluded() {
        let ctx = dns_test_ctx();
        let mut deleting = egress_svc("media", "gone", "gone.ts.example.com");
        deleting.metadata.deletion_timestamp =
            serde_json::from_value(serde_json::json!("2026-01-01T00:00:00Z")).ok();
        let mut foreign = egress_svc("media", "other", "other.ts.example.com");
        foreign
            .metadata
            .annotations
            .as_mut()
            .unwrap()
            .insert(
                ANNOTATION_CONFIG.to_string(),
                r#"{"headscale-ref":"main","user":"alice","tailnet-fqdn":"other.ts.example.com","headscale-namespace":"elsewhere"}"#.to_string(),
            );
        let services = [deleting, foreign];
        let (rewrites, dups) = collect_rewrites(&services, &ctx);
        assert!(
            rewrites.is_empty(),
            "deleting + foreign must both be excluded"
        );
        assert!(dups.is_empty());
    }

    #[test]
    fn override_format_is_one_rewrite_per_line() {
        let rewrites = vec![
            (
                "a.ts.example.com".to_string(),
                "svc-a.ns.svc.cluster.local".to_string(),
            ),
            (
                "b.ts.example.com".to_string(),
                "svc-b.ns.svc.cluster.local".to_string(),
            ),
        ];
        assert_eq!(
            build_override(&rewrites),
            "rewrite name a.ts.example.com svc-a.ns.svc.cluster.local\n\
             rewrite name b.ts.example.com svc-b.ns.svc.cluster.local\n"
        );
    }
}
