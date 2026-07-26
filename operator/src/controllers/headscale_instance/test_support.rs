//! Shared `#[cfg(test)]` fixtures for the headscale_instance controller submodules.

use std::sync::Arc;

use headscale_client::LiveConnector;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::runtime::events::Reporter;

use crate::context::Context;
use crate::types::{HeadscaleInstance, HeadscaleInstanceSpec, StorageSpec};

pub(super) fn test_ctx(client: kube::Client) -> Context {
    Context {
        client,
        operator_namespace: "default".to_string(),
        headscale: Arc::new(LiveConnector),
        reporter: Reporter {
            controller: "test".to_string(),
            instance: None,
        },
        headscale_image: "test".to_string(),
        proxy_image: "test".to_string(),
        socat_image: "test".to_string(),
        tun_device: crate::context::TunDeviceAccess::Privileged,
        egress_dns_coredns_custom: false,
        operator_image: "test".to_string(),
        claim_default: true,
    }
}

pub(super) fn minimal_instance(name: &str) -> HeadscaleInstance {
    HeadscaleInstance {
        metadata: ObjectMeta {
            name: name.to_string().into(),
            namespace: "default".to_string().into(),
            uid: "test-uid".to_string().into(),
            generation: 1.into(),
            ..Default::default()
        },
        spec: HeadscaleInstanceSpec {
            server_url: "https://headscale.example.com".to_string(),
            dns_base_domain: "ts.example.com".to_string(),
            storage: StorageSpec {
                size: "1Gi".to_string(),
                ..Default::default()
            },
            watched_namespaces: vec!["*".to_string()],
            ..Default::default()
        },
        status: None,
    }
}
