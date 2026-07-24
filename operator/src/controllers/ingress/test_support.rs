//! Shared `#[cfg(test)]` fixtures for the ingress controller submodules.

use std::sync::Arc;

use headscale_client::LiveConnector;
use k8s_openapi::api::networking::v1::{Ingress, IngressSpec};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::runtime::events::Reporter;

use super::INGRESS_CLASS_NAME;
use crate::context::Context;

pub(crate) fn test_ctx(client: kube::Client) -> Context {
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
        operator_image: "test".to_string(),
        claim_default: true,
    }
}

pub(crate) fn test_ingress() -> Ingress {
    Ingress {
        metadata: ObjectMeta {
            name: Some("test-ingress".to_string()),
            namespace: Some("default".to_string()),
            uid: Some("00000000-0000-0000-0000-000000000001".to_string()),
            ..Default::default()
        },
        ..Default::default()
    }
}

pub(crate) fn headmaster_ingress(namespace: &str) -> Ingress {
    Ingress {
        metadata: ObjectMeta {
            name: Some("test-ingress".to_string()),
            namespace: Some(namespace.to_string()),
            uid: Some("00000000-0000-0000-0000-000000000001".to_string()),
            ..Default::default()
        },
        spec: Some(IngressSpec {
            ingress_class_name: Some(INGRESS_CLASS_NAME.to_string()),
            ..Default::default()
        }),
        ..Default::default()
    }
}
