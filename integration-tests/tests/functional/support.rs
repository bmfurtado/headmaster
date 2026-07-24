use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use headscale_client::HeadscaleConnector;
use k8s_openapi::ByteString;
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::api::networking::v1::{
    HTTPIngressPath, HTTPIngressRuleValue, Ingress, IngressBackend, IngressRule,
    IngressServiceBackend, IngressSpec, ServiceBackendPort,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::Api;
use kube::api::{Patch, PatchParams, PostParams};
use kube::runtime::events::Reporter;
use operator::context::Context;
use operator::controllers::ingress;
use operator::types::{HeadscaleInstance, HeadscaleInstanceSpec, StorageSpec};
use serde_json::json;

/// Creates a `HeadscaleInstance` in `ns` and immediately patches its status to
/// Ready, so that sub-resource controllers can proceed without waiting for a
/// real headscale to come up.  Returns the `Api` handle for further assertions.
pub async fn create_ready_instance(
    kube_client: &kube::Client,
    ns: &str,
    name: &str,
) -> Api<HeadscaleInstance> {
    let api: Api<HeadscaleInstance> = Api::namespaced(kube_client.clone(), ns);
    api.create(
        &PostParams::default(),
        &HeadscaleInstance {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(ns.to_string()),
                ..Default::default()
            },
            spec: HeadscaleInstanceSpec {
                server_url: "https://headscale.example.com".to_string(),
                dns_base_domain: "ts.example.com".to_string(),
                storage: StorageSpec {
                    size: "1Gi".to_string(),
                    ..Default::default()
                },
                ..Default::default()
            },
            status: None,
        },
    )
    .await
    .expect("create HeadscaleInstance");

    api.patch_status(
        name,
        &PatchParams::apply("headmaster-test").force(),
        &Patch::Apply(json!({
            "apiVersion": "headmaster.potatonode.github.io/v1alpha1",
            "kind": "HeadscaleInstance",
            "metadata": {"name": name, "namespace": ns},
            "status": {
                "observedGeneration": 1,
                "conditions": [{
                    "type": "Ready",
                    "status": "True",
                    "reason": "StatefulSetReady",
                    "message": "headscale StatefulSet is ready",
                    "lastTransitionTime": "2024-01-01T00:00:00Z",
                    "observedGeneration": 1
                }]
            }
        })),
    )
    .await
    .expect("patch HeadscaleInstance status to Ready");

    // Create the api-key Secret the ingress controller reads when connecting to headscale.
    // FakeConnector ignores the key value, but headscale_connect still needs the secret to exist.
    Api::<Secret>::namespaced(kube_client.clone(), ns)
        .create(
            &PostParams::default(),
            &Secret {
                metadata: ObjectMeta {
                    name: Some(format!("headscale-api-key-{name}")),
                    namespace: Some(ns.to_string()),
                    ..Default::default()
                },
                string_data: Some(BTreeMap::from([(
                    "HEADSCALE_API_KEY".to_string(),
                    "fake-api-key".to_string(),
                )])),
                ..Default::default()
            },
        )
        .await
        .expect("create api-key secret for test");

    api
}

/// Waits for the operator to pre-create the proxy state Secret for the given
/// Ingress, then patches it with `device_id` and `device_ips` to simulate what
/// containerboot writes after the proxy registers on the tailnet.
pub async fn populate_state_secret(
    kube_client: &kube::Client,
    ns: &str,
    ingress_ns: &str,
    ingress_name: &str,
    device_id: &str,
    device_ips: &[&str],
) {
    let state_secret_name = ingress::proxy_state_secret_name(ingress_ns, ingress_name);
    let secret_api = Api::<Secret>::namespaced(kube_client.clone(), ns);

    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        match secret_api.get(&state_secret_name).await {
            Ok(_) => break,
            Err(kube::Error::Api(e)) if e.code == 404 => {}
            Err(e) => panic!("unexpected error waiting for state secret: {e}"),
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timed out: state secret {state_secret_name} was not pre-created within 15s"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let patch = Secret {
        metadata: ObjectMeta {
            name: Some(state_secret_name.clone()),
            namespace: Some(ns.to_string()),
            ..Default::default()
        },
        data: Some(BTreeMap::from([
            (
                "device_id".to_string(),
                ByteString(device_id.as_bytes().to_vec()),
            ),
            (
                "device_ips".to_string(),
                ByteString(serde_json::to_vec(&device_ips).unwrap()),
            ),
        ])),
        ..Default::default()
    };

    secret_api
        .patch(
            &state_secret_name,
            &PatchParams::default(),
            &Patch::Merge(serde_json::to_value(&patch).unwrap()),
        )
        .await
        .expect("patch state secret with device_id and device_ips");
}

pub fn make_ingress(name: &str, ns: &str, headscale_ref: &str) -> Ingress {
    make_ingress_with_annotations(name, ns, headscale_ref, Some(name), &[])
}

/// Builds a test Ingress with explicit user and tags in the config annotation.
///
/// `user`: pass `None` to omit it (tags-only path). `tags`: pass an empty
/// slice to omit it.
pub fn make_ingress_with_annotations(
    name: &str,
    ns: &str,
    headscale_ref: &str,
    user: Option<&str>,
    tags: &[&str],
) -> Ingress {
    let mut config = serde_json::json!({"headscale-ref": headscale_ref});
    if let Some(u) = user {
        config["user"] = serde_json::Value::String(u.to_string());
    }
    if !tags.is_empty() {
        config["managed-key-tags"] = serde_json::json!(tags);
    }
    let annotations = BTreeMap::from([(
        "headmaster.potatonode.github.io/config".to_string(),
        config.to_string(),
    )]);
    Ingress {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(ns.to_string()),
            annotations: Some(annotations),
            ..Default::default()
        },
        spec: Some(IngressSpec {
            ingress_class_name: Some("headmaster".to_string()),
            rules: Some(vec![IngressRule {
                http: Some(HTTPIngressRuleValue {
                    paths: vec![HTTPIngressPath {
                        path: Some("/".to_string()),
                        path_type: "Prefix".to_string(),
                        backend: IngressBackend {
                            service: Some(IngressServiceBackend {
                                name: "my-svc".to_string(),
                                port: Some(ServiceBackendPort {
                                    number: Some(8080),
                                    ..Default::default()
                                }),
                            }),
                            ..Default::default()
                        },
                    }],
                }),
                ..Default::default()
            }]),
            ..Default::default()
        }),
        status: None,
    }
}

/// Builds a test Ingress with `access` grants in the config annotation.
///
/// The Ingress has the given `user` and the provided `access` JSON array.
pub fn make_ingress_with_access(
    name: &str,
    ns: &str,
    headscale_ref: &str,
    user: &str,
    access: serde_json::Value,
) -> Ingress {
    let config = serde_json::json!({
        "headscale-ref": headscale_ref,
        "user": user,
        "access": access,
    });
    let annotations = BTreeMap::from([(
        "headmaster.potatonode.github.io/config".to_string(),
        config.to_string(),
    )]);
    Ingress {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(ns.to_string()),
            annotations: Some(annotations),
            ..Default::default()
        },
        spec: Some(IngressSpec {
            ingress_class_name: Some("headmaster".to_string()),
            rules: Some(vec![IngressRule {
                http: Some(HTTPIngressRuleValue {
                    paths: vec![HTTPIngressPath {
                        path: Some("/".to_string()),
                        path_type: "Prefix".to_string(),
                        backend: IngressBackend {
                            service: Some(IngressServiceBackend {
                                name: "my-svc".to_string(),
                                port: Some(ServiceBackendPort {
                                    number: Some(8080),
                                    ..Default::default()
                                }),
                            }),
                            ..Default::default()
                        },
                    }],
                }),
                ..Default::default()
            }]),
            ..Default::default()
        }),
        status: None,
    }
}

/// Constructs a test [`Context`] backed by the given `connector`.
///
pub fn make_ctx(
    kube_client: &kube::Client,
    ns: &str,
    connector: Arc<dyn HeadscaleConnector>,
) -> Arc<Context> {
    Arc::new(Context {
        client: kube_client.clone(),
        operator_namespace: ns.to_string(),
        headscale: connector,
        reporter: Reporter {
            controller: "headmaster-test".into(),
            instance: None,
        },
        headscale_image: "ghcr.io/juanfont/headscale:v0.29.0-beta.2".to_string(),
        proxy_image: "tailscale/tailscale:v1.98.4".to_string(),
        socat_image: "alpine/socat:1.8.0.3".to_string(),
        egress_dns_coredns_custom: false,
        operator_image: "ghcr.io/potatonode/headmaster:dev".to_string(),
        claim_default: true,
    })
}
