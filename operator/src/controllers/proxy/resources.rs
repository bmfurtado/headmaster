//! Builds and applies the Kubernetes resources every Tailscale proxy consists
//! of: the WireGuard Service, state Secret, serve ConfigMap, RBAC
//! (ServiceAccount, Role, RoleBinding), and the proxy StatefulSet itself.
//! What the proxy serves (the serve.json payload) is the parent controller's
//! concern; it arrives here prebuilt.

use k8s_ext::{
    ConfigMapExt, ConfigMapVolumeSourceExt, ContainerExt, EnvVarExt, PodSpecExt,
    PodTemplateSpecExt, PolicyRuleExt, RoleBindingExt, RoleExt, SecretExt, ServiceAccountExt,
    ServiceExt, ServicePortExt, StatefulSetExt, SubjectExt, VolumeExt, VolumeMountExt,
};
use k8s_openapi::ByteString;
use k8s_openapi::api::apps::v1::StatefulSet;
use k8s_openapi::api::core::v1::{
    ConfigMap, ConfigMapVolumeSource, Container, EnvVar, PodSecurityContext, PodSpec,
    PodTemplateSpec, SeccompProfile, Secret, Service, ServiceAccount, ServicePort, ServiceSpec,
    Volume, VolumeMount,
};
use k8s_openapi::api::rbac::v1::{PolicyRule, Role, RoleBinding, Subject};
use kube::api::Api;

use super::Error;
use super::names::ProxyNames;
use crate::controllers::applier::{ChildApplier, delete_ignoring_404};

const WIREGUARD_POD_PORT: i32 = 41641;
const SERVE_CONFIG_MOUNT: &str = "/etc/serve";
const SERVE_CONFIG_PATH: &str = "/etc/serve/serve.json";
const PROXY_COMPONENT: &str = "tailscale-proxy";

/// How the proxy's WireGuard socket is reachable by peers.
pub(crate) enum ProxyNetworking {
    /// Pod network: tailscaled is pinned to the in-pod port, exposed by the
    /// WireGuard NodePort Service, and the node's LAN endpoint is advertised
    /// via `TS_DEBUG_PRETENDPOINT` so LAN peers can connect directly.
    NodePort { node_port: i32 },
    /// Host network: tailscaled binds the node's own stack on an
    /// auto-selected port (the node's tailscaled owns 41641) and discovers
    /// its endpoints natively, the node's IPv6 addresses included.
    Host,
}

pub(crate) async fn apply_wireguard_service(
    child: &ChildApplier<'_>,
    names: &ProxyNames,
    host_network: bool,
) -> Result<ProxyNetworking, Error> {
    ensure_service_shape(child, names, host_network).await?;
    if host_network {
        // A host-networked tailscaled owns its own socket on the node: there
        // is no NodePort to allocate, and a NodePort's kube-proxy DNAT would
        // shunt stray WireGuard packets into the node's own tailscaled on
        // 41641. The Service survives headless, purely as the StatefulSet's
        // governing service.
        child
            .apply_service(
                PROXY_COMPONENT,
                Service::new(&names.wg_service_name).spec(ServiceSpec {
                    cluster_ip: Some("None".to_string()),
                    ports: Some(vec![ServicePort::udp("wireguard", WIREGUARD_POD_PORT)]),
                    ..Default::default()
                }),
            )
            .await?;
        return Ok(ProxyNetworking::Host);
    }
    child
        .apply_service(
            PROXY_COMPONENT,
            Service::new(&names.wg_service_name).spec(ServiceSpec {
                type_: Some(Service::NODE_PORT.to_string()),
                external_traffic_policy: Some("Local".to_string()),
                ports: Some(vec![
                    ServicePort::udp("wireguard", WIREGUARD_POD_PORT)
                        .target_port(WIREGUARD_POD_PORT),
                ]),
                ..Default::default()
            }),
        )
        .await?;
    let svc = Api::<Service>::namespaced(child.client.clone(), &child.namespace)
        .get(&names.wg_service_name)
        .await
        .map_err(Error::Kube)?;
    let node_port = svc
        .spec
        .as_ref()
        .and_then(|s| s.ports.as_ref())
        .and_then(|p| p.first())
        .and_then(|p| p.node_port)
        .ok_or(Error::NodePortNotAssigned)?;
    Ok(ProxyNetworking::NodePort { node_port })
}

/// Deletes the WireGuard Service when its shape disagrees with the desired
/// networking mode. `spec.clusterIP` is immutable, so a NodePort Service
/// cannot be patched into a headless one (or back) — toggling `host-network`
/// on a live parent needs a delete + recreate.
async fn ensure_service_shape(
    child: &ChildApplier<'_>,
    names: &ProxyNames,
    want_headless: bool,
) -> Result<(), Error> {
    let api = Api::<Service>::namespaced(child.client.clone(), &child.namespace);
    match api.get(&names.wg_service_name).await {
        Ok(svc) => {
            let is_headless =
                svc.spec.as_ref().and_then(|s| s.cluster_ip.as_deref()) == Some("None");
            if is_headless != want_headless {
                delete_ignoring_404(api, &names.wg_service_name).await?;
            }
            Ok(())
        }
        Err(kube::Error::Api(ref e)) if e.code == 404 => Ok(()),
        Err(e) => Err(Error::Kube(e)),
    }
}

pub(crate) async fn ensure_state_secret(
    child: &ChildApplier<'_>,
    names: &ProxyNames,
    headscale_ref: &str,
) -> Result<Secret, Error> {
    child
        .apply(
            PROXY_COMPONENT,
            Secret::new(&names.state_secret_name).data([(
                "headscale_ref",
                ByteString(headscale_ref.as_bytes().to_vec()),
            )]),
        )
        .await?;
    Api::<Secret>::namespaced(child.client.clone(), &child.namespace)
        .get(&names.state_secret_name)
        .await
        .map_err(Error::Kube)
}

pub(crate) async fn apply_serve_configmap(
    child: &ChildApplier<'_>,
    names: &ProxyNames,
    serve_json: &serde_json::Value,
) -> Result<(), Error> {
    child
        .apply(
            PROXY_COMPONENT,
            ConfigMap::new(&names.serve_configmap_name).data([(
                "serve.json",
                serde_json::to_string_pretty(serve_json)
                    .expect("serve JSON is always serializable"),
            )]),
        )
        .await?;
    Ok(())
}

pub(crate) async fn apply_proxy_rbac(
    child: &ChildApplier<'_>,
    names: &ProxyNames,
) -> Result<(), Error> {
    child
        .apply(PROXY_COMPONENT, ServiceAccount::new(&names.proxy_name))
        .await?;

    let role = Role::new(&names.proxy_name).rules([
        PolicyRule::default()
            .api_groups([""])
            .resources(["secrets"])
            .resource_names([names.state_secret_name.as_str()])
            .verbs(["get", "update", "patch"]),
        PolicyRule::default()
            .api_groups([""])
            .resources(["events"])
            .verbs(["create", "patch"]),
    ]);
    child.apply(PROXY_COMPONENT, role.clone()).await?;

    child
        .apply(
            PROXY_COMPONENT,
            RoleBinding::new(&names.proxy_name, &role).subjects([Subject::service_account(
                &names.proxy_name,
                &child.namespace,
            )]),
        )
        .await?;
    Ok(())
}

pub(crate) async fn apply_proxy_statefulset(
    child: &ChildApplier<'_>,
    names: &ProxyNames,
    proxy_image: &str,
    headscale_url: &str,
    hostname: &str,
    networking: &ProxyNetworking,
) -> Result<(), Error> {
    child
        .apply_statefulset(
            PROXY_COMPONENT,
            build_proxy_statefulset(names, proxy_image, headscale_url, hostname, networking),
        )
        .await?;
    Ok(())
}

fn build_proxy_statefulset(
    names: &ProxyNames,
    proxy_image: &str,
    headscale_url: &str,
    hostname: &str,
    networking: &ProxyNetworking,
) -> StatefulSet {
    let serve_config_volume = Volume::configmap(
        "serve-config",
        ConfigMapVolumeSource::new(&names.serve_configmap_name),
    );
    let mut env = vec![
        EnvVar::secret_key_ref("TS_AUTHKEY", &names.config_secret_name, "key"),
        EnvVar::value("TS_HOSTNAME", hostname),
        // TS_EXTRA_ARGS → passed to `tailscale up` (CLI flags only).
        EnvVar::value(
            "TS_EXTRA_ARGS",
            format!(
                "--login-server={headscale_url} \
                 --advertise-exit-node=false \
                 --snat-subnet-routes=false \
                 --stateful-filtering=false"
            ),
        ),
        // TS_TAILSCALED_EXTRA_ARGS → passed to the tailscaled daemon.
        // NodePort mode pins --port to the NodePort Service targetPort;
        // host-network mode auto-selects (--port=0) because the node's own
        // tailscaled already owns 41641 on the host stack. --socket places
        // the IPC socket in /tmp which is writable in restricted containers.
        EnvVar::value(
            "TS_TAILSCALED_EXTRA_ARGS",
            match networking {
                ProxyNetworking::NodePort { .. } => {
                    format!("--port={WIREGUARD_POD_PORT} --socket=/tmp/tailscaled.sock")
                }
                ProxyNetworking::Host => "--port=0 --socket=/tmp/tailscaled.sock".to_string(),
            },
        ),
        EnvVar::value("TS_SERVE_CONFIG", SERVE_CONFIG_PATH),
        EnvVar::value("TS_USERSPACE", "true"),
        EnvVar::value("TS_KUBE_SECRET", &names.state_secret_name),
        EnvVar::metadata_name("POD_NAME"),
        EnvVar::metadata_namespace("POD_NAMESPACE"),
    ];
    if let ProxyNetworking::NodePort { node_port } = networking {
        env.extend([
            EnvVar::status_host_ip("NODE_IP"),
            EnvVar::value("NODE_PORT", node_port.to_string()),
            EnvVar::value("TS_DEBUG_PRETENDPOINT", "$(NODE_IP):$(NODE_PORT)"),
        ]);
    }
    let container = Container::new("proxy")
        .image(proxy_image)
        .allow_privilege_escalation(false)
        .drop_capabilities(["ALL"])
        .env(env)
        .volume_mounts([VolumeMount::new(SERVE_CONFIG_MOUNT, &serve_config_volume).read_only()]);
    let (host_network, dns_policy) = match networking {
        // ClusterFirstWithHostNet: a hostNetwork pod otherwise inherits the
        // node's resolv.conf and cannot resolve the backend Service names in
        // serve.json.
        ProxyNetworking::Host => (Some(true), Some("ClusterFirstWithHostNet".to_string())),
        ProxyNetworking::NodePort { .. } => (None, None),
    };
    let pod_spec = PodSpec {
        host_network,
        dns_policy,
        security_context: Some(PodSecurityContext {
            seccomp_profile: Some(SeccompProfile {
                type_: "RuntimeDefault".into(),
                localhost_profile: None,
            }),
            ..Default::default()
        }),
        ..PodSpec::container(container)
            .service_account_name(&names.proxy_name)
            .volumes([serve_config_volume])
    };
    StatefulSet::new(&names.proxy_name)
        .replicas(1)
        .service_name(&names.wg_service_name)
        .template(PodTemplateSpec::new().pod_spec(pod_spec))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controllers::ingress::test_support::test_ctx;
    use crate::test_support::FaultService;

    fn service_no_nodeport(_: &http::Method, _: &str) -> (u16, Vec<u8>) {
        let body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": "t", "namespace": "default", "resourceVersion": "1"},
            "spec": {"type": "NodePort", "ports": [{"port": 41641, "protocol": "UDP"}]}
        });
        (200, serde_json::to_vec(&body).unwrap())
    }

    #[tokio::test]
    async fn apply_wireguard_service_errors_when_nodeport_absent() {
        let ctx = test_ctx(FaultService::client(service_no_nodeport));
        let child = ChildApplier::for_test(&ctx.client, "default", "test-proxy");
        let names = ProxyNames::new("default", "test-ingress");

        let result = apply_wireguard_service(&child, &names, false).await;
        assert!(
            matches!(result, Err(Error::NodePortNotAssigned)),
            "must return NodePortNotAssigned when the Service has no nodePort assigned"
        );
    }

    // ── proxy StatefulSet structure tests ─────────────────────────────────────

    fn make_proxy_statefulset(names: &ProxyNames, networking: &ProxyNetworking) -> StatefulSet {
        build_proxy_statefulset(
            names,
            "tailscale/tailscale:stable",
            "https://headscale.example.com",
            "my-app",
            networking,
        )
    }

    fn pod_spec_of(sts: &StatefulSet) -> &PodSpec {
        sts.spec
            .as_ref()
            .unwrap()
            .template
            .spec
            .as_ref()
            .expect("pod spec must be set")
    }

    fn env_of<'a>(sts: &'a StatefulSet, name: &str) -> Option<&'a EnvVar> {
        pod_spec_of(sts)
            .containers
            .iter()
            .find(|c| c.name == "proxy")
            .unwrap()
            .env
            .as_ref()
            .unwrap()
            .iter()
            .find(|e| e.name == name)
    }

    #[test]
    fn proxy_statefulset_has_service_name() {
        let names = ProxyNames::new("default", "my-app");
        let sts = make_proxy_statefulset(&names, &ProxyNetworking::NodePort { node_port: 30123 });
        assert_eq!(
            sts.spec.as_ref().unwrap().service_name.as_deref(),
            Some(names.wg_service_name.as_str()),
            "proxy StatefulSet must have spec.serviceName set"
        );
    }

    #[test]
    fn proxy_statefulset_has_seccomp_profile() {
        let names = ProxyNames::new("default", "my-app");
        let sts = make_proxy_statefulset(&names, &ProxyNetworking::NodePort { node_port: 30123 });
        let pod_sec = pod_spec_of(&sts)
            .security_context
            .as_ref()
            .expect("pod security_context must be set");
        assert_eq!(
            pod_sec.seccomp_profile.as_ref().map(|p| p.type_.as_str()),
            Some("RuntimeDefault"),
            "proxy pod must use RuntimeDefault seccomp profile"
        );
    }

    #[test]
    fn proxy_statefulset_container_disallows_privilege_escalation() {
        let names = ProxyNames::new("default", "my-app");
        let sts = make_proxy_statefulset(&names, &ProxyNetworking::NodePort { node_port: 30123 });
        let proxy = pod_spec_of(&sts)
            .containers
            .iter()
            .find(|c| c.name == "proxy")
            .unwrap();
        assert_eq!(
            proxy
                .security_context
                .as_ref()
                .and_then(|s| s.allow_privilege_escalation),
            Some(false),
            "proxy container must have allowPrivilegeEscalation=false"
        );
    }

    #[test]
    fn proxy_statefulset_nodeport_mode_advertises_node_endpoint() {
        let names = ProxyNames::new("default", "my-app");
        let sts = make_proxy_statefulset(&names, &ProxyNetworking::NodePort { node_port: 30123 });
        assert!(
            pod_spec_of(&sts).host_network.is_none(),
            "NodePort mode must not set hostNetwork"
        );
        assert_eq!(
            env_of(&sts, "NODE_PORT").and_then(|e| e.value.as_deref()),
            Some("30123"),
            "NodePort mode must pass the assigned nodePort to the pod"
        );
        assert!(
            env_of(&sts, "TS_DEBUG_PRETENDPOINT").is_some(),
            "NodePort mode must advertise the node endpoint via TS_DEBUG_PRETENDPOINT"
        );
        assert_eq!(
            env_of(&sts, "TS_TAILSCALED_EXTRA_ARGS").and_then(|e| e.value.as_deref()),
            Some("--port=41641 --socket=/tmp/tailscaled.sock"),
            "NodePort mode must pin tailscaled to the NodePort Service targetPort"
        );
    }

    #[test]
    fn proxy_statefulset_host_mode_uses_host_network() {
        let names = ProxyNames::new("default", "my-app");
        let sts = make_proxy_statefulset(&names, &ProxyNetworking::Host);
        let spec = pod_spec_of(&sts);
        assert_eq!(
            spec.host_network,
            Some(true),
            "Host mode must set hostNetwork on the pod"
        );
        assert_eq!(
            spec.dns_policy.as_deref(),
            Some("ClusterFirstWithHostNet"),
            "Host mode must keep cluster DNS so serve.json backends resolve"
        );
        for var in ["NODE_IP", "NODE_PORT", "TS_DEBUG_PRETENDPOINT"] {
            assert!(
                env_of(&sts, var).is_none(),
                "Host mode must not set {var}: endpoints are discovered natively"
            );
        }
        assert_eq!(
            env_of(&sts, "TS_TAILSCALED_EXTRA_ARGS").and_then(|e| e.value.as_deref()),
            Some("--port=0 --socket=/tmp/tailscaled.sock"),
            "Host mode must auto-select the UDP port; 41641 belongs to the node's tailscaled"
        );
    }
}
