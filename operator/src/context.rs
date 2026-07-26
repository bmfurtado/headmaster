use std::sync::Arc;

use headscale_client::HeadscaleConnector;
use kube::Client;
use kube::runtime::events::{Recorder, Reporter};

/// How tun-mode proxy pods get access to /dev/net/tun. Operator-wide,
/// selected via the chart's `tunDevice` values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunDeviceAccess {
    /// Run the proxy container privileged and hostPath-mount /dev/net/tun.
    /// The simplest variant and the default; requires the cluster to admit
    /// privileged pods in the operator namespace.
    Privileged,
    /// Request one unit of a device-plugin resource (e.g. `squat.ai/tun`
    /// from squat/generic-device-plugin) and add only CAP_NET_ADMIN — no
    /// privileged mode. IP forwarding is set via pod `securityContext.sysctls`,
    /// so the kubelet must allow the `net.ipv4.ip_forward` and
    /// `net.ipv6.conf.all.forwarding` unsafe sysctls.
    DevicePlugin {
        /// Extended-resource name advertised by the device plugin.
        resource: String,
    },
}

pub struct Context {
    pub client: Client,
    pub operator_namespace: String,
    pub headscale: Arc<dyn HeadscaleConnector>,
    pub reporter: Reporter,
    pub headscale_image: String,
    pub proxy_image: String,
    /// socat image for the forwarder container in tailnet egress proxy pods.
    pub socat_image: String,
    /// How tun-mode proxy pods get access to /dev/net/tun.
    pub tun_device: TunDeviceAccess,
    /// Maintain egress DNS rewrites in the kube-system coredns-custom
    /// ConfigMap (k3s/AKS convention; opt-in via the chart).
    pub egress_dns_coredns_custom: bool,
    pub operator_image: String,
    /// When true this deployment claims Ingresses that have no explicit `headscale-namespace`
    /// annotation. Only one deployment may hold `claim_default = true` at a time;
    /// a second one loses the IngressClass annotation SSA race and fails at startup.
    pub claim_default: bool,
}

impl Context {
    pub fn recorder(&self) -> Recorder {
        Recorder::new(self.client.clone(), self.reporter.clone())
    }
}
