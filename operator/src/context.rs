use std::sync::Arc;

use headscale_client::HeadscaleConnector;
use kube::Client;
use kube::runtime::events::{Recorder, Reporter};

pub struct Context {
    pub client: Client,
    pub operator_namespace: String,
    pub headscale: Arc<dyn HeadscaleConnector>,
    pub reporter: Reporter,
    pub headscale_image: String,
    pub proxy_image: String,
    /// socat image for the forwarder container in tailnet egress proxy pods.
    pub socat_image: String,
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
