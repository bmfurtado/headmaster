//! Ingress controller — provisions a Tailscale proxy StatefulSet (plus
//! WireGuard NodePort Service, auth-key Secret, serve ConfigMap, RBAC) in the
//! operator namespace for every `Ingress` annotated `ingressClassName: headmaster`.
//! The proxy building blocks shared with the ExternalName Service controller
//! live in [`crate::controllers::proxy`]; this module owns what is
//! Ingress-specific: adoption gates, HTTP route collection, and status.

mod reconcile;
mod serve;
#[cfg(test)]
pub(crate) mod test_support;

pub use crate::controllers::proxy::{ingress_auto_tag, proxy_state_secret_name, proxy_sts_name};
pub use reconcile::{ensure_ingress_class, stream};

#[cfg(test)]
pub(crate) use crate::types::ANNOTATION_CONFIG;

pub const CONTROLLER_NAME: &str = "headmaster.potatonode.github.io/ingress-controller";
pub(crate) const INGRESS_CLASS_NAME: &str = "headmaster";
