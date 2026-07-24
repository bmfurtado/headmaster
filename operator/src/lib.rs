use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;

pub const GROUP: &str = "headmaster.potatonode.github.io";
pub const ANNOTATION_CLAIMED_BY: &str = "headmaster.potatonode.github.io/claimed-by";
pub const ANNOTATION_DEFAULT_NAMESPACE: &str = "headmaster.potatonode.github.io/default-namespace";

pub fn finalizer(operator_ns: &str) -> String {
    format!("headmaster.potatonode.github.io/cleanup-{operator_ns}")
}

pub fn field_manager(operator_ns: &str) -> String {
    format!("headmaster-{operator_ns}")
}

pub mod labels {
    pub use k8s_ext::label::{APP_INSTANCE, APP_MANAGED_BY, APP_NAME};

    pub const MANAGED_BY_VALUE: &str = "headmaster";
    // Historical key names: the "ingress-" prefix predates ExternalName
    // Service proxies. Both parent kinds use these keys for their
    // coordinates; PARENT_KIND disambiguates. The values are live as labels
    // on deployed clusters, so the keys must not change.
    pub const INGRESS_NAME: &str = "headmaster.potatonode.github.io/ingress-name";
    pub const INGRESS_NAMESPACE: &str = "headmaster.potatonode.github.io/ingress-namespace";
    /// Which kind of parent owns a proxy child resource: "ingress" (also the
    /// meaning when the label is absent, for children created before this
    /// label existed) or "service".
    pub const PARENT_KIND: &str = "headmaster.potatonode.github.io/parent-kind";
    pub const PARENT_KIND_INGRESS: &str = "ingress";
    pub const PARENT_KIND_SERVICE: &str = "service";
    pub fn managed_by_selector() -> String {
        format!("{}={}", APP_MANAGED_BY, MANAGED_BY_VALUE)
    }
}

pub mod context;
pub mod controllers;
pub mod server;
pub mod types;

#[cfg(test)]
pub(crate) mod test_support;

/// Returns CRDs owned by this operator.
///
/// Used by `crdgen` to emit manifests and by functional tests to register
/// operator-managed CRDs with envtest.
pub fn crds() -> Vec<CustomResourceDefinition> {
    use kube::CustomResourceExt;
    vec![types::HeadscaleInstance::crd()]
}
