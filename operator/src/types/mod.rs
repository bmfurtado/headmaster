pub mod condition;
pub mod headscale_instance;
pub mod ingress_annotations;

pub use condition::ResourceStatus;
pub use headscale_instance::{
    ExternalSpec, HeadscaleInstance, HeadscaleInstancePolicy, HeadscaleInstanceSpec,
    HeadscaleInstanceStatus, ScimSpec, StorageSpec,
};
pub use ingress_annotations::{
    ANNOTATION_CONFIG, AnnotationError, EgressConsumer, IngressAccessGrant, IngressAnnotations,
    ProxyMode,
};
