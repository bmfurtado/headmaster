use headscale_client::Status as GrpcStatus;
use headscale_client::policy::PolicyParseError;

#[derive(thiserror::Error, Debug)]
pub(crate) enum Error {
    #[error("kube error: {0}")]
    Kube(#[from] kube::Error),
    #[error("config serialization failed: {0}")]
    ConfigSerialization(#[from] serde_saphyr::ser::Error),
    #[error("object has no namespace")]
    MissingNamespace,
    #[error("object has no name")]
    UnnamedObject,
    #[error("headscale gRPC error: {0}")]
    HeadscaleApi(#[from] GrpcStatus),
    #[error("exec io error: {0}")]
    ExecIo(#[from] std::io::Error),
    #[error("exec failed: {0}")]
    ExecFailed(String),
    #[error("exec produced unexpected output: {0}")]
    ExecInvalidOutput(String),
    #[error("spec.policy.inline is not valid HuJSON: {0}")]
    InvalidPolicy(PolicyParseError),
    #[error(
        "spec.policy.inline contains groups with members while spec.scim is set; \
         SCIM owns the groups section — remove member entries from 'groups' in spec.policy.inline"
    )]
    ScimPolicyConflict,
    #[error(
        "spec.external is mutually exclusive with spec.policy, spec.scim, and \
         spec.extraConfig; the external headscale's configuration and policy \
         are managed outside the operator"
    )]
    ExternalSpecConflict,
}
