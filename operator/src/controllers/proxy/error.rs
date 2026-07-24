use headscale_client::Status;

use crate::types::AnnotationError;

#[derive(thiserror::Error, Debug)]
pub(crate) enum Error {
    #[error("kube error: {0}")]
    Kube(#[from] kube::Error),
    #[error("headscale gRPC error: {0}")]
    HeadscaleApi(#[from] Status),
    #[error("{0}")]
    Annotation(#[from] AnnotationError),
    #[error("object has no namespace")]
    MissingNamespace,
    #[error("object has no name")]
    UnnamedObject,
    #[error("WireGuard NodePort service has no nodePort assigned yet")]
    NodePortNotAssigned,
}
