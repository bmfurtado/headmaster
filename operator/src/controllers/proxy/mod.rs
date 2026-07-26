//! Shared machinery for Tailscale proxies — the tailnet-facing pods that the
//! Ingress and ExternalName Service controllers provision. Owns resource
//! naming, the pre-auth key lifecycle, and every child resource a proxy
//! consists of (WireGuard Service, state Secret, serve ConfigMap, RBAC,
//! StatefulSet). Parent-specific concerns — what the proxy serves, adoption
//! gates, status patching — stay with each controller.

mod auth_key;
mod error;
mod names;
mod resources;
mod support;

pub use names::{
    ingress_auto_tag, proxy_state_secret_name, proxy_sts_name, service_proxy_state_secret_name,
    service_proxy_sts_name,
};

pub(crate) use auth_key::{AuthKeyStatus, ensure_auth_key, rotate_stale_auth_key};
pub(crate) use error::Error;
pub(crate) use names::ProxyNames;
pub(crate) use resources::{
    ProxyNetworking, apply_proxy_rbac, apply_proxy_statefulset, apply_serve_configmap,
    apply_tun_proxy_statefulset, apply_wireguard_service, ensure_state_secret,
};
pub(crate) use support::{
    cleanup_proxy_resources, deregister_and_cleanup, headscale_connect, namespace_is_deleting,
    read_secret_json, read_secret_string, reset_if_retargeted,
};
