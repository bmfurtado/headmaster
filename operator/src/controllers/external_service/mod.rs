//! Tailnet egress controller — makes tailnet hosts reachable from in-cluster
//! pods. For every `Service` of `type: ExternalName` carrying the headmaster
//! config annotation with a `tailnet-fqdn`, provisions an egress proxy pod
//! that joins the tailnet as its own node (userspace tailscaled with a
//! loopback SOCKS5 listener) and socat-forwards each declared Service port to
//! the tailnet destination; the Service's `externalName` is then pointed at
//! the proxy, so pods dial the Service and land on the tailnet host.
//!
//! Shares the proxy building blocks (names, auth keys, cleanup, headscale
//! connection) with the Ingress controller via [`crate::controllers::proxy`].

mod dns;
mod reconcile;

pub use reconcile::stream;
