//! Service controller — Tailscale proxies for annotated `Service` objects,
//! in both directions:
//!
//! - **Egress** (`type: ExternalName` + `tailnet-fqdn`): makes a tailnet host
//!   reachable from in-cluster pods. The proxy joins the tailnet as its own
//!   node (userspace tailscaled with a loopback SOCKS5 listener) and
//!   socat-forwards each declared Service port to the tailnet destination;
//!   the Service's `externalName` is then pointed at the proxy.
//! - **Exposure** (any other annotated Service): puts the Service *on* the
//!   tailnet as its own node — userspace TCP forwarding by default
//!   (`mode: tsnet`) or kernel DNAT through a TUN device (`mode: tun`) for
//!   high-bandwidth services. See [`expose`].
//!
//! Shares the proxy building blocks (names, auth keys, cleanup, headscale
//! connection) with the Ingress controller via [`crate::controllers::proxy`].

mod dns;
mod expose;
mod reconcile;

pub use reconcile::stream;
