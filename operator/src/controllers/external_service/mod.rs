//! ExternalName Service controller — provisions a Tailscale proxy for every
//! `Service` of `type: ExternalName` carrying the headmaster config
//! annotation. The proxy TCP-forwards each declared Service port to the
//! external hostname via tailscale serve, so the external endpoint appears
//! on the tailnet as its own node — no socat, no extra binary.
//!
//! Shares the proxy building blocks (names, auth keys, child resources,
//! cleanup) with the Ingress controller via [`crate::controllers::proxy`];
//! this module owns what is Service-specific: adoption gates, TCP forward
//! collection, and ownership release.

mod reconcile;

pub use reconcile::stream;
