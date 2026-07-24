# Headmaster

Headmaster is a Kubernetes operator that manages self-hosted
[headscale](https://github.com/juanfont/headscale) control-plane instances.
It provisions headscale as a StatefulSet, reconciles ACL policies, and ships a
SCIM sidecar that keeps headscale users in sync with an OIDC provider.

## Features

- **Declarative instances** — one `HeadscaleInstance` CR per control plane;
  headmaster handles the StatefulSet, Services, PVCs, and Secrets
- **ACL policy management** — the operator takes ownership of the acl policy
  which users define in the CRD.
- **OIDC integration** — link an instance to an OIDC provider via
  `scimProviderID`; users and groups flow in automatically
- **SCIM user sync** — the bundled `headmaster-scim` sidecar bridges the OIDC
  provider's SCIM endpoint to the headscale API
- **Per-Ingress access grants** — declare who can reach each app directly on
  the Ingress using headscale grants, including app-capability headers
- **Admission webhook** — validates `HeadscaleInstance` and `Ingress` specs at
  apply time

## Requirements

| Tool       | Version | Notes                    |
| ---------- | ------- | ------------------------ |
| Kubernetes | 1.32+   |                          |
| Helm       | 3.x     |                          |
| headscale  | 0.29.0+ | image set in values.yaml |

## Installation

```sh
helm upgrade --install headmaster \
  oci://ghcr.io/potatonode/charts/headmaster \
  --namespace headmaster-system --create-namespace
```

See [`chart/README.md`](chart/README.md) for all chart values.

## Usage

Create a `values.yaml` with the minimum required configuration:

```yaml
headscaleInstances:
  main:
    serverUrl: https://headscale.example.com
    dnsBaseDomain: ts.example.com
    extraConfig:
      prefixes:
        v4: "100.64.0.0/10"
        v6: "fd7a:115c:a1e0::/48"
        allocation: sequential
      derp:
        urls:
          - https://controlplane.tailscale.com/derpmap/default
        auto_update_enabled: true
        update_frequency: 24h
```

Then install:

```sh
helm upgrade --install headmaster \
  oci://ghcr.io/potatonode/charts/headmaster \
  --namespace headmaster-system --create-namespace \
  -f values.yaml
```

The operator creates a `headscale-server-<name>` Service in the operator
namespace. You need an Ingress to expose it at the `serverUrl` hostname:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: headscale
  namespace: headmaster-system
spec:
  rules:
    - host: headscale.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: headscale-server-main
                port:
                  name: http
```

Instances can also be managed as standalone `HeadscaleInstance` manifests
applied directly to the cluster.

### External headscale (fork addition)

An instance can point at a headscale server managed _outside_ the cluster.
The operator then provisions nothing for it — it only verifies reachability
and uses it to mint pre-auth keys and register Ingress proxies:

```yaml
headscaleInstances:
  main:
    serverUrl: https://headscale.example.com
    dnsBaseDomain: ts.example.com
    external:
      # gRPC endpoint of the existing server (h2c URI; reachable from pods).
      grpcEndpoint: http://100.64.0.3:50443
      # Existing Secret in the operator namespace with key HEADSCALE_API_KEY.
      apiKeySecretRef: headscale-api-key
```

`external` is mutually exclusive with `policy`, `scim`, and `extraConfig`:
the external server's configuration and ACL policy stay with whoever runs
it, and the operator never calls `SetPolicy` (per-Ingress `access` grants
are therefore unavailable — manage grants in the external policy instead).

See [`examples/`](examples/) for a full values file including OIDC and SCIM
configuration.

### Per-Ingress access grants

The `access` field on the headmaster annotation lets you express who can reach
an app directly on the `Ingress`, instead of editing the shared inline policy
on `HeadscaleInstance`. Each grant specifies a set of source principals and an
optional map of app capabilities.

**Plain access grant** — allow a group to reach the app over any port:

```yaml
annotations:
  headmaster.potatonode.github.io/config: |
    {
      "headscale-ref": "main",
      "user": "alice",
      "access": [
        { "from": ["group:eng"] }
      ]
    }
```

**Capability grant** — attach roles that the app receives via the
`Tailscale-App-Capabilities` HTTP header:

```yaml
annotations:
  headmaster.potatonode.github.io/config: |
    {
      "headscale-ref": "main",
      "user": "alice",
      "access": [
        {
          "from": ["group:eng"],
          "capabilities": {
            "myapp/cap/admin": [{ "role": "admin" }]
          }
        },
        {
          "from": ["group:viewers"],
          "capabilities": {
            "myapp/cap/admin": [{ "role": "viewer" }]
          }
        }
      ]
    }
```

The operator assigns a synthetic tag `tag:hm-<namespace>-<name>` to the proxy
and uses it as the grant destination. If a `group:*` reference in `from` is not
yet synced (e.g. SCIM hasn't run), that grant is skipped and a `WaitingForGroup`
warning event is posted on the Ingress. Once the group appears, the next
reconcile applies the grant automatically.

The admission webhook validates that each access grant's `from` list is non-empty.

### Host-network proxies

By default a proxy runs on the pod network: tailscaled is pinned to UDP
41641 in-pod, a NodePort Service exposes it, and the node's LAN endpoint is
advertised (`TS_DEBUG_PRETENDPOINT`) so LAN peers can connect directly.
Off-LAN peers usually cannot — the advertised address is private, and the
pod-SNAT + site-NAT stack defeats hole punching — so they fall back to DERP.

Setting `"host-network": true` on the annotation runs the proxy pod with
`hostNetwork: true` instead. tailscaled binds the node's own network stack on
an auto-selected UDP port and discovers its endpoints natively — including
the node's global IPv6 addresses, which is what makes direct connections
from IPv6-capable peers (e.g. phones on cellular) possible:

```yaml
annotations:
  headmaster.potatonode.github.io/config: |
    {
      "headscale-ref": "main",
      "user": "alice",
      "host-network": true
    }
```

The trade-off is the pod's network isolation: the proxy shares the node's
network namespace and bypasses NetworkPolicies. The WireGuard Service turns
headless in this mode (it remains only as the StatefulSet's governing
service); toggling the field on a live Ingress recreates that Service, since
`clusterIP` is immutable.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development environment setup and
common commands.

## License

BSD-3-Clause — see [LICENSE](LICENSE).
