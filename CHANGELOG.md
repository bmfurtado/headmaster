# Changelog

## [0.3.0](https://github.com/bmfurtado/headmaster/compare/v0.2.0...v0.3.0) (2026-08-06)


### Features

* consumers allowlist for egress Services ([3430e78](https://github.com/bmfurtado/headmaster/commit/3430e78119dec2e6c72b30d681b79731aa299fba))
* expose ExternalName Services on the tailnet ([f1001de](https://github.com/bmfurtado/headmaster/commit/f1001deb3e1e33baeccede3b3ae80d93f56c2fb5))
* expose Services on the tailnet, with a tun mode for high bandwidth ([e930529](https://github.com/bmfurtado/headmaster/commit/e930529e6372ad57849ced8b8d0f29ed828adb5e))
* external headscale mode — point an instance at a server outside the cluster ([b301186](https://github.com/bmfurtado/headmaster/commit/b3011863d58d4defcd39d7e3d88065907e651bc7))
* mode tun on Ingresses — kernel tailscaled under the serve config ([168d895](https://github.com/bmfurtado/headmaster/commit/168d895f5d697630b224087e0ad92bae991483d7))
* operator-managed CoreDNS rewrites for tailnet egress ([b4c0f9f](https://github.com/bmfurtado/headmaster/commit/b4c0f9fff08d49ca4c0f038cdf54dd85d3add0f9))
* opt-in host-network mode for Ingress proxies ([0124593](https://github.com/bmfurtado/headmaster/commit/0124593e8c512b4971636f7ad8d5badbbbcd2c7a))
* tailnet egress — reach tailnet hosts from k8s pods ([4ca9db5](https://github.com/bmfurtado/headmaster/commit/4ca9db570c266d5d4a938579a34c73e7ed4acbe7))


### Bug Fixes

* **ci:** create GitHub Release before chart upload if missing ([6f7214e](https://github.com/bmfurtado/headmaster/commit/6f7214ed696a0810089ababdbc13602d686a2a8c))
* **deps:** update rust dependencies ([#55](https://github.com/bmfurtado/headmaster/issues/55)) ([6466f96](https://github.com/bmfurtado/headmaster/commit/6466f967c0d32429859e1ba20ab46150116993d2))
* egress DNS watch needs list/watch on kube-system configmaps ([eaf5cc4](https://github.com/bmfurtado/headmaster/commit/eaf5cc485860ab773fb6399ff584a109a72d0062))
* k8s-openapi Time wraps jiff, not chrono — as_second() ([3d05647](https://github.com/bmfurtado/headmaster/commit/3d056470e6e5f5cc879d4e3898b3c8e2146617ac))
* operator Role missing networkpolicies verbs for the consumers feature ([b8ec6b6](https://github.com/bmfurtado/headmaster/commit/b8ec6b6ef98a03985b4d367a28facd615006ab66))
* recover proxies stuck on a dead auth key, watch proxy StatefulSets ([af29a7e](https://github.com/bmfurtado/headmaster/commit/af29a7efe378f941ec73fc0d551c24ba1bfdde52))
* recover proxies stuck on a dead auth key, watch proxy StatefulSets ([5e568c0](https://github.com/bmfurtado/headmaster/commit/5e568c01452badd11be5477ab6e99bc9bd35f356))
* resync egress DNS when coredns-custom changes externally ([82a1628](https://github.com/bmfurtado/headmaster/commit/82a16286d5fa8435770e54f5876fb37e1704ecf6))
* rotate the auth key when headscale refuses a healthy-looking node ([f375df0](https://github.com/bmfurtado/headmaster/commit/f375df0547a24e7466d1d6221cb381a2f6c6f3bf))
* rotate the auth key when headscale refuses a healthy-looking node ([d7829a1](https://github.com/bmfurtado/headmaster/commit/d7829a10a8758e6200205a041b42968d5bc4e880))
* seed fake headscale nodes in functional tests that claim a device_id ([4932c7d](https://github.com/bmfurtado/headmaster/commit/4932c7d782ae31f93ad835b5b4f6de54dffc961a))
* skip SetTags for tag-less proxies; allow cluster-wide Service reads ([fd71cf8](https://github.com/bmfurtado/headmaster/commit/fd71cf831d5a5e2de673dfa9428989b6146879d1))

## [0.2.0](https://github.com/potatonode/headmaster/compare/headmaster-v0.1.0...headmaster-v0.2.0) (2026-07-07)

Initial release.
