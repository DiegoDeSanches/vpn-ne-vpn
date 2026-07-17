# Architecture Decision Records

| ADR | Решение | Статус |
|---|---|---|
| [0001](0001-control-data-plane-separation.md) | Жёсткое разделение control plane и data plane | Accepted |
| [0002](0002-fail-closed-kill-switch.md) | Kill switch до любой сетевой сессии и fail-closed recovery | Accepted |
| [0003](0003-anonymous-capability-tokens.md) | Blind-issued short-lived capability tokens | Accepted, algorithm pending security review |
| [0004](0004-versioned-protobuf-contracts.md) | Protobuf v1 + explicit runtime negotiation | Accepted |
| [0005](0005-signed-gateway-directory.md) | Exact-byte Ed25519 signed gateway directory | Accepted |
| [0006](0006-make-before-break-rotation.md) | Make-before-break identity rotation | Accepted |
| [0007](0007-tor-backend-abstraction.md) | Runtime-neutral TorBackend, C Tor first and Arti later | Accepted |
| [0008](0008-multihop-terminal-encryption.md) | Opaque entry/relay and terminal TLS at exit | Accepted |
| [0009](0009-bounded-tcp-proxy-engine.md) | Bounded tun2socks-style TCP proxy engine for MVP | Accepted for MVP |
| [0011](0011-private-exit-gateway-fail-closed-egress.md) | Fail-closed private exit gateway egress boundary | Proposed, experimental |
| [0013](0013-mvp-pop-capability-tokens.md) | Short-lived role-scoped PoP capability tokens for MVP | Proposed, experimental |
| [0012](0012-immutable-multi-provider-platform.md) | Immutable multi-provider platform and workload-identity secret delivery | Proposed, experimental |
| [0014](0014-control-plane-ingress-and-signing-isolation.md) | Separate control API ingresses and offline-root trust | Accepted |
| [0017](0017-github-releases-for-binary-artifacts.md) | Immutable GitHub Releases for signed binary artifacts | Accepted |

ADR immutable после `Accepted`: изменение решения создаёт новый ADR со ссылкой
`Supersedes`. Любое изменение public contract, dependency direction, криптографии,
trust boundary или fail-closed semantics требует ADR до merge.
