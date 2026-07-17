# OnionRoute: security release gates

- Статус: normative; применяется к каждому production candidate.
- Версия: 1.0.
- Дата: 2026-07-17.
- Текущее состояние: **BLOCKED** — в репозитории нет evidence об исполнении обязательной матрицы.

## 1. Политика решения

Release manager выпускает candidate только если каждый применимый gate имеет signed evidence от primary owner и
независимое подтверждение `qa/integration`/`security/threat-model`. Отсутствующий тест, неподдерживаемая platform,
flaky result, неизвестный memory budget или потерянный artifact считаются `FAIL`, а не `N/A`.

G-01…G-16 не имеют waiver для production. Security owner не может единолично принять исключение. Изменение
критерия требует ADR, обновления threat/privacy model и повторного независимого review; оно не может применяться
задним числом к текущему candidate. Rollout немедленно останавливается при post-release сигнале любого gate.

Evidence хранится неизменяемо: commit/source digest, dependency lock digest, build provenance, artifact/signature
digest, environment image, test command/config, raw test output/pcap с проверенной redaction, reviewer и timestamp.

## 2. Обязательные блокирующие критерии

| Gate | Release блокируется, если | Критерий PASS | Обязательное evidence | Primary owner / tests |
|---|---|---|---|---|
| G-01 DNS leak | Любой DNS packet/query покидает разрешённый tunnel/exit resolver path при любом lifecycle/failure | Zero unexpected DNS packets на каждом supported OS и gateway namespace во всех сценариях; system resolver недоступен в protected state | OS/gateway pcaps, resolver logs с synthetic names, state trace | `core/network-engine`; ST-004, ST-041 |
| G-02 Clearnet fallback | Любой user destination packet/socket существует вне Tor/private route при connect, rotation, outage, crash, shutdown, update или resume | Zero direct packets/sockets; uncertainty переводит в `Blocked`; Direct Tor только явный mode, не fallback | Multi-interface pcap, socket audit, fault matrix, kill-switch generations | `core/network-engine`; ST-001, ST-003, ST-009…ST-011 |
| G-03 Unsigned directory acceptance | Client принимает unsigned, wrong-key/algorithm/domain, mutated, expired, oversized или ambiguously framed catalog | Все negative fixtures reject до payload use; предыдущий valid cache не заменён; hard-expired cache не используется | Exact-byte golden corpus, mutation/fuzz output, secure-store trace | `control/directory`; ST-045, ST-046 |
| G-04 Protocol downgrade | Peer/MITM снижает major/minor/security feature или продолжает после incompatible negotiation | Highest allowed common version; required feature stripping, cross-major fallback и unknown policy enum fail closed | Bidirectional negotiation transcript/corpus, property tests | `protocol/gateway-v1`; ST-036 |
| G-05 Unbounded memory/backpressure | Input, concurrency, queue, decompression, slow peer или cancellation превышают утверждённый budget/не достигают plateau | Bounds проверяются до allocation; RSS/heap/FD/tasks plateau под worst-case soak; overload reject/close без bypass | Reviewed per-component budgets, profiler graphs, 24h soak, fuzz corpus | `protocol/gateway-v1`; ST-038, ST-042, ST-044, ST-058, ST-072 |
| G-06 SSRF / DNS rebinding | Exit соединяется с loopback, private, link-local, multicast, reserved, metadata, management, Tor-control или запрещённым адресом через literal/DNS/CNAME/rebind | Полный IPv4/IPv6 reserved corpus reject на parse, resolve и immediately-before-dial; nftables независимо блокирует; OS получает только checked IP | Controlled resolver transcripts, connect targets, namespace pcap/nft counters | `gateway/egress`; ST-039, ST-040 |
| G-07 Persistent destination logging | Destination/DNS/payload/flow port появляется в log, trace, metric, event, crash, support, backup или vendor export | Static schema/source scan и dynamic canary find zero occurrences после normal/error/debug/incident paths; volatile state purged ≤60s | Canary corpus, storage/export scan, redaction manifest, backup scan | `security/threat-model`; ST-014, ST-027, ST-041, ST-064…ST-071 |
| G-08 Hardcoded secrets | Source/history/build/image/SBOM/test fixture содержит production-capable secret или deterministic default | Secret scanners clean; runtime secret provenance только approved KMS/secure store; rotation drill successful | Multi-engine scan, image filesystem scan, provenance, revoke/rotation record | `infra/platform`; ST-063 |
| G-09 Updater signature verification | Updater устанавливает unsigned/wrong-channel/wrong-platform/mutated/rollback/freeze metadata или доверяет transport TLS alone | Pinned offline root + threshold metadata + artifact hash/signature + monotonic version проверены до write; failure keeps last verified version | Offline negative corpus, rollback/freeze test, root/threshold ceremony record | `infra/platform`; ST-059, ST-060 |
| G-10 Gateway public user ingress | User data-plane listener достижим с public/VPC peer вне Tor frontend или approved mTLS gateway network | External/VPC scans show no user listener; exit accepts loopback Tor frontend only; inter-gateway endpoints require role mTLS; namespace egress is explicit | IaC review, runtime socket inventory, external/VPC scans, SG/nft dump | `gateway/egress`; ST-032, ST-033, ST-035 |
| G-11 Token expiry verification | Gateway принимает expired, too-long, not-yet-valid, wrong issuer/audience/role/scope token или verifier timeout | Signature/profile/issuer/audience/scope/role/`iat`/`nbf`/`exp`/max 15m lifetime checked offline; clock skew max 5m; any error reject | Crypto fixtures, boundary clock tests, reject-all failure injection | `control/auth-tokens`; ST-051…ST-058 |
| G-12 IPv6/WebRTC/QUIC containment | IPv6, UDP STUN/TURN, QUIC или unknown transport выходит напрямую | Zero unexpected packets per supported OS/interface; supported DNS only on protected path; unknown transport blocks | App/browser matrix pcaps including extension headers and interface changes | `core/network-engine`; ST-005…ST-007 |
| G-13 Directory/root and gateway identity | Rollback, targeted wrong pin/role, unauthorized next key или same-sequence equivocation принимаются | Monotonic persistent sequence, exact payload equality, valid preauthorized rotation, pin+role+onion binding; corruption fail closed | Rotation/rollback/equivocation fixtures, storage power-loss tests | `control/directory`; ST-030, ST-034, ST-046…ST-049 |
| G-14 Privacy separation and deletion | Есть payment-to-session join, user-level network analytics, small cohort, TTL breach или restored expired record | No common/direct/quasi join; `k>=100` before analyst; TTL/restore tests pass; access roles physically separated | Schema/IAM/warehouse diff, synthetic join test, deletion/restore report | `security/threat-model`; ST-054, ST-055, ST-066…ST-071 |
| G-15 Supply-chain/release integrity | Build не имеет reviewed lock/SBOM/provenance, artifact не воспроизводим в пределах documented variance, Tor/PT не manifest-bound, critical dependency issue открыт | Protected hermetic build, two-person release, signed provenance/SBOM, dependency review, runtime Tor/PT hash binding; zero unresolved critical | CI/IAM audit, independent rebuild/diff, signatures, dependency scan | `infra/platform`; ST-061, ST-062 |
| G-16 Critical design/review completeness | Token crypto не reviewed, critical threat без owner/treatment, mandatory test missing, critical vuln открыт или claims обещают global-observer protection | Independent crypto/security review closed; 74 threats owned; all mandatory tests green; no open Critical/High privacy leak; claims limitations approved | Review reports, threat/test traceability check, release sign-off | `security/threat-model`; ST-019…ST-024, ST-056 |

На дату документа G-16 дополнительно заблокирован конфликтом между ADR-0003 и описанным в
[auth-tokens component review](auth-tokens-threat-model.md) не-blind MVP issuance. Организационное разделение
issuer/account не эквивалентно blind issuance и не закрывает T-054/T-056.

## 3. Обязательная pre-release последовательность

1. Freeze source/dependency locks and schemas; generate SBOM and provenance candidate.
2. Static gates: secret scan, schema/privacy scan, import/data-flow boundary scan, unsafe/dependency review.
3. Unit/property/golden/fuzz tests for parser, protocol, directory, tokens and state machines.
4. Integration tests in isolated hostile network: SSRF, rebinding, role/pin/mTLS, replay, downtime and overload.
5. Platform leak tests на **каждой** supported OS/version: DNS, IPv6, WebRTC, QUIC, clearnet, captive portal,
   sleep/resume, network changes, crash/update/uninstall.
6. Gateway namespace/IaC tests from Internet and peer VPC, then 24-hour bounded-resource soak.
7. Privacy canary, cross-store join, TTL deletion и clean-room backup restore.
8. Independent updater/supply-chain verification and rebuild.
9. Security review checks evidence against [security test matrix](security-test-matrix.md); release manager verifies no `N/A`.
10. Canary rollout with automatic stop on leak, unexpected listener, auth bypass, memory slope or privacy-schema drift.

## 4. Environment coverage

- Каждая заявленная desktop/mobile OS, minor version и network extension/firewall backend.
- IPv4-only, IPv6-only, dual stack, NAT64, multiple interfaces, Wi-Fi↔cellular/Ethernet, captive portal.
- Clean install, upgrade, rollback attempt, corrupted secure storage, crash, power loss, sleep/resume и uninstall.
- Standard, Enhanced, Maximum и явный Direct Tor; forbidden fallback между modes.
- Gateway entry/relay/exit roles, single/multi-cloud failure domains, DNS/auth/KMS outage и draining.
- Release и debug-symbol configurations; production artifact тестируется повторно после signing/notarization.

## 5. Stop-ship и post-release response

Любой наблюдённый DNS/IPv6/QUIC/clearnet leak, auth bypass, unsigned directory/update, destination persistence или
public gateway ingress — incident severity Critical. Rollout останавливается, affected artifacts/keys отзываются,
kill-switch остаётся engaged, privacy incident process запускается. Для сохранения evidence нельзя включать raw
destination logging; используются synthetic canaries, coarse state и локальная добровольная диагностика.

Release возобновляется только новым artifact с полным повтором применимых gates, а не hot config, ослабляющим
fail-closed policy.
