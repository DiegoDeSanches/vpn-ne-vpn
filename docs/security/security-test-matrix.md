# OnionRoute: security test matrix

- Статус: mandatory specification; **execution evidence отсутствует, все tests считаются NOT RUN**.
- Версия: 1.0.
- Дата: 2026-07-17.
- Правило: каждый `ST-*` выполняется на production-equivalent signed artifact; mock-only результат не закрывает gate.

`Pcap` означает capture на всех физических/виртуальных interfaces и внутри соответствующего namespace. В test
evidence synthetic identifiers допускаются только из fixture manifest; после теста scanner подтверждает отсутствие
их в logs/metrics/traces/backups. Fuzz/soak corpus и seeds сохраняются с artifact digest.

## 1. Endpoint и local enforcement

| Test / threat | Тип и метод | PASS criterion | Environment / evidence | Primary owner / gate |
|---|---|---|---|---|
| ST-001 / T-001 | Adversarial app открывает TCP/raw sockets через все interfaces/namespaces во всех tunnel states | Нет direct destination packet/socket; только protected connector; unknown path blocked | OS matrix, socket inventory, pcap | `core/network-engine` / G-02 |
| ST-002 / T-002 | IPC fuzz + wrong peer credentials + replay/stale generation + arbitrary command injection | Helper принимает только authenticated OS peer и fixed policy; stale/unknown command reject | Platform helper integration, IPC transcript | `client/desktop` / G-02 |
| ST-003 / T-003 | Nanosecond-order fault injection между route/firewall/TUN/verify во время connect/reconfigure | Ни один synthetic destination packet не выходит; state `Blocked` при uncertainty | Deterministic scheduler + multi-interface pcap | `core/network-engine` / G-02 |
| ST-004 / T-004 | Synthetic unique DNS names через system APIs/browser при connect, rotation, Tor/DNS crash, shutdown | Zero DNS вне protected/approved exit path; system resolver calls fail closed | Каждая OS, pcap + authoritative test resolver | `core/network-engine` / G-01 |
| ST-005 / T-005 | IPv6-only/dual/NAT64, fragments и extension headers, AAAA destinations | Zero user IPv6 packets; unsupported IPv6 deterministically blocked | OS/network matrix pcap | `core/network-engine` / G-12 |
| ST-006 / T-006 | Browser/app WebRTC ICE с STUN/TURN UDP/TCP candidates | Нет host/server-reflexive direct UDP/TURN bypass; only explicitly protected TCP behavior | Browser versions + LAN/Internet STUN canary pcap | `client/desktop` / G-12 |
| ST-007 / T-007 | HTTP/3/QUIC preferred и forced TCP failure | QUIC/UDP blocked; application может перейти только на protected TCP, не direct | Browser/curl test, pcap | `core/network-engine` / G-12 |
| ST-008 / T-008 | Allowlisted app, child/helper, exec, PID/UID reuse, symlink/path/signature spoof | Только определённая OS identity bypasses до TUN; ambiguous attribution blocked | Platform-specific process lifecycle suite | `client/desktop` / G-02 |
| ST-009 / T-009 | Captive portal до/во время tunnel, timeout/crash/user cancel | Portal workflow never globally opens protected traffic; after exit rules verified before connect | Controlled portal + pcap/state trace | `client/desktop` / G-02 |
| ST-010 / T-010 | Repeated sleep/resume, hibernate, Wi-Fi/cell/Ethernet/VPN switch, DHCP/route change | Before any user packet new interface is blocked and leases/routes reverified; fresh Tor isolation as required | 1 000 transition soak per OS + pcap | `core/network-engine` / G-02,G-12 |
| ST-011 / T-011 | Kill client/helper/Tor at every state; power loss, uninstall, concurrent stale process | Recovery starts blocked; stale lease cannot remove current rules; uninstall follows explicit safe policy | Fault/power-loss harness + firewall snapshots | `client/desktop` / G-02 |
| ST-012 / T-012 | Probe/attach Tor SOCKS/control/data dir as another local user/process; steal wrong cookie | All access rejected; ACL/mode verified before spawn; contexts remain isolated | Unix/Windows ACL tests, Tor transcript | `core/tor-backend` |
| ST-013 / T-013 | Secure-store theft simulation, corrupt value, rollback snapshot, token/root substitution | Secrets unreadable to normal peer; corruption/rollback fail closed; root never auto-reset | OS secure-store + restore/power-loss suite | `architecture/contracts` / G-13 |
| ST-014 / T-014 | Crash/panic/support bundle in every sensitive state with synthetic token/DNS/destination canaries | Canary absent in dumps/logs/bundle/vendor queue; manifest shown; server auto-delete verified | Production crash config + storage scanner | `client/desktop` / G-07 |

## 2. Tor и correlation resistance

| Test / threat | Тип и метод | PASS criterion | Environment / evidence | Primary owner / gate |
|---|---|---|---|---|
| ST-015 / T-015 | ISP censorship/throttle/reset/bootstrap fault simulation | No clearnet fallback; bridge/PT policy behaves as documented; UX states Tor detectability | Controlled WAN faults + pcap | `core/tor-backend` / G-02,G-16 |
| ST-016 / T-016 | Inspect Tor guard-facing traces and client logs across identities | No account/gateway/destination fields reach Tor backend; guard visibility limitation documented | Instrumented Tor testnet + schema scan | `core/tor-backend` / G-16 |
| ST-017 / T-017 | Relay injects delay/drop/reorder/selective failures and malformed responses | TLS integrity holds, no downgrade/fallback; bounded retry avoids forced churn | Private Tor testnet adversarial relay | `core/tor-backend` / G-02,G-16 |
| ST-018 / T-018 | Selectively fail circuits/guards over long simulation | Client preserves Tor guard policy and bounded backoff; does not rotate until attacker-selected peer outside Tor policy | Deterministic Tor integration/simulation | `core/tor-backend` / G-16 |
| ST-019 / T-019 | Two-ended trace correlation benchmark over representative traffic | Report quantifies attacker accuracy/false positives; claims explicitly state protection not guaranteed; no pass claim based on multihop alone | Lab access+egress capture, reproducible notebook | `security/threat-model` / G-16 |
| ST-020 / T-020 | Active watermark/controlled-fetch experiments with delay and burst injection | Integrity unaffected; measured confirmation susceptibility documented; no unsafe countermeasure/fallback | Isolated traffic-analysis lab | `security/threat-model` / G-16 |
| ST-021 / T-021 | Website/flow fingerprint benchmark across modes | Publish measured leakage and confidence; any padding claim has separate ADR/budget/test | Synthetic site corpus, classifier report | `security/threat-model` / G-16 |
| ST-022 / T-022 | Route/country/mode distribution and metadata uniqueness analysis without user network data | No route violates approved failure domains; rare mode/capability UX and risk documented | Synthetic catalog + account-side aggregate only | `core/tor-backend` / G-14,G-16 |
| ST-023 / T-023 | Rotate under long/short flows; correlate old/new sessions, tokens, DNS cache and isolation | New flows use fresh isolation/token/DNS; old flows drain bounded; overlap/resource limits hold | Instrumented Tor/gateway testnet | `core/tor-backend` / G-05,G-16 |
| ST-024 / T-024 | UX/security test with cookies/login/fingerprint before/after New Identity | UI never claims app identity cleared; warning shown before action and docs cover limitation | Product acceptance + automated UI snapshot | `product/documentation` / G-16 |

## 3. Gateway, protocol и egress

| Test / threat | Тип и метод | PASS criterion | Environment / evidence | Primary owner / gate |
|---|---|---|---|---|
| ST-025 / T-025 | Compromised-entry harness records everything available and injects failures | Terminal DNS/destination/payload unavailable; no unsafe retry/fallback; only bounded timing metadata | Multihop testnet + entry capture | `gateway/multihop` / G-16 |
| ST-026 / T-026 | Compromised relay introspection/delay/drop/replay | Relay cannot decode terminal frames or act as exit; teardown bounded | Maximum-mode testnet | `gateway/multihop` / G-05,G-16 |
| ST-027 / T-027 | Malicious-exit canary/error/debug test | Destination is only volatile during flow, absent from all persistence; UX documents exit visibility | Exit memory lifecycle + storage/export scan | `gateway/egress` / G-07,G-16 |
| ST-028 / T-028 | Failure-domain/IAM/cloud graph audit + colluding trace experiment | Enhanced/Maximum policy rejects same prohibited admin/cloud domain; residual correlation measured | IaC inventory + two-ended traces | `infra/platform` / G-16 |
| ST-029 / T-029 | Cloud snapshot, flow-log, serial console, host-agent and IAM review | Disk encrypted, flow/content logging off, keys non-exportable where possible, roles separated; exceptions block release | Cloud config dump + access drill | `infra/platform` / G-14,G-15 |
| ST-030 / T-030 | Catalog includes validly signed but policy-malicious/wrong-domain gateway | Four-eyes policy rejects before signing/client selection; incident removal drill works | Staging publisher/signing ceremony | `control/directory` / G-13 |
| ST-031 / T-031 | Authorized/unauthorized catalog/onion enumeration and targeted load | Unauthorized probes learn no usable ingress; load isolated; signed removal no fallback | External red-team testnet | `infra/platform` / G-10,G-16 |
| ST-032 / T-032 | Internet/VPC/host scans all TCP/UDP, alternate interfaces and restarts | No public user listener; only loopback Tor frontend and explicit role-mTLS peer listener | Independent external scan + socket/nft/SG inventory | `gateway/egress` / G-10 |
| ST-033 / T-033 | Send terminal TCP/DNS to entry/relay; spoof roles/OpenRelay; attempt Internet dial | Wrong-role frames reject and namespace cannot dial; exit-only policy independently enforced | Role matrix + namespace pcap | `gateway/multihop` / G-10 |
| ST-034 / T-034 | Wrong SPKI/onion/gateway ID/role/cert chain and valid cert for other gateway | Every mismatch closes before token/flow; no alternate endpoint | TLS negative fixtures/transcripts | `protocol/gateway-v1` / G-13 |
| ST-035 / T-035 | mTLS expired/revoked/wrong-role/cross-env cert, stolen old key and rotation | Only current role/env identity accepted; revoke/rotation bounded; no plaintext fallback | Gateway PKI integration + drill | `infra/platform` / G-10,G-15 |
| ST-036 / T-036 | MITM/peer strips feature, changes range/selected minor, unknown enum/major, retries lower version | Required feature/major mismatch rejects; highest allowed common chosen; no automatic lower-session retry | Golden/property/fuzz negotiation corpus | `protocol/gateway-v1` / G-04 |
| ST-037 / T-037 | Replay duplicate/out-of-order/wrap frame, session ID, open/auth across connections | Strict monotonic sequence/session binding; duplicate/replay closes; no side effect | Protocol integration + property model | `protocol/gateway-v1` / G-11 |
| ST-038 / T-038 | Length/allocation bombs, max streams, credit abuse, cancellation race, 24h hostile fuzz/soak | Pre-allocation reject; no panic; reviewed heap/RSS/FD/task plateau; recovery releases resources | Sanitizers/profilers/fuzz artifacts | `protocol/gateway-v1` / G-05 |
| ST-039 / T-039 | Exhaustive IPv4/IPv6 special-use, numeric encodings, localhost names, metadata/management targets | App validation and nftables both block; zero SYN to forbidden address | Namespace test resolver/server + pcap/counters | `gateway/egress` / G-06 |
| ST-040 / T-040 | Controlled DNS changes A/AAAA/CNAME between every resolve/check/dial step | Every returned address validated; final direct IP is second checked answer; any forbidden answer rejects | Authoritative rebinding harness + pcap | `gateway/egress` / G-06 |
| ST-041 / T-041 | Disable approved resolver, poison system resolver, inspect all gateway interfaces/logs | Query only to approved namespace upstream; outage rejects; no query persistence | Gateway namespace pcap + resolver canaries | `gateway/egress` / G-01,G-07 |
| ST-042 / T-042 | Invalid/valid connection storms, slow TLS/auth/DNS/open under constrained resources | Cheap bounded reject, fair quotas, no auth bypass; resource plateau and recovery within SLO | Distributed isolated load + profiler | `gateway/egress` / G-05 |
| ST-043 / T-043 | SMTP/25, BitTorrent corpus, blocked admin ports across hostnames/IP and fragmentation attempts | Application policy and nftables deny; no destination stored; allowed TCP unaffected | Synthetic services + pcap/log scan | `gateway/egress` |
| ST-044 / T-044 | Upstream endless/slow/half-close/RST/oversized patterns after client cancellation | Fixed reverse buffer, deadlines, complete task/FD cleanup, no cross-stream corruption | Malicious upstream harness, 24h soak | `gateway/egress` / G-05 |

## 4. Directory, control и tokens

| Test / threat | Тип и метод | PASS criterion | Environment / evidence | Primary owner / gate |
|---|---|---|---|---|
| ST-045 / T-045 | Exact-byte directory golden + mutations: unsigned, wrong key/alg/domain, trailing/oversize, decode ambiguity | Verify bounded envelope/signature before decode; every mutation reject and valid cache unchanged | Unit/property/fuzz corpus | `control/directory` / G-03 |
| ST-046 / T-046 | Expiry/clock skew/backward jump, sequence rollback, same-sequence different payload, store corruption/power loss | Old/expired/equivocating/corrupt state fail closed; atomic highest sequence survives | Fake clock + secure-store fault injection | `control/directory` / G-03,G-13 |
| ST-047 / T-047 | Directory signing key compromise tabletop + attempted single-admin signing | Offline/threshold/two-person controls prevent single-role issuance; revoke/publish drill meets documented bound | KMS/IAM logs, ceremony evidence | `control/directory` / G-13,G-15 |
| ST-048 / T-048 | Next-key, premature/expired/revoked key, emergency root and updater-root substitution | Only preauthorized valid rotation accepted; emergency replacement requires verified product update/reprovisioning | Golden fixtures + operational drill | `control/directory` / G-13 |
| ST-049 / T-049 | Publisher serves distinct valid catalogs/sequence histories to clients/monitors | Equivocation is detected within defined bound and blocks affected catalogs/rollout; no unique client targeting field | Transparency/gossip testbed; blocks until design exists | `control/directory` / G-13 |
| ST-050 / T-050 | DDoS/partition directory/control through cache expiry | Valid cache works only to hard expiry; after expiry client blocks, never accepts old/unsigned/fallback | WAN fault test + state trace | `infra/platform` / G-02,G-03 |
| ST-051 / T-051 | Same token concurrent/sequential redemption, replay after restart and on another gateway | Exactly one allowed per defined semantics; atomic nullifier; replay reject; state expires bounded | Multi-gateway race harness | `control/auth-tokens` / G-11 |
| ST-052 / T-052 | Expired, future, >15m lifetime, ±clock skew, wrong issuer/audience/role/scope/signature | All invalid profiles reject; only ≤15m valid token within max 5m skew accepted | Crypto/boundary fixtures | `control/auth-tokens` / G-11 |
| ST-053 / T-053 | Reuse token across entry/relay/exit, route/identity and capability escalation | Scope/hop/role binding rejects reuse; independently issued tokens have no common external ID | Multihop auth integration | `control/auth-tokens` / G-11,G-14 |
| ST-054 / T-054 | Compromised control/issuer linkage и synthetic issuance/redemption timing attack under low/high load | Standard blind issuance скрывает unblinded token от account/control path; batching/coarsening даёт approved anonymity threshold; нет deterministic linkage/shared IDs | Crypto transcript + privacy lab dataset, attack precision report | `control/auth-tokens` / G-14 |
| ST-055 / T-055 | Enumerate token capability/TTL/issuer combinations against subscription catalog | Only approved coarse profiles; each profile account-side cohort ≥1 000/30d; no payment/country/A-B fingerprint | Schema/catalog policy test | `control/auth-tokens` / G-14 |
| ST-056 / T-056 | Independent crypto review, standard test vectors, malicious issuer/tagging/unlinkability/forge tests | Reviewed standard scheme/library; all vectors/proofs pass; no custom primitive; findings closed | External report + reproducible vectors | `control/auth-tokens` / G-11,G-16 |
| ST-057 / T-057 | Issuer old/stolen/revoked key and emergency rotation | Old/revoked issuer rejected by deadline; mint blast radius bounded by ≤15m TTL; no account lookup fail-open | KMS/key distribution drill | `control/auth-tokens` / G-11,G-15 |
| ST-058 / T-058 | Parallel nullifier races and unique-nullifier memory/storage flood | Atomic single redemption; bounded state/queue; expiry purge; RSS/storage plateau; overload rejects | Race/property/load test | `control/auth-tokens` / G-05,G-11 |

## 5. Operations, supply chain, privacy и abuse

| Test / threat | Тип и метод | PASS criterion | Environment / evidence | Primary owner / gate |
|---|---|---|---|---|
| ST-059 / T-059 | Update negative corpus: unsigned, wrong key/channel/platform, altered artifact/metadata, TLS MITM | No file/install state change before full pinned threshold/hash/signature verification; old verified client remains | Offline updater lab + filesystem snapshots | `infra/platform` / G-09 |
| ST-060 / T-060 | Serve old signed metadata/artifact, freeze timestamp/snapshot, clock rollback | Monotonic version/fresh metadata enforced; freeze detected; recovery never installs older vulnerable version | Updater time/rollback harness | `infra/platform` / G-09 |
| ST-061 / T-061 | Dependency/runner/maintainer compromise simulation and independent clean rebuild | Protected review/lock prevents unauthorized source; signed provenance/SBOM match; rebuild diff explained; no critical finding | Isolated CI/rebuilder + IAM audit | `infra/platform` / G-15 |
| ST-062 / T-062 | Replace Tor/PT binary/config after install and before spawn; wrong platform binary | Runtime signed manifest/hash/provenance check rejects before execution; app remains blocked | Production package tamper suite | `core/tor-backend` / G-15 |
| ST-063 / T-063 | Secret scan full history/source/generated/build/image/SBOM plus runtime provenance | Zero production-capable/hardcoded/default secrets; all runtime keys originate approved store and rotate | Multiple scanners + image mount + KMS audit | `infra/platform` / G-08 |
| ST-064 / T-064 | Malicious admin attempts deploy/config of destination log/packet capture/export | Schema/CI/SoD deny; immutable alert; no canary reaches persistence; two colluding roles documented residual | Policy-as-code red-team + canary scan | `infra/platform` / G-07,G-14 |
| ST-065 / T-065 | Enable every production error/debug/incident flag during synthetic sensitive traffic | Closed schema remains; no raw canary; core/packet capture disabled; temporary stores obey TTL | Production config matrix + storage scan | `infra/platform` / G-07 |
| ST-066 / T-066 | Static/dynamic schema graph and synthetic cross-layer join using IDs/times/capabilities | No common ID/key; temporal/capability linkage below approved threshold; exact clocks coarsened | Data-flow manifest + joinability report | `security/threat-model` / G-14 |
| ST-067 / T-067 | Attempt join billing/account/issuance to redemption/health via fields, IAM, warehouses, backups | No credential/path/common or quasi-unique field; forbidden network routes fail; queries impossible by one role | IAM/network/schema/store audit | `control/auth-tokens` / G-14 |
| ST-068 / T-068 | Inject cohorts k=1…99 and rare label combinations; analyst query attempts drill-down | Suppress/merge before analyst; only k≥100 coarse buckets; no arbitrary label/query | Telemetry integration + analyst role test | `infra/platform` / G-14 |
| ST-069 / T-069 | Seed canaries in each allowed TTL dataset/queue/replica/export/backup, expire, clean-room restore | No record older TTL+10%; restored system deletes before network; deletion evidence contains no subject data | Time-travel + quarterly restore report | `infra/platform` / G-07,G-14 |
| ST-070 / T-070 | IAM/console/snapshot/KMS red-team for cloud and malicious admin | Least privilege/JIT/MFA/SoD/non-exportable keys; denied paths; break-glass ≤TTL and alerted | Multi-cloud control-plane drill | `infra/platform` / G-14,G-15 |
| ST-071 / T-071 | Inject forbidden canaries/arbitrary labels; inspect every collector/vendor/export/DLQ | Schema rejects before export; allowlisted endpoints only; no raw canary; vendor roles cannot cross-join | Egress capture + vendor config/storage scan | `infra/platform` / G-07,G-14 |
| ST-072 / T-072 | Distributed control/directory/token request flood incl. malformed/expensive issuance | Bounded queue/RAM/DB, cheap reject/fairness; valid sessions/cache unaffected as designed; no auth/fallback relaxation | Isolated distributed load, profiler | `infra/platform` / G-05 |
| ST-073 / T-073 | Synthetic scan/DDoS/credential fanout with valid tokens; inspect anti-abuse state | Coarse 10m throttle works; no destination/user history/export; normal traffic fairness meets budget | Closed victim lab + memory/log scan | `gateway/egress` / G-05,G-07 |
| ST-074 / T-074 | Token sharing/resale/concurrency/quota bypass across gateways | Replay/scope/concurrency bound enforced without device/account ID; overload rejects; no stable fingerprint introduced | Multi-client/multi-gateway load | `control/auth-tokens` / G-05,G-11,G-14 |

## 6. Fuzzing и длительность

- Parser, gateway framing, directory envelope/payload, token decoder, DNS/CNAME и privileged IPC fuzzers выполняются
  с sanitizers где применимо, seed corpus versioned и минимум 24 часа aggregate CPU на release candidate.
- Ни одного panic, UB, OOM, unbounded allocation/task/FD, timeout hang или semantic fail-open.
- Resource soak минимум 24 часа при max allowed concurrency плюс adversarial slow peer; memory/FD/task slope после
  warm-up должен статистически соответствовать нулю в рамках reviewed tolerance. Само значение tolerance и budget
  утверждается до запуска; отсутствие budget — FAIL.
- Любой найденный crash добавляется как minimized permanent regression fixture.

## 7. Evidence и traceability checks

Автоматическая проверка release package должна подтвердить:

1. `T-001…T-074` встречаются в threat model и каждый ссылается ровно на существующий `ST-*`.
2. `ST-001…ST-074` имеют owner, PASS criterion и сохранённый result для текущего artifact digest.
3. Все G-01…G-16 имеют только PASS и независимого reviewer.
4. Ни один result не помечен `skipped`, `allowed failure`, `flaky`, `mock only` или `N/A` для supported scope.
5. Pcap/log/test evidence прошёл privacy redaction scan до загрузки в evidence store.
