# Integration test plan OnionRoute v1

Цель — позволить командам реализовывать компоненты независимо через
`common-types::contracts::v1` и заменить mock на real implementation без изменения
оркестратора или соседних public APIs.

## 1. Уровни проверки

1. **Static contract**: formatting/lint Rust, protobuf lint/breaking, dependency DAG,
   forbidden-field scan, docs/ADR links.
2. **Unit**: parser/state/error/policy/limits каждого компонента, без сети.
3. **Contract**: одна test suite запускается для mock и каждой implementation trait.
4. **Component integration**: real component + mocks всех зависимостей.
5. **End-to-end namespace/lab**: platform tunnel → Tor test network → private gateway
   chain → controlled Internet fixtures.
6. **Leak/security/fuzz**: packet capture, fault injection, hostile protobuf/DNS/IP,
   privilege boundaries, key/token replay.
7. **Performance/soak**: memory/backpressure, latency, rotation и долгие sessions.

Production promotion требует прохождения 1–6; performance budgets 7 утверждаются
до public beta.

## 2. Общий test harness

`tests/integration` содержит orchestrator scenarios, `tests/leak-tests` — pcap и OS
route assertions, `tests/security` — hostile/fault scenarios, `tests/performance` —
criterion/load/soak definitions. Harness предоставляет:

- deterministic clock и entropy source только для tests;
- controllable fake packet tunnel;
- ephemeral Tor test network с v3 onion services;
- fake control plane для signed directory и blind-token fixtures;
- 1/2/3-hop gateway topology в изолированных network namespaces/VM;
- controlled DNS and TCP echo/HTTP/TLS destinations;
- packet capture на physical, TUN, Tor, inter-gateway и exit interfaces;
- fault proxy: latency, loss, half-close, truncation, replay, oversized frames;
- no-network assertions для fail-closed phases;
- redaction sink, который проваливает test при forbidden fields.

Test keys, onion identities и tokens имеют явный `TEST ONLY` marker. Они никогда не
используются в production images.

## 3. Mock strategy

Feature `onionroute-common-types/test-utils` публикует deterministic mocks всех
обязательных contracts:

| Contract | Mock | Управляемое поведение для component tests |
|---|---|---|
| `TorBackend` | `MockTorBackend` | ready bootstrap, memory streams; fault wrapper добавит timeout/failure |
| `CircuitManager` | `MockCircuitManager` | deterministic leases и rotation candidate |
| `GatewayConnector` | `MockGatewayConnector` | active anonymous session, TCP memory stream, DNS echo |
| `PacketEngine` | `MockPacketEngine` | explicit bounded event queue |
| `DnsEngine` | `MockDnsEngine` | только explicit active gateway session, без system resolver |
| `PolicyEngine` | `MockPolicyEngine` | role selection, SMTP/25 deny, protected DNS |
| `KillSwitch` | `MockKillSwitch` | generation lease, verify, recovery, stale-lease error |
| `SecureStorage` | `MockSecureStorage` | atomic in-memory logical keys, redacted values |
| `GatewayDirectoryProvider` | `MockGatewayDirectoryProvider` | pre-verified cache/refresh result |
| `TokenProvider` | `MockTokenProvider` | bounded anonymous token |
| `HealthReporter` | `MockHealthReporter` | closed-schema event capture/purge |

Mocks не утверждают криптографическую, privacy или performance корректность. Каждая
команда добавляет configurable fault wrapper вокруг trait, а не изменяет mock public
API. Real implementation проходит тот же contract suite.

## 4. Contract suites по компонентам

### TorBackend

- progress 0..100 monotonic; `ready` только после bootstrap;
- v3 onion stream использует isolation key; разные keys не делят circuit policy;
- deadline/cancel/shutdown освобождает resources;
- Direct Tor вызывается только для explicit `DirectTor` route;
- backend error не содержит relay/onion/IP details в shared diagnostics.

### CircuitManager

- role-correct `GatewayPlan` создаёт один bounded `RouteLease`;
- concurrent prepare не переиспользует isolation key;
- make-before-break не retire old lease до Active replacement;
- expiry запрещает новый stream; retirement idempotent;
- bounded route count и backpressure.

### GatewayConnector

- TLS SPKI pin обязателен поверх onion stream;
- highest common version и feature negotiation;
- каждый token предъявляется ровно один раз соответствующему hop, account fields отсутствуют;
- stream IDs/sequence/windows/half-close/GOAWAY lifecycle;
- DNS проходит terminal session; entry/relay получает opaque bytes;
- expired/draining session не принимает новые flow.

### PacketEngine/DnsEngine/PolicyEngine

- TCP reassembly и bounded buffers; malformed packets не panic;
- UDP/QUIC/BitTorrent/SMTP25 reject; unsupported never bypass;
- DNS query/response bounds, cache scope per identity, flush on rotation;
- system resolver spy остаётся с нулём вызовов;
- split-tunnel allowlist explicit; DNS/forbidden policy имеет приоритет.

### KillSwitch/SecureStorage

- atomic apply + independent verify + crash recovery;
- stale generation не снимает новые rules;
- teardown reverse order; failed cleanup remains blocked;
- secure values atomic, redacted, bounded; corruption не вызывает trust reset.

### Directory/Token/Health

- exact-byte Ed25519 fixture, expiry, sequence rollback, key rotation, limits;
- blind issuance/redemption fixture не имеет общего identifier;
- token expiry/scope/replay; gateway verifier offline from account DB;
- health schema rejects arbitrary label/ID/destination; purge works offline.

## 5. Сквозные сценарии

| Test ID | Сценарий | Ожидаемый результат |
|---|---|---|
| E2E-001 | Standard connect + TCP echo + protected DNS | States по happy path; physical pcap содержит только Tor; exit видит destination |
| E2E-002 | Enhanced connect | Entry не видит DNS/destination; TLS inter-gateway; exit работает |
| E2E-003 | Maximum connect | Role order entry→relay→exit; terminal traffic opaque первым двум hops |
| E2E-004 | Explicit Direct Tor | Private gateway/token не вызываются; режим не используется как fallback |
| E2E-005 | Manual New Identity | New isolation/sessions/per-hop tokens; old flow drains; DNS cache flushed |
| E2E-006 | Scheduled rotation under load | New flows атомарно переходят; no loss/direct traffic; memory bounded |
| E2E-007 | Split tunnel explicit app | Только allowlisted app bypass; tunnel app и DNS не протекают |
| E2E-008 | Graceful disconnect | Reverse-order shutdown; KS снят последним; final OS routes verified |
| E2E-009 | Crash + restart | Persistent KS блокирует; `recover` resumes without leak |
| FAIL-010 | Kill-switch partial apply | Emergency block; Tor/control/gateway не запускаются |
| FAIL-011 | Tor bootstrap timeout | Reconnecting/backoff; all user packets blocked |
| FAIL-012 | Directory bad signature + valid cache | Bad update rejected; cached unexpired directory usable |
| FAIL-013 | Directory expired/no service | No gateway selection; Reconnecting; no direct fallback |
| FAIL-014 | Directory rollback/equivocation | Reject + security code; highest sequence unchanged |
| FAIL-015 | No matching country/roles | One refresh; clear availability error; old path retained if healthy |
| FAIL-016 | Gateway TLS pin mismatch | No auth/token redemption; descriptor quarantined for attempt budget |
| FAIL-017 | Protocol major mismatch | Alternate compatible gateway or upgrade-required FatalError |
| FAIL-018 | Token issuance outage | Old session remains; new connection waits under KS |
| FAIL-019 | Hop token expired/replayed | Fresh token for that hop once; replay cannot open relay/flow |
| FAIL-020 | Oversized/replayed gateway frame | Session closed; memory stays below limit; reconnect protected |
| FAIL-021 | Gateway dies during active TCP | Reconnecting; no packets reach physical interface outside Tor |
| FAIL-022 | Rotation new path fails, old healthy | `Rotating → Degraded`; old session stays default |
| FAIL-023 | Rotation both paths fail | `Reconnecting`; new flows rejected; KS engaged |
| FAIL-024 | DNS timeout/malformed answer | Local SERVFAIL; zero system DNS packets/calls |
| FAIL-025 | Injected system DNS route/rule drift | Leak monitor detects; emergency block → `Blocked` |
| FAIL-026 | UDP/QUIC packet flood | Bounded local rejects; no physical UDP/443; control remains responsive |
| FAIL-027 | SMTP25/BitTorrent attempt | Policy deny at client and defense-in-depth exit egress |
| FAIL-028 | Packet/gateway backpressure | Reads pause and new flow rejected; no unbounded allocation/deadlock |
| FAIL-029 | Secure storage unavailable/corrupt | Blocked/Fatal per error model; no automatic key/sequence reset |
| FAIL-030 | Shutdown timeout/stale lease | Force-close but KS remains until verified cleanup |
| FAIL-031 | Health collector outage | Tunnel unaffected; bounded aggregate dropped/persisted by policy |
| FAIL-032 | Clock skew beyond policy | Directory/token validity not assumed; user action under block |
| SEC-033 | Forbidden SSRF/private/metadata destination | Exit blocks after resolve/connect recheck |
| SEC-034 | Malformed IP/TCP/DNS/protobuf fuzz corpus | No panic/OOM; bounded stable error; no input echo in logs |
| SEC-035 | Issuance/redemption log correlation audit | Нет общего token/account/correlation identifier |
| SEC-036 | Support bundle redaction | Запрещённые fields/secret bytes отсутствуют |

Эти 36 сценариев покрывают 26+ failure paths; детализация кодов находится в
`docs/error-model.md` F01–F35.

## 6. Leak-test assertions

Для активных Standard/Enhanced/Maximum на physical interface допускаются только
Tor-approved transport и platform-essential traffic из явной policy. Assertions:

- ни одного DNS packet к system-configured resolvers;
- ни одного destination IP из тестового набора вне exit interface;
- ни одного UDP/443 QUIC flow;
- IPv6 либо проходит полностью внутри поддерживаемого tunnel, либо блокируется;
- после Tor/gateway crash application traffic остаётся blocked;
- connect/rotation/disconnect не создают transient route gap;
- control plane вызывается через Tor, не direct clearnet;
- packet capture не содержит token/account identifiers.

Leak tests запускаются на каждой поддерживаемой OS/версии kernel/network stack в VM
и повторяются при network change, sleep/resume, interface reorder, captive portal,
IPv4-only, dual-stack и IPv6-only входной сети.

## 7. Fuzz/property plan

Targets: IPv4/IPv6, TCP state/reassembly, DNS wire, gateway length/frame/state,
directory envelope/payload, control responses, token decoder и persisted state.

Properties:

- RSS/allocation bounded относительно configured maximum, не attacker length;
- no panic/unsafe UB/deadlock; cancellation освобождает resources;
- malformed/unknown critical value никогда не превращается в allow/bypass;
- signed bytes не reserialize до verify;
- `MustBlock` error всегда ведёт только к `Blocked`/`FatalError` path;
- arbitrary input не появляется в logs/errors;
- decoder encode/decode round-trip для supported fields и golden compatibility.

Минимум: corpus regression на каждый найденный crash, continuous short fuzz в CI и
длинные nightly jobs с sanitizers на поддерживаемой toolchain.

## 8. Performance и soak

До beta измеряются: connect p50/p95/p99, Tor bootstrap отдельно, DNS latency, TCP
throughput, active-flow memory, CPU, rotation pause, packet queue depth и gateway
window utilization. Privacy-sensitive raw samples не отправляются пользователями;
benchmark выполняется в lab.

Soak 24/72 h: тысячи short flow, long-lived half-close flow, periodic rotation,
directory/token expiry, network changes и gateway drain. Pass: no leak, deadlock,
unbounded memory/handle growth и session/circuit leak.

## 9. CI gates и ownership

| Gate | Команда-владелец | Block condition |
|---|---|---|
| Rust public API + mock contract | architecture/integration | breaking diff без ADR; mock suite failure |
| Protobuf lint/breaking/golden bytes | gateway protocol + architecture | incompatible schema, unbounded/forbidden field |
| Dependency DAG | architecture/integration | cycle или forbidden control↔data import |
| Component unit/contract | владелец компонента | failed behavior/limit/redaction |
| E2E Standard/Enhanced/Maximum | integration | state/path/session mismatch |
| Leak tests | security + platform | любой packet вне policy |
| Fuzz/security | security + component owner | panic/OOM/allow-on-error/secret log |
| Performance/soak | performance + SRE | утверждённый budget exceeded |

Каждая PR, меняющая contract, обновляет mock, contract suite, error mapping, limits,
docs и ADR. Integration branch не принимает временное отключение kill switch или
clearnet fallback для стабилизации тестов.

## 10. Entry/exit criteria для команд

Команда может начать с одного trait + mock dependency. Компонент готов к интеграции,
когда implementation object-safe, сообщает compatible `ContractVersion`, проходит
общую contract suite, документирует bounds/backpressure/cancellation, имеет unit и
fuzz entrypoint, не добавляет telemetry и предоставляет fault-injection adapter.

Система готова к MVP integration, когда E2E-001..009, FAIL-010..032 и SEC-033..036
проходят на каждой целевой платформе, protobuf compatibility зелёная, dependency
graph acyclic, gateway descriptor не содержит account identity, а открытые security
вопросы имеют владельца и release-blocking решение.

## 11. Открытые вопросы

1. Выбрать VM/device matrix и минимальные поддерживаемые OS versions.
2. Утвердить конкретные latency/memory/flow-count SLO и gateway capacity budget.
3. Выбрать fuzz infrastructure и покрытие sanitizers для C Tor boundary.
4. Согласовать test-only blind-token implementation после выбора production scheme.
5. Определить автоматизированную проверку административной независимости multihop.
