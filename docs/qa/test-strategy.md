# Тестовая стратегия OnionRoute

Статус: QA baseline v1. Владелец: `qa/integration`. Стратегия проверяет
fail-closed privacy tunnel, но не доказывает абсолютную анонимность и не заменяет
независимый security review.

## 1. Цели и инварианты

Главный критерий качества — не доступность любой ценой, а отсутствие обхода
защищённого маршрута. Во всех неопределённых состояниях новые пользовательские
потоки блокируются. Direct Tor допустим только как явно выбранный режим.

Непрерывно проверяются инварианты:

1. kill switch установлен и независимо проверен до TUN/маршрута;
2. физический интерфейс видит только разрешённый Tor transport и обязательный
   platform traffic;
3. DNS не вызывает системный resolver и не уходит ISP;
4. IPv6 либо полностью поддержан внутри tunnel, либо блокируется (MVP);
5. UDP/QUIC/WebRTC не создают физический egress;
6. directory проверяется до использования и имеет жёсткий срок действия;
7. token проверяется offline по подписи, времени, scope, role и replay policy;
8. все frame/window/queue/session limits применяются до allocation;
9. сбой UI не меняет daemon-owned kill-switch generation;
10. telemetry проходит только через закрытую агрегированную схему.

## 2. Уровни evidence

| Окружение | Назначение | Что реально | Можно квалифицировать релиз |
|---|---|---|---|
| Mock Tor | PR, детерминированные state/fault tests | loopback SOCKS и bounded TCP mocks | Нет |
| Local integration | nightly, component wiring | процессы, TUN/network namespaces, pcap | Нет |
| Staging real Onion | nightly/pre-release | C Tor, v3 Onion Service, pinned TLS, signed directory/token | Только совместно с нижними строками |
| Multi-region staging | pre-release | Standard/Enhanced/Maximum, независимые регионы, capacity/failover | Да, как часть полного пакета |
| Adversarial | pre-release/quarterly | hostile network/peer, netem, malformed trust inputs, pressure | Да, как часть полного пакета |

Манифесты находятся в `tests/environments`. Симуляция никогда не повышается до
release evidence. Staging использует только synthetic destinations и staging-only
keys. Onion hostname попадает к клиенту через обычный подписанный каталог, а не
читается напрямую из HiddenServiceDir.

## 3. Пирамида и частота

| Слой | PR | Nightly | Pre-release | Quarterly |
|---|---:|---:|---:|---:|
| unit/property/static schema | Да | Да | Да | Да |
| protocol conformance/golden | Да | Да | Да | Да |
| Mock Tor full route | Да | Да | Да | Да |
| local namespace + pcap | выборочно | Да | Да | Да |
| real Onion staging | Нет | Да | Да | Да |
| multi-region/load/soak | Нет | выборочно | Да | Да |
| adversarial/failure injection | quick corpus | Да | Да | Да |
| 24/72h soak, restore/KMS drills | Нет | Нет | 24h | 72h/DR drill |

Flaky security/leak тест не разрешается повторным запуском. Он блокирует релиз до
root-cause, владельца и сохранённого минимального reproduction corpus.

## 4. Сквозная матрица

| ID | Сценарий | Основные assertions |
|---|---|---|
| E2E-001 | первый запуск | KS до connect; traffic blocked до verified path |
| E2E-002/003 | connect/disconnect | порядок KS→TUN→Tor→gateway; teardown в обратном порядке; no transient gap |
| E2E-004..007 | Standard/Enhanced/Maximum/Direct Tor | правильные роли; Direct Tor только explicit; private hops не вызываются для Direct Tor |
| E2E-008 | country change | signed compatible route; old path до ready replacement |
| E2E-009/010 | soft/hard rotation | make-before-break; bounded pause; no fallback |
| E2E-011 | identity reset | новая isolation/session/token set; DNS cache generation сменена |
| E2E-012/013 | gateway failure/Tor crash | active flows fail; новые blocked; protected reconnect only |
| E2E-014/015 | directory expiry/revocation | новые selection/streams rejected; no stale trust reset |
| E2E-016 | token expiry | expired token rejected at every hop; fresh unlinkable token or block |
| E2E-017 | network loss/sleep/resume | new interface blocked first; health and routes reverified |
| E2E-018 | captive portal | portal не вызывает clearnet probe; state blocked/reconnecting |
| E2E-019 | daemon/UI crash | UI crash не снимает KS; daemon crash сохраняет persistent block |
| E2E-020 | system reboot | early persistent KS; atomic state recovery; no boot gap |

Реализация oracle и loopback topology находится в `tests/qa_harness`, executable
tests — в `tests/integration`. Enhanced/Maximum loopback forwarders проверяют
порядок ролей, но не шифрование; terminal TLS/opacity доказывает только staging.

## 5. Leak suite

Для каждой поддерживаемой OS, каждого anonymity mode и состояний startup,
connected, shutdown, soft/hard rotation, reconnect выполняются:

| Вектор | Stimulus | Pass condition |
|---|---|---|
| DNS | A/AAAA, UDP/TCP 53, system API | 0 ISP/system DNS; protected answer или local SERVFAIL |
| IPv4 | unique TCP canary | destination только на exit capture |
| IPv6 | dual/IPv6-only/NAT64, fragments | 0 bypass; tunneled либо deterministic block |
| WebRTC | STUN/ICE UDP | 0 physical STUN/UDP; bounded local reject |
| QUIC | HTTP/3 и UDP/443 flood | 0 physical UDP/443 |
| DoH/DoT | browser/system attempts | protected TCP path или policy block, никогда bypass |
| app fallback | raw socket/helper/PID reuse | no direct socket/destination packet |
| local network bypass | RFC1918/link-local/mDNS | blocked unless explicit reviewed split rule; DNS still protected |
| network transition | Wi-Fi/cell/Ethernet/interface reorder | KS present before first packet on new interface |

Каждый lab case сохраняет pcap physical/TUN/Tor/inter-gateway/exit, route/firewall
snapshot до/во время/после события и destination-free process events. Анализатор
`tests/leak-tests/mobile/assert_no_leaks.py` fail-closed при отсутствии `tshark`.

## 6. Protocol conformance

`tests/protocol-conformance/manifest.json` связывает normative gateway v1 tests с
реальными Rust suites. Обязательны golden bytes, incremental boundaries,
canonical varint, version downgrade, critical extensions, session state,
stream/connection windows, half-close, backpressure, hostile frames и redacted
diagnostics. Parser fuzz target проверяет, что attacker-controlled length не
управляет allocation. Compatible pair matrix: current↔current, oldest supported
v1 client↔current gateway, current client↔oldest supported v1 gateway и явный
reject другого major.

## 7. Failure injection

| Домен | Faults | Механизм | Expected |
|---|---|---|---|
| WAN | packet loss, latency, bandwidth | netem/fault proxy | bounded retry; no downgrade/fallback |
| process | Tor/gateway/daemon/UI kill | supervisor/OS kill | KS continuous; recovery bounded |
| protocol/trust | malformed frame, expired cert, clock skew | hostile peer/fake clock | session close/reject before use |
| dependencies | DNS, partial gateway, DB, KMS, directory signer | proxy/firewall/service stop | existing safe data plane isolated; new unsafe work blocked |
| resources | disk full, memory pressure | quota/cgroup/VM pressure | bounded memory/disk; overload rejects; KS not shed |

Fault values заданы в `tests/staging/adversarial.plan.json`. Для process/network
race fault применяется на каждой точке lifecycle, а не только после connect.

## 8. Performance и capacity

Измеряются p50/p95/p99 по агрегированным synthetic samples: Tor bootstrap,
connect, TTFB, latency, throughput, CPU, memory, battery energy, simultaneous
streams, reconnect, rotation, gateway streams/s и protocol overhead. Raw browsing
timelines не собираются.

Абсолютные marketing SLO до полевого baseline не задаются. Для каждого сочетания
hardware class + OS family + build + route mode + region profile сохраняется
baseline минимум из 30 cold/warm samples. Сравнивать разные fingerprints нельзя.
`tests/performance/thresholds.json` задаёт realistic noise-aware gates: обычно
15–30% relative с небольшим absolute allowance для latency/CPU/memory. Throughput
и capacity блокируются при падении на 10–15%. Battery baseline принимается только
с физического device power harness; Mock Tor явно возвращает `unavailable`.

Baseline обновляется только отдельным reviewed change с причиной (hardware,
dependency, protocol) и сравнительным отчётом. Нельзя обновлять baseline в том же
изменении только потому, что regression test стал красным.

## 9. Compatibility

`tests/compatibility/matrix.json` извлекает заявленные floors из build config:
Windows 10.0.19041 x64/arm64, macOS 13 x64/arm64, Android API 29 (target 36)
arm64 и emulator x86_64, iOS 17 arm64. Каждый release-required lane проходит
IPv4-only, dual-stack, IPv6-only access, NAT64, Wi-Fi/Ethernet/cellular/captive,
clean install, upgrade, rollback и reboot-active. Linux остаётся release-blocked,
пока product не утвердит distributions/systemd/nftables/secure-storage matrix.

## 10. Privacy-safe observability и reports

Remote schema разрешает только component health, closed error code, coarse OS
family, client semver без build metadata, gateway load bucket, latency bucket,
aggregate throughput bucket и crash count при явном согласии. IP, domain,
destination, account/token/stable-device ID и точные timelines отсутствуют на
уровне типа и отвергаются до serialization.

JSON/JUnit отчёты `tests/run_qa.py` содержат test ID, status, duration и тип ошибки,
но не raw exception, packet payload или destination. Pcap и security artifacts
хранятся отдельно в ограниченном lab storage, содержат только synthetic traffic,
имеют TTL и digest; в telemetry они не экспортируются.

## 11. Release qualification

Production candidate требует evidence одновременно из real Onion, multi-region и
adversarial environments. `tests/release/qualify.py` fail-closed: `true`, `null`
или отсутствующий blocker одинаково блокируют выпуск. Дополнительно каждый
security regression обязан иметь владельца.

Немедленные blockers: любая clearnet leak; ISP DNS; IPv6 bypass; acceptance
unsigned/revoked/expired directory; expired token; unbounded protocol allocation;
KS loss при UI crash; direct reconnect fallback; destination в telemetry;
security regression без владельца.

## 12. Assumptions и открытые вопросы

Assumptions: staging image digests подписаны; test keys не входят в production
images; controlled fixtures имеют публично маршрутизируемые адреса, чтобы gateway
SSRF policy не ослаблялась; test clock не доступен production build.

Открыто:

1. Утвердить Linux distribution matrix и владельца device lab.
2. Утвердить независимые cloud/admin/KMS domains для Enhanced/Maximum claims.
3. Выбрать физический battery harness и единицу energy normalization.
4. Зафиксировать oldest supported v1 client/gateway build после первого beta.
5. Утвердить retention для pcaps, crash artifacts и performance reports.
6. Выбрать sanitizer coverage C Tor boundary и nightly fuzz infrastructure.
