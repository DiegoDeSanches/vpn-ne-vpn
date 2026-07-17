# Отчёт итерации `qa/integration`

Дата: 2026-07-17. Git branch не создана: предоставленная рабочая папка не
содержит `.git`, поэтому выполнить требование отдельной ветки технически нельзя.

## Что реализовано

- QA strategy с evidence tiers, cadence, E2E/leak/failure/performance/
  compatibility matrices и fail-closed release process.
- Исполняемый authenticated Mock Tor SOCKS stand с actual loopback byte path для
  Standard, Enhanced, Maximum и explicit Direct Tor.
- Deterministic lifecycle/leak/chaos oracle: startup/shutdown/rotation, crash,
  directory/token/network/control-plane/resource failures.
- Общий JSON/JUnit runner без raw exceptions/payload/destination.
- Strict pcap evidence matrix и переиспользование fail-closed `tshark` analyzer.
- Gateway v1 protocol conformance manifest/runner поверх существующих Rust tests.
- Environment-relative performance thresholds, 30-sample Mock harness baseline,
  lab counter aggregator для throughput/CPU/memory/battery/capacity/overhead.
- Closed privacy-safe telemetry schema и artifact canary scanner.
- Fail-closed release qualifier, immutable candidate/report digest binding,
  release checklist и privacy checklist.
- Пять environment manifests; Linux namespace local lab; real Onion Compose
  skeleton; multi-region/adversarial plans.

## Добавленные/изменённые файлы

- `tests/qa_harness/`: model, loopback route, privacy, performance и release gates.
- `tests/integration/`, `tests/leak-tests/`, `tests/chaos/`,
  `tests/protocol-conformance/`, `tests/performance/`, `tests/security/`,
  `tests/compatibility/`, `tests/release/`: executable suites и manifests.
- `tests/environments/`, `tests/staging/`, `tests/integration/local-lab/`:
  environment/deployment artifacts.
- `tests/run_qa.py`, `tests/README.md`: unified runner и entry point.
- `docs/qa/test-strategy.md`, `docs/adr/0015-qa-evidence-and-regression-gates.md`.
- README существующих test domains обновлены.

## Созданные публичные интерфейсы

Только test/tooling interfaces; production public API не менялся:

- `python tests/run_qa.py --suite ... --output ...`;
- `python tests/protocol-conformance/run_suite.py [--include-daemon]`;
- `python tests/performance/benchmark.py` и `compare_baseline.py`;
- `python tests/performance/aggregate_lab_metrics.py <counters.json>`;
- `python tests/leak-tests/validate_evidence.py ...`;
- `python tests/release/qualify.py <evidence.json>`;
- telemetry aggregate schema v1 и release evidence schema v1.

## Предположения

- Staging images передаются digest-pinned и подписаны вне QA harness.
- Controlled staging fixture имеет публично маршрутизируемый адрес; gateway SSRF
  policy не ослабляется для private/test ranges.
- Onion descriptor публикуется обычным signed directory pipeline.
- Mock private hops проверяют topology, но не cryptographic opacity.
- Python 3.11+ и Rust toolchain/OS lab dependencies предоставляются runner image.

## Проходящие тесты

- Unified Python QA: **50/50 pass**, 0 failed, 0 skipped.
- `compileall` для test harness: pass.
- Privacy artifact scan generated `qa-report.json`: pass для двух canaries.
- Mock performance capture: 30 samples; baseline сохранён, release claim запрещён.
- JSON/JUnit reports: `test-results/qa/qa-report.json`, `qa-junit.xml`.

## Непроходящие/не выполненные тесты

- Rust protocol/gateway/directory/auth/client/Tor tests не собраны в текущем
  Windows environment: MSVC `link.exe` отсутствует. `cargo` найден, compilation
  остановлена linker error до выполнения tests. Это environment blocker, не
  test failure, но Rust conformance остаётся непроверенным этой итерацией.
- Real Onion, OS TUN/pcap, multi-region, adversarial, battery и 24/72h soak не
  запускались: отсутствуют signed images/keys/cloud/device lab и внешняя fixture.
- Docker Compose validation runtime не выполнялся; definition проверена static suite.

## Ожидаемые зависимости

- `infra/platform`: digest-pinned runner/Tor/gateway/fixture images, staging KMS,
  disposable multi-region deployment, netem/cgroup adapters, evidence storage.
- `client/desktop`, `client/mobile`: signed candidate builds и platform lifecycle
  adapters для pcap/route/firewall evidence.
- `gateway/multihop`: real terminal TLS/opaque relay implementation.
- `product/documentation`: Linux support matrix и oldest-supported version policy.
- `security/threat-model`: retention/cohort policy и approval failure domains.

## Security/privacy риски

1. Mock Enhanced/Maximum forwarders не доказывают encryption/opacity.
2. Staging Compose — Standard skeleton; multi-region deployment ещё требует IaC adapter.
3. Mock performance числа не репрезентативны для Tor/product и могут использоваться
   только для regression самого harness.
4. Battery/capacity/protocol overhead release evidence отсутствует до device/gateway lab.
5. Local namespace lab проверяет Linux topology, но platform VM/device adapters ещё
   должны гарантировать тот же capture coverage.

## Contract proposals

Не создавались: защищённые `proto/`, `common-types`, root Cargo, CI, directory/token
formats и production public API не изменялись.

## Готово к интеграции

Mock/local QA runner, manifests, release/privacy gates, relative threshold policy,
documentation и staging skeleton готовы. Production release qualification не
готова до получения внешнего evidence и успешного Rust conformance run.

## Открытые вопросы

1. Какая Linux distribution/kernel/systemd/nftables matrix поддерживается?
2. Какие cloud/admin/KMS domains считаются независимыми для Maximum?
3. Какой physical battery harness утверждён?
4. Каковы oldest supported gateway/client v1 builds после beta?
5. Каковы TTL для pcap/crash/performance evidence?
6. Кто предоставляет Windows MSVC Build Tools в runner image?
