# OnionRoute: audit preparation checklist

- Статус: template; unchecked item означает audit/release readiness gap.
- Дата: 2026-07-17.
- Координатор: `security/threat-model`.

## 1. Правила evidence room

- [ ] Scope содержит точные source commits, signed artifact digests, OS/platform versions, cloud accounts/regions,
  gateway roles, protocol/token/directory/update versions и excluded components с причиной.
- [ ] Read-only evidence room имеет immutable retention, MFA/JIT access и audit; auditor не получает production data.
- [ ] Каждый artifact имеет owner, creation time, source digest, tool/version, command/config и reviewer.
- [ ] Pcaps/logs/dumps используют только synthetic canaries и прошли privacy scan до загрузки.
- [ ] Ни один screenshot или export не содержит production secret, account/payment, IP, destination, token/session ID.
- [ ] Findings tracker имеет severity, threat/test/gate mapping, owner, deadline, fix commit и retest evidence.
- [ ] Auditor independence/conflicts, NDA, data handling и secure deletion after engagement зафиксированы.

Рекомендуемая структура evidence IDs: `EV-<domain>-<gate>-<artifact>-<date>-<digest8>`.

## 2. Architecture и scope

- [ ] Current data-flow и deployment diagrams совпадают с production IaC/runtime inventory.
- [ ] TB-1…TB-14 имеют входы, данные, authentication, bounds, failure mode и owner.
- [ ] Реестр активов, actors и 74 угроз рассмотрен владельцами; critical residual risks явно accepted/blocked.
- [ ] STRIDE/LINDDUN coverage и attack trees обновлены после последнего architecture change.
- [ ] Standard/Enhanced/Maximum/Direct Tor semantics и запрет availability fallback однозначны.
- [ ] Global passive observer, malicious exit/device и app-identity ограничения присутствуют в UX/claims.
- [ ] Public API/proto/directory/token changes имеют ADR/contract proposal и compatibility/security review.
- [ ] Экспериментальные компоненты не помечены production-ready до закрытия gates.

## 3. Cryptography и key management

- [ ] Нет custom cryptography; алгоритмы, параметры, libraries и versions перечислены.
- [ ] Independent token blind-signature/VOPRF review и standard vectors закрыты.
- [ ] TLS 1.3 policy, trust stores, SPKI/onion/gateway/role binding и hostname semantics документированы.
- [ ] Directory exact-byte Ed25519 domain separation, pinned root, sequence, expiry и rotation fixtures приложены.
- [ ] Update root/threshold/metadata/artifact/rollback/freeze design имеет отдельный review.
- [ ] Directory, update, token issuer, gateway TLS/mTLS и infrastructure keys раздельны.
- [ ] Key inventory содержит owner, purpose, environment, storage, exportability, rotation/revoke и blast radius.
- [ ] Root/signing ceremonies требуют two-person approval; последние drills и immutable KMS audit приложены.
- [ ] Compromise/revocation runbooks тестировались и не требуют privacy-ослабления/fallback.

## 4. Client, TUN и kill switch

- [ ] Для каждой supported OS/version есть firewall/TUN/route/secure-store design и privileges review.
- [ ] Privileged helper IPC mutual authentication, peer credentials, fixed commands, bounds и stale lease tests.
- [ ] Atomic `engage → verify`, emergency block, generation lease, recovery и last-step disengage доказаны.
- [ ] DNS, IPv6, WebRTC, QUIC, unknown UDP и direct socket pcap tests green.
- [ ] Captive portal не ослабляет protected state; workflow и UI протестированы.
- [ ] Sleep/resume/hibernate/interface/DHCP/route changes, crash/power loss/update/uninstall tests green.
- [ ] Split-tunnel attribution предотвращает child/PID/UID/path/signature spoof и не отправляется в telemetry.
- [ ] Crash dumps, panic, debug, clipboard/export и support bundle не раскрывают secrets/flows.
- [ ] Production artifact после signing/notarization повторно прошёл leak suite.

## 5. Tor boundary

- [ ] C Tor/PT versions, source/provenance, manifest hashes и vulnerability review приложены.
- [ ] Owner-only Unix mode/Windows ACL + SAFECOOKIE проверяются до spawn.
- [ ] Dynamic SOCKS/control endpoints не доступны другому local user/process.
- [ ] Context count/data directories/isolation keys bounded и не происходят из account/device ID.
- [ ] Guard/circuit behavior следует Tor policy; selective-failure tests не вызывают unsafe churn/fallback.
- [ ] Child logs не ingest-ятся; bootstrap/errors закрытые и не содержат onion/destination/token.
- [ ] Bridges/PT claims не обещают невидимость для ISP без доказательства.

## 6. Gateway и egress

- [ ] Runtime socket inventory и external/VPC scans доказывают отсутствие public user ingress.
- [ ] Entry/relay/exit имеют разные identities, namespaces, policy и role-negative tests.
- [ ] Terminal TLS до exit и inter-gateway mTLS rotation/revocation/wrong-role tests green.
- [ ] Frame/stream/session bounds проверяются до allocation; fuzz и 24h resource soak green.
- [ ] SSRF special-use IPv4/IPv6, textual encoding, CNAME/rebinding/TOCTOU corpus green.
- [ ] Application checks и nftables независимо блокируют metadata/private/management/Tor-control/SMTP25.
- [ ] OS gateway получает только final checked IP, никогда hostname.
- [ ] Approved resolver path и DNS failure behavior доказаны pcap; query persistence отсутствует.
- [ ] Draining, half-close, malicious upstream, auth/DNS outage и cancellation полностью освобождают resources.
- [ ] Exit visibility и malicious gateway residual risk отражены в product claims.

## 7. Directory, control и tokens

- [ ] Unsigned/wrong-key/algorithm/domain/mutated/oversized directory corpus reject до decode/use.
- [ ] Expiry, clock, rollback, same-sequence equivocation, corruption и power-loss tests green.
- [ ] Inventory four-eyes и independent failure-domain policy проверяются до signing.
- [ ] Targeted valid catalog equivocation detection реализован и протестирован либо release blocked.
- [ ] Account/control outage не вызывает data-plane account lookup или auth fail-open.
- [ ] Token profile проверяет issuer/audience/role/scope/iat/nbf/exp, ≤15m TTL и ≤5m skew.
- [ ] Per-hop tokens независимы; replay/nullifier atomic, bounded и TTL-purged.
- [ ] Issuance/redemption batching/coarsening и capability cohort ≥1 000 доказаны без network analytics.
- [ ] Gateway не имеет route/credential/schema к account/billing/token issuance DB.

## 8. Privacy и data governance

- [ ] Complete schema/data-store/queue/export/backup registry содержит purpose, owner, TTL и access role.
- [ ] Static schema scan и dynamic canary подтверждают no destination/DNS/payload logging.
- [ ] Нет user-level network analytics и per-session/per-token drill-down.
- [ ] Billing/account и network/health не имеют общего ID, exact clock, key, warehouse, IAM или backup.
- [ ] Telemetry closed-schema, opt-out, Tor path, daily/hourly coarsening и `k >= 100` до human access.
- [ ] TTL tests покрывают primary, replicas, caches, DLQ, search, vendor exports и object storage.
- [ ] Clean-room backup restore не оживляет expired records; cryptographic erasure evidence приложено.
- [ ] Support bundles имеют preview, explicit action, redaction и 7-day server deletion.
- [ ] Data-processing inventory/vendor contracts запрещают secondary use/cross-customer joins.
- [ ] Quarterly access review, offboarding и SoD violations закрыты.

## 9. Supply chain, build и update

- [ ] Dependencies locked, reviewed, minimally scoped; SBOM покрывает Rust/C/native/mobile/build tools.
- [ ] CI runners ephemeral/hardened; untrusted PR не получает secrets/signing/network production access.
- [ ] Branch protection, two-person review, signed commits/tags policy и maintainer inventory audited.
- [ ] Hermetic/reproducible build или documented deterministic diff verified independent rebuilder.
- [ ] SLSA-compatible provenance подписано отдельной identity и связано с source/dependencies/artifact.
- [ ] Release signer проверяет provenance/SBOM/test evidence, а не только artifact hash.
- [ ] Secret scan покрывает history, generated files, packages, images, symbols и test fixtures.
- [ ] Updater negative, rollback, freeze, root rotation и interrupted-write tests green.
- [ ] Last-known-good/recovery path не отключает signature verification/kill switch.

## 10. Operations и incident response

- [ ] Production IAM least privilege, MFA, JIT, SoD и break-glass TTL технически enforced.
- [ ] Deploy/analyst/billing/signing/KMS/support roles не пересекаются запрещённым образом.
- [ ] Closed log/metric/trace schemas versioned; arbitrary labels и runtime raw debug отсутствуют.
- [ ] Cloud flow logs, load-balancer logs, host agents, serial consoles и crash services privacy-reviewed.
- [ ] DDoS/load shedding оставляет auth/kill-switch/directory expiry fail-closed.
- [ ] Leak, key compromise, malicious directory/update, destination persistence и privacy-join runbooks tested.
- [ ] Incident evidence collection использует synthetic/coarse signals, не включает browsing history.
- [ ] Notification/legal processes, chain of custody и verified deletion после incident определены.
- [ ] Backup, DR и region failover повторяют security groups/IAM/TTL, а не создают weaker copy.

## 11. Verification и quality

- [ ] ST-001…ST-074 имеют PASS для текущего signed artifact и поддерживаемого scope.
- [ ] G-01…G-16 имеют immutable evidence и independent reviewer; skipped/flaky/N/A отсутствуют.
- [ ] Unit/integration/property/fuzz/leak/performance/security tests привязаны к requirements/threat IDs.
- [ ] Fuzz corpus versioned; каждый past crash — permanent regression fixture.
- [ ] Memory/FD/task budgets утверждены до soak; profiler доказывает plateau, backpressure и cleanup.
- [ ] Negative tests проверяют side effects и logs, не только error code.
- [ ] Mocks не засчитаны как production OS/network/KMS evidence.
- [ ] Test infrastructure не имеет Internet victim targets и очищает synthetic secrets/canaries.

## 12. Audit exit criteria

- [ ] Нет open Critical/High finding о leak, trust root, auth bypass, SSRF, unbounded memory, public ingress,
  destination persistence, supply-chain или billing/network correlation.
- [ ] Medium findings имеют owner, due date, compensating control и residual risk approval.
- [ ] Auditor retest подтверждает fixes на final artifact, не на промежуточной ветке.
- [ ] Final report перечисляет limitations против global observer/malicious device/exit и не использует термин
  «абсолютная анонимность».
- [ ] Security owner, privacy owner, release manager и relevant system owners подписали итоговый gate record.

## 13. Открытые evidence gaps на дату документа

В текущем репозитории есть архитектурные ADR и часть unit/integration intent, но нет предоставленных production
artifacts, platform pcaps, token cryptographic review, updater design/evidence, directory transparency, cloud/IAM
exports, privacy deletion restore report или выполненной ST-матрицы. Поэтому checklist не содержит заранее
отмеченных пунктов и не должен использоваться как утверждение audit readiness.
