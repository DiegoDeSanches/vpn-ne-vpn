# OnionRoute release qualification checklist

Checklist заполняется для конкретного immutable release candidate. Пустой пункт
блокирует релиз; waiver для leak/trust/privacy gates запрещён.

## Provenance и compatibility

- [ ] Source, image, installer, SBOM и config digests зафиксированы и подписаны.
- [ ] Staging использует ровно candidate artifacts и staging-only keys.
- [ ] Все release-required lanes `tests/compatibility/matrix.json` зелёные.
- [ ] Upgrade, rollback, clean install и reboot-active пройдены.
- [ ] Gateway protocol v1 current/oldest-supported pairs и incompatible-major reject пройдены.

## Route и lifecycle

- [ ] Первый запуск/connect/disconnect пройдены на каждой OS.
- [ ] Standard, Enhanced, Maximum и explicit Direct Tor пройдены.
- [ ] Country change, soft/hard rotation и New Identity пройдены under load.
- [ ] Gateway/Tor/directory/token/network failures дают block/protected reconnect.
- [ ] Sleep/resume, captive portal, daemon/UI crash и reboot не создают route gap.

## Безусловные blockers

- [ ] Zero clearnet destination packets/sockets во всех captures.
- [ ] Zero DNS к ISP/system resolver.
- [ ] Zero IPv6 bypass.
- [ ] Unsigned, revoked, expired, rollback и equivocated directory rejected.
- [ ] Expired/not-yet-valid/replayed/wrong-scope token rejected.
- [ ] Gateway frame/window/session/queue allocation bounded under hostile load.
- [ ] UI crash не снимает daemon-owned kill switch.
- [ ] Reconnect не создаёт direct fallback.
- [ ] Destination canaries отсутствуют в telemetry/log/crash/support/export.
- [ ] Каждый security regression имеет owner, severity и resolution.

## Performance/reliability

- [ ] Baseline fingerprint совпадает; sample count ≥30.
- [ ] Нет regression за `tests/performance/thresholds.json`.
- [ ] Mobile battery evidence получен на физических devices.
- [ ] 24h soak чист; 72h soak/DR drill выполнен по release cadence.
- [ ] Gateway capacity/backpressure и regional partial outage пройдены.

## Evidence и approval

- [ ] Есть real Onion, multi-region и adversarial evidence с artifact digests.
- [ ] Automated JSON/JUnit reports прошли privacy validation.
- [ ] `python tests/release/qualify.py <evidence.json>` завершился кодом 0.
- [ ] QA, Security, SRE и Product подписали candidate digest.
