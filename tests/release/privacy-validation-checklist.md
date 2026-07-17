# Privacy validation checklist

- [ ] Remote schema содержит только allowlisted aggregate fields v1.
- [ ] Нет IP, domain, destination address/port, account ID, token ID, stable device ID.
- [ ] Нет exact OS build, hostname, hardware serial или client build fingerprint.
- [ ] Нет per-user/per-flow/per-destination labels и точных timelines.
- [ ] Crash count отсутствует без consent; revoke consent прекращает export.
- [ ] Synthetic canaries отсутствуют в logs, traces, metrics, crash, support, queue, DB, backup и vendor export.
- [ ] Debug/incident paths проверены тем же canary corpus.
- [ ] Aggregation buckets и minimum cohort policy проверены до analyst access.
- [ ] TTL, deletion, queue purge и restore-before-network тесты пройдены.
- [ ] Payment/account plane нельзя связать с network telemetry schema/IAM/query.
- [ ] Pcap содержит только synthetic lab traffic, хранится отдельно, имеет owner/TTL/digest.
- [ ] JSON/JUnit report не содержит raw exception, payload или destination.
- [ ] `tests/security/test_privacy_observability.py` и dynamic redaction scan зелёные.
