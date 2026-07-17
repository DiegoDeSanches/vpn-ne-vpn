# OnionRoute automated QA stand

Быстрый локальный запуск (Python 3.11+):

```text
python tests/run_qa.py --suite all --output test-results
```

Результаты: `test-results/qa-report.json` и `qa-junit.xml`. Отдельный реальный
gateway v1 suite:

```text
python tests/protocol-conformance/run_suite.py --include-daemon
```

Mock stand не является release evidence. Полная последовательность и требования
к pcap/staging описаны в `docs/qa/test-strategy.md`; release qualification — в
`tests/release/release-checklist.md`.
