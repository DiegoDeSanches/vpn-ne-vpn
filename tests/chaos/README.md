# Chaos suite

`test_failure_injection.py` — детерминированный PR oracle и loopback fault proxy.
Полные netem/cgroup/process/trust values находятся в
`tests/staging/adversarial.plan.json` и выполняются только в изолированной среде с
synthetic destinations. Любая неопределённость трактуется как failure, не skip.
