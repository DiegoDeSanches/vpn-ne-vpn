# Security tests

Fault injection, hostile protocol inputs, token/directory replay, SSRF, redaction,
and cross-domain correlation checks are specified in `docs/integration-plan.md`.

`test_privacy_observability.py` технически фиксирует закрытую allowlist schema и
consent gate для crash count. Raw destination-shaped dimensions отвергаются до
serialization.
