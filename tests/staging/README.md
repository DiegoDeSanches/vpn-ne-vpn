# Real Onion staging deployment

`compose.yaml` разворачивает staging gateway и реальный Tor v3 Onion Service без
host-published gateway ports. Все images должны быть digest-pinned через `OR_*_IMAGE`.
TLS key и token verifier bundle поступают только через staging secrets.

До запуска инфраструктурная команда должна:

1. предоставить внешнюю controlled public fixture и approved gateway DNS;
2. создать staging TLS/token/directory keys в отдельном KMS domain;
3. запустить compose и дождаться создания v3 hostname;
4. опубликовать hostname/SPKI/role/country через обычный signed directory pipeline;
5. передать runner только directory Onion endpoint, не HiddenServiceDir;
6. включить physical/TUN/Tor/exit capture и route/firewall snapshots;
7. после suite уничтожить secrets и HiddenServiceDir по staging retention policy.

Пример:

```text
docker compose -f tests/staging/compose.yaml config
docker compose -f tests/staging/compose.yaml up --abort-on-container-exit --exit-code-from test-runner
```

Compose покрывает Standard real-Onion skeleton. Enhanced/Maximum и regional
faults разворачиваются из `multi-region.plan.json` существующим immutable platform
deployment pipeline; этот QA change не дублирует production IaC и не ослабляет ACL.
