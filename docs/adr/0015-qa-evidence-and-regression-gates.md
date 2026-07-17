# ADR-0015: Evidence tiers и environment-matched regression gates

Статус: proposed. Дата: 2026-07-17. Владельцы: `qa/integration`,
`security/threat-model`, `infra/platform`.

## Контекст

Mock окружение быстро и детерминированно проверяет state transitions, но не может
доказать свойства OS firewall, Tor v3, TLS, regional failure domains или battery.
Единый абсолютный performance target между разными устройствами и Tor paths был
бы либо нестабилен, либо нереалистичен.

## Решение

Разделить evidence на simulation, local lab, real Onion staging, multi-region и
adversarial. Simulation/local результаты не квалифицируют production release.
Release требует последние три класса одновременно и fail-closed qualifier.

Performance сравнивается только с reviewed baseline того же environment
fingerprint. Gate равен baseline плюс relative threshold и небольшой absolute
noise allowance; throughput/capacity используют lower bound. Baseline содержит
не менее 30 samples и не обновляется автоматически при regression.

QA reports используют closed destination-free schema; raw pcaps остаются в
изолированном synthetic lab storage и не являются telemetry.

## Последствия

- PR остаётся быстрым, но зелёный PR не означает release readiness.
- Для релиза обязательны дорогостоящие device/multi-region/adversarial jobs.
- Отсутствующее или stale evidence блокирует, а не превращается в waiver.
- Значения SLO утверждаются только после репрезентативного baseline.

## Альтернативы

Единый all-in-one environment отклонён из-за слабой изоляции failure domains.
Абсолютные цели до baseline отклонены как недостоверные. Автоматическое принятие
нового baseline отклонено, поскольку скрывает regressions.
