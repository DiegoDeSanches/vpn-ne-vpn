# ADR-0004: versioned protobuf и явное negotiation

- Статус: Accepted
- Дата: 2026-07-16

## Контекст

Клиенты, gateways и control services обновляются независимо. Неявная совместимость
protobuf недостаточна для security semantics, size limits и feature rollout.

## Решение

Публичный wire формат — protobuf через prost. Package содержит major (`.v1`), а
top-level сообщения несут `(major, minor)` или inclusive range. Hello выбирает highest
common minor одного major и явно подтверждает features.

Additive fields допустимы только с безопасным default. Tags/names удалённых fields
reserved навсегда. Unknown policy/crypto/role/state enum и unknown critical frame
отклоняются. Все message/list/string limits нормативны и проверяются до тяжёлых
allocation. Gateway frames имеют length prefix и 64 KiB hard limit.

Breaking change создаёт новый package/service/endpoint major. Support window — current
и previous major минимум 12 месяцев, кроме documented critical vulnerability.

## Последствия

- Нужны generated-code pipeline, descriptor snapshots, golden bytes и breaking CI.
- Minor feature нельзя начать писать, пока readers и negotiation не готовы.
- Protobuf payload не считается canonical; opaque/signed bytes нельзя reserialize.

## Проверка

- Buf lint/breaking либо эквивалент against last release descriptors.
- Cross-version compatibility matrix, golden frames, unknown-field/enum tests.
- Rust traits versioned отдельно в `contracts::v1` по тем же breaking principles.

