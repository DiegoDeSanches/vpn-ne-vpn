# ADR-0005: подписанный gateway directory с rollback protection

- Статус: Accepted
- Дата: 2026-07-16

## Контекст

Client получает onion endpoints, gateway roles и TLS pins из control plane. TLS
download channel один недостаточен: CDN/control compromise мог бы заменить весь
маршрут. Требуются offline-verifiable authenticity, expiry и защита от rollback.

## Решение

Directory service публикует `SignedGatewayDirectory`. Ed25519 signature покрывает
точно `"onionroute-directory-v1\0" || payload`, где payload — исходные serialized
protobuf bytes `GatewayDirectory`. Проверка выполняется до decode; reserialization
для signature запрещена.

Client имеет pinned signing root, проверяет algorithm/key validity, hard limits,
format version, issuance/expiry, monotonic sequence, uniqueness, v3 onion IDs, roles,
TLS SPKI pins и descriptor bounds. Highest sequence хранится атомарно в
`SecureStorage`. Key rotation принимается только через `next_signing_keys`, подписанные
действующим key. Cache после `valid_until` не используется.

Catalog содержит только public gateway metadata и не содержит account/client data
или clearnet gateway IP.

## Последствия

- Directory можно кэшировать и распространять через недоверенный transport/CDN.
- Требуются clock policy, isolated signing, inventory approval и emergency root plan.
- Потеря/corruption rollback state — fail-closed, а не автоматический reset.

## Проверка

- Golden exact-byte signature fixtures и mutation tests.
- Expiry, rollback, same-sequence equivocation и key-rotation tests.
- Fuzz decode только после bounded signature envelope extraction.

