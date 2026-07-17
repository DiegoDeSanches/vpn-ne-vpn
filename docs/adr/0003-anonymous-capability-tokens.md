# ADR-0003: анонимные capability tokens

- Статус: Accepted; конкретный алгоритм ожидает security review
- Дата: 2026-07-16

## Контекст

Gateway должен проверять право на сервис и limits, но account bearer token или stable
user ID в gateway protocol связывает browsing session с billing identity. Простая
случайная opaque token, выданная control plane, остаётся коррелируемой issuer-ом.

## Решение

Использовать стандартную blind-signature либо VOPRF-based issuance схему из
рецензируемой библиотеки. Control API аутентифицирует account, проверяет entitlement
и подписывает blinded request. Client unblind-ит короткоживущий capability token;
gateway offline проверяет issuer signature, scope, expiry и replay/nullifier.

Token не содержит account/device/payment/IP. Capability set coarse и не должен быть
уникальным fingerprint. Для каждого private hop выдаётся независимый token с role-
scoped capability; token нельзя переиспользовать на другом hop. Для новой identity/
route выдаётся полностью свежий набор.
Issuance и redemption storage разделены, correlation IDs не переносятся.

Пока алгоритм и библиотека не утверждены, token implementation помечается
experimental и не считается production-ready. Wire contract остаётся opaque bytes с
hard limit 4 KiB, поэтому алгоритм можно заменить новым token-protocol version.

## Последствия

- Token service сложнее обычного bearer JWT, появляется replay state/key rotation.
- Немедленная revocation ограничена TTL и issuer-key emergency revoke.
- Batching/timing/capability policy нужны, иначе blind crypto не исключает correlation.

## Отклонённые варианты

- Account JWT в gateway: нарушает data-plane anonymity.
- Random token с issuer database lookup: создаёт прямой issuance/redemption join.
- Самодельная blind signature: запрещена требованием не изобретать криптографию.

## Проверка

- Cryptographic test vectors выбранной библиотеки и independent review.
- Replay/expiry/scope tests; gateway не имеет account network route.
- Log/schema audit подтверждает отсутствие общего identifier.
