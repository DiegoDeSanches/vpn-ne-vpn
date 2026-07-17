# ADR-0008: terminal encryption через opaque entry/relay

- Статус: Accepted
- Дата: 2026-07-16

## Контекст

Если entry или relay завершает пользовательский gateway protocol, он видит DNS и
destination, уменьшая смысл multihop. Одновременно inter-gateway links нуждаются в
аутентификации и защите без самодельной криптографии.

## Решение

Первый hop доступен через Tor v3 onion service. Межgateway links используют TLS 1.3
с mutual authentication по отдельному gateway PKI. Внутри relay path client создаёт
terminal TLS 1.3 session до exit, pinning exit SPKI из подписанного каталога. Entry и
relay пересылают bounded opaque bytes; только exit декодирует `OpenTcp`/`DnsQuery`.
Каждый nested hop аутентифицируется отдельным role-scoped anonymous token;
`OpenRelay` ссылается на public next gateway ID, не на clearnet address.

Standard завершается непосредственно на exit через Tor. Enhanced использует
entry→exit, Maximum entry→relay→exit. Roles и разные failure/admin domains проверяет
signed directory + client policy. Entry/relay egress policy не позволяет им стать
неявным exit.

## Последствия

- Nested TLS и relay flow control увеличивают latency/overhead.
- Exit всё равно видит destination; абсолютная анонимность не заявляется.
- Route setup protocol/tickets ещё требует отдельной детальной схемы и security review;
  до этого multihop gateway implementation отмечается experimental.

## Отклонённые варианты

- Terminate user session на entry: раскрывает destination entry gateway.
- Собственный onion encryption protocol: нарушает запрет custom cryptography.
- Plain inter-gateway TCP в private network: доверяет сети и расширяет blast radius.

## Проверка

- Packet capture entry/relay не декодирует terminal DNS/destination.
- TLS identity/role/key rotation tests, wrong-role и pin mismatch rejection.
- Backpressure и nested-session teardown tests под fault injection.
