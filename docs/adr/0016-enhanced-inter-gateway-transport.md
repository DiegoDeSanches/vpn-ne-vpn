# ADR-0016: Enhanced inter-gateway transport

- Status: Proposed for architecture/security review
- Date: 2026-07-17
- Owner: `gateway/multihop`

## Контекст

Enhanced mode должен передавать клиентскую terminal TLS-сессию от entry к exit,
не раскрывая entry DNS/destination и не передавая exit account ID или реальный IP
клиента. Межсерверный канал должен поддерживать multiplexing, backpressure,
короткоживущие service identities, emergency revocation и graceful drain.

Accepted ADR-0008 требует opaque entry: именно exit завершает terminal TLS и
декодирует пользовательский gateway protocol. Entry отдельно проверяет
entry-scoped anonymous credential и выбирает exit.

## Сравнение вариантов

| Вариант | Преимущества | Недостатки | Решение |
|---|---|---|---|
| Один multiplexed TLS stream | Один mTLS handshake, один bounded state machine, меньше ключей/соединений, централизованные quotas и drain | TCP HOL при packet loss; сбой link закрывает все его relay sessions | Основной v1 transport |
| Несколько TLS streams | Меньше межsession HOL и выше fault isolation | Больше handshakes, памяти, observable concurrency и correlation surface; сложнее rotation/revocation | Только bounded pool для новых sessions; 2–4 после измерений, без миграции активных sessions |
| HTTP/2 | Готовые streams, flow control и GOAWAY | HPACK/SETTINGS/HTTP semantics и существенно большая attack surface; не нужен HTTP routing | Отклонён для v1 |
| Собственный framing поверх TLS | Минимальные typed frames, строгие лимиты, reuse gateway-v1 windows/IDs/fairness | Собственная protocol state machine требует fuzzing/conformance review | Выбран поверх rustls TLS 1.3; криптография не изобретается |

## Решение

Entry–exit использует TLS 1.3 mTLS (`rustls`) с ALPN
`onionroute-inter-gateway/1`. TLS 1.2, 0-RTT, resumption и server tickets
отключены. Entry и exit используют отдельные data-plane service certificates и
разные role-specific issuing CA. Exact short-lived leaf digest должен быть в
актуальном signed trust bundle; WebPKI chain validation остаётся обязательной.

Поверх TLS работает `InterGatewayFrame`: canonical u32 varint length + bounded
Protobuf. Envelope sequence строго возрастает. После mTLS стороны обмениваются
fresh nonce, connection ID и TLS-exporter-bound Finished. Exit хранит bounded
replay cache `(entry_service_id, client_nonce)`. OpenSession содержит только
ephemeral odd session ID, terminal protocol version, receive window и expiry.

Flow control повторяет проверенные `gateway-protocol::FlowController` semantics:
connection window + per-session window, checked credit, hard limits и
WindowUpdate только после потребления bytes. Queue bounded и round-robin;
saturation возвращает Backpressure.

## Failure recovery

- Active streams никогда не мигрируют между exits: TCP semantics этого не
  допускают. При link failure они закрываются fail-closed.
- Новые streams могут использовать новый diverse Enhanced route после backoff.
- Draining посылает GOAWAY, запрещает новые sessions и завершает активные в
  ограниченный grace period.
- В state machine нет direct-clearnet fallback action. Если безопасного маршрута
  нет, результат только `Block`.

## Security consequences

- Entry mTLS certificate авторизует только OpenRelaySession/RelayBytes и не
  принимается management/control-plane listeners.
- Exit проверяет mTLS role/pin/revocation и применяет per-entry quotas.
- Exit не доверяет destination внутри terminal protocol: hostname/port, каждый
  DNS result и IP непосредственно перед dial проверяются самостоятельно.
- Entry видит объём/тайминг opaque sessions; exit видит destination/egress IP.
  Это не даёт абсолютной анонимности и не устраняет timing correlation.
- Single TCP link сохраняет unavoidable wire HOL; bounded scheduling устраняет
  только producer starvation в локальной очереди.

## Проверка

- Real in-memory rustls TLS 1.3 mTLS + application handshake test.
- Wrong-role, pin, management-authority, emergency-revocation и replay tests.
- ACL/SSRF/DNS-result tests и structural privacy contract.
- 10,000-producer bounded queue load test.
- `decode_inter_gateway_frame` fuzz target.

