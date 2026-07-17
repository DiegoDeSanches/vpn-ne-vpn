# Версионирование протоколов OnionRoute

Статус: normative v1. Правила относятся к protobuf, gateway framing, подписанному
каталогу, feature registry и Rust component contracts.

## 1. Модель версии

Версия — `(major, minor)`:

- `major` меняется при wire/semantic incompatibility;
- `minor` растёт только для additive optional behavior, которое старый peer может
  безопасно игнорировать либо явно не включать;
- patch version не передаётся по wire и относится только к implementation release.

Protobuf package содержит major: `onionroute.gateway.v1`. Каждое top-level request,
response или session hello также несёт `ProtocolVersion`/`ProtocolVersionRange`.
Package path предотвращает случайное смешивание generated types, а runtime field
обеспечивает negotiation и deprecation.

## 2. Negotiation

1. `ProtocolVersionRange` охватывает ровно один major; cross-major range invalid.
2. Client отправляет inclusive minimum/maximum и bounded requested features.
3. Server выбирает наибольший общий minor того же major.
4. Server возвращает selected version, gateway ID/active role и только реально
   enabled features; client сверяет ID/role и TLS pin с signed route plan.
5. До завершения negotiation допустимы только hello/error/close frames.
6. Нет пересечения → `ProtocolIncompatible`; fallback на другой major в той же
   session запрещён. Client может открыть отдельную session явно поддерживаемого major.
7. Security-critical feature включается только после двустороннего подтверждения.

`requested_features` ограничен 32 элементами по 64 ASCII bytes. Имена находятся в
registry (`tcp-connect-v1`, `dns-wire-v1`, `flow-control-v1`). Префикс
`required:` означает, что отсутствие feature завершает negotiation. Неизвестный
обычный optional feature игнорируется, неизвестный required feature отклоняется.

## 3. Protobuf evolution rules

В пределах major разрешено:

- добавлять новое поле с новым tag и безопасным default;
- добавлять новый response/service method, не меняя существующие;
- добавлять enum value, если receiver проверяет unknown numeric values;
- добавлять optional oneof alternative только за negotiated feature;
- добавлять error code, сохраняя coarse fallback category.

В пределах major запрещено:

- менять tag, type, cardinality, oneof membership или signedness поля;
- менять единицу измерения, default semantics, privacy classification или limit;
- превращать optional behavior в обязательное;
- переиспользовать удалённый tag/name — они объявляются `reserved` навсегда;
- добавлять account/user/device/payment identity в gateway или health schema;
- менять порядок/смысл hop roles или fail-closed policy;
- считать proto3 zero value валидным без explicit semantic validation.

Unknown fields обычного сообщения игнорируются. Unknown enum, управляющий policy,
role, crypto algorithm или state transition, не преобразуется в zero/default: всё
сообщение отклоняется как `ProtocolViolation`. Неизвестный `GatewayFrame.body` также
отклоняется, если он не был согласован feature negotiation.

Prost может не сохранять unknown fields после decode/re-encode. Поэтому компонент,
который должен переслать opaque protobuf, пересылает исходные bounded bytes, а не
декодированную структуру. Особенно это обязательно для signed directory payload.

## 4. Wire limits

Limits проверяются до allocation/decompression и повторно после decode. Compression
для gateway frames v1 не поддерживается.

| Объект | Hard limit v1 |
|---|---:|
| Length-delimited `GatewayFrame` | 64 KiB encoded |
| `Data.payload` | 32 KiB |
| DNS wire query/response | 64 KiB |
| Capability token | 4 KiB |
| Proof of possession | 4 KiB |
| Session ID / nonce | ровно 16–32 bytes по полю |
| Hostname | 253 ASCII bytes после IDNA |
| Feature/capability name | 64 ASCII bytes |
| Features per hello/token | 32 |
| Concurrent streams per session | не более 4,096; server обычно ниже |
| Initial per-stream window | не более 4 MiB |
| Signed directory envelope | 2 MiB |
| Directory payload | 2 MiB |
| Gateways per directory | 4,096 |
| Secure-storage value | 256 KiB |
| Roles per gateway | 3 |
| Protocol versions per gateway | 16 |
| Capabilities per gateway | 64 |
| Generic control request | 256 KiB, если ниже не указано |
| Health report | 64 KiB и 32 counters |

Zero-length token, empty hostname, port 0, unspecified enum, duplicate gateway ID,
duplicate role, non-v3 onion ID, invalid IP byte length и `valid_until <= issued_at`
являются semantic errors независимо от protobuf decode success.

## 5. Gateway framing compatibility

Transport — последовательность unsigned-varint length + serialized `GatewayFrame`.
Application TLS 1.3 устанавливается до frames. Frame sequence начинается с 1 для
каждого направления и строго возрастает; wrap и replay закрывают session.

Stream IDs создаёт client, они нечётные и строго возрастают. `OpenTcpRequest`
предшествует `Data`. Flow-control credit измеряется uncompressed payload bytes;
sender никогда не превышает stream/session credit. Unknown stream, duplicate open,
data after half-close и credit overflow — `ProtocolViolation`.

В Enhanced/Maximum `OpenRelayRequest` создаёт bounded opaque stream к public
`next_gateway_id`; receiving hop находит private mutually-authenticated endpoint из
operator inventory. Client не передаёт clearnet IP. Nested gateway session внутри
этого stream имеет собственные TLS, sequence space, session ID и независимо выданный
token. Entry/relay role не принимает terminal TCP/DNS frames по policy.

Minor version может добавить frame только с negotiated feature. Изменение framing,
sequence или stream-ID rules требует нового major.

## 6. Формат подписанного gateway directory

Wire envelope определён `directory/v1/directory.proto`:

```text
SignedGatewayDirectory {
  envelope_version = 1
  signing_key_id
  payload = exact serialized onionroute.directory.v1.GatewayDirectory bytes
  signature_algorithm = ED25519
  signature
}
```

Signature input без дополнительного hashing/application encoding:

```text
ASCII("onionroute-directory-v1") || 0x00 || payload
```

Используется стандартная Ed25519 implementation из прошедшей review библиотеки.
Подписываются точные `payload` bytes. Verifier сначала извлекает bounded envelope,
проверяет key/algorithm/signature над исходными bytes и только затем декодирует
payload. Reserialization для проверки запрещена: protobuf serialization не является
универсальной canonical form, а unknown fields могут потеряться.

Payload содержит:

- `format_version` — major/minor schema;
- monotonic `sequence` в одном signing lineage;
- `issued_at` и hard `valid_until`;
- bounded `GatewayDescriptor[]`;
- заранее заверенные `next_signing_keys` для ротации.

Descriptor содержит только public gateway metadata: случайный catalog `gateway_id`,
country, roles, Tor v3 service ID/port, supported protocol versions, TLS SPKI SHA-256,
capabilities, coarse capacity bucket и validity. Account/client data и clearnet IP
gateway не входят в client catalog.

Порядок проверки:

1. Envelope encoded size ≤ 2 MiB; обязательные поля присутствуют.
2. `envelope_version == 1`, algorithm известен, `signing_key_id` есть в pinned/
   previously-authorized keyring и действителен по времени.
3. Signature проверена над domain separator + exact payload.
4. Payload size ≤ 2 MiB; decode без trailing/ambiguous framing.
5. Supported `format_version`; time window валиден с консервативным clock policy.
6. `sequence >= highest_accepted_sequence`; равный sequence допустим только если
   payload hash совпадает, иначе equivocation error.
7. Gateway/list/string bounds, uniqueness, roles, v3 ID, TLS pin и validity.
8. `next_signing_keys` принимаются только после всех предыдущих проверок.
9. Payload и highest sequence атомарно записываются в secure storage; только после
   commit каталог публикуется consumer-ам.

Cache допустим до `valid_until`; grace period после expiry отсутствует. Ошибка новой
подписи не удаляет valid cache. Emergency root replacement требует signed update
действующим root либо явного product upgrade/reprovisioning; download по TLS сам по
себе не авторизует новый root.

## 7. Control/data compatibility firewall

- `gateway.proto` импортирует только `common.proto`, никогда `control.proto`.
- `control.proto` может возвращать opaque blind-signature result и signed public
  directory, но ни один объект с authenticated account context не сериализуется в
  gateway request.
- Gateway token verifier получает issuer public keys через operator distribution,
  не выполняет account lookup при redemption.
- CI descriptor check запрещает identity-like fields в `onionroute.gateway.*` и
  arbitrary labels в `onionroute.health.*`.

## 8. Support window и rollout

- Production server поддерживает текущий gateway major и предыдущий major минимум
  12 месяцев после stable release нового major, если нет documented critical flaw.
- Directory публикует endpoints/protocols для обоих major во время окна.
- Client release поддерживает текущий major и предыдущий, но выбирает highest common.
- Minor rollout: readers first → directory advertisement → writers. Новый field
  записывается только после распространения совместимых readers.
- Major rollout: parallel endpoint/package/service, canary, compatibility matrix,
  migration metric без user identifiers, затем signed deprecation date.
- Экстренное прекращение уязвимой версии допускается только signed control policy и
  приводит к fail-closed `FatalError`/upgrade required, не к downgrade/fallback.

Breaking checks выполняются по last released descriptors (`buf breaking` или
эквивалент). Golden-byte tests обязаны покрывать hello, auth, TCP/DNS, error,
directory signature и unknown-field behavior.

## 9. Rust contract versioning

Rust API живёт в `contracts::v1`. Все component traits наследуют
`VersionedContract`; baseline — `ContractVersion { major: 1, minor: 0 }`.

- Новый обязательный trait method, изменение signature/semantics, Send/Sync или
  ownership requirements — breaking change и новый `contracts::v2`/ADR.
- Minor revision может добавить тип, helper либо trait method с безопасной default
  implementation. Implementer сообщает фактический minor.
- Старые modules не удаляются, пока действует support window. Adapters позволяют
  `client-core` одновременно работать с v1/v2 implementations.
- Generated protobuf types не входят в `common-types`; wire adapter является внешним
  implementation и тем самым не создаёт dependency cycle.

Любое изменение public contract включает: ADR, owner review, compatibility analysis,
updated mock, contract test, bounds, error mapping и privacy classification.
