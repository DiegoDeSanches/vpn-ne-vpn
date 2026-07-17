# OnionRoute error model v1

Цель error model — одинаковое fail-closed решение в `client-core`, стабильные
contract tests и безопасная диагностика без чувствительных данных.

## 1. Структура ошибки

Внутренний `OnionError` содержит только:

- `domain`: компонентная область;
- `code`: стабильный machine-readable код;
- `severity`: `Warning`, `Error` или `Fatal`;
- `retry`: класс восстановления;
- `safety`: `Protected`, `MustBlock` или `NotApplicable`;
- `message`: статическая redacted строка.

Wire `ErrorStatus` содержит `code`, coarse category, retry hint и случайный
boundary-local correlation ID. Он не переносит внутренний stack trace. Account ID,
IP, hostname, DNS/payload bytes, token, session/route/flow ID и gateway onion address
запрещены в message, context, tracing fields и metrics labels.

## 2. Taxonomy

| Domain | Типичные коды | Владелец классификации |
|---|---|---|
| `Configuration` | `InvalidConfiguration` | client-core/config provider |
| `Platform` | `PlatformUnsupported` | platform shell |
| `KillSwitch` | `KillSwitchApplyFailed`, `KillSwitchVerificationFailed` | platform KillSwitch adapter |
| `Tor` | `TorBootstrapTimeout`, `TorUnavailable`, `TorStreamFailed` | TorBackend/CircuitManager |
| `Directory` | `DirectoryUnavailable`, `DirectorySignatureInvalid`, `DirectoryExpired`, `DirectoryRollback`, `GatewayUnavailable` | GatewayDirectoryProvider/PolicyEngine |
| `Authentication` | `TokenUnavailable`, `TokenRejected` | TokenProvider/GatewayConnector |
| `Gateway` | `GatewayIdentityMismatch`, `SessionExpired`, `GatewayTimeout`, `ProtectedPathLost` | GatewayConnector |
| `Packet` | `Backpressure`, `UnsupportedTransport` | PacketEngine |
| `Dns` | `DnsResolutionFailed`, `DnsLeakDetected` | DnsEngine/leak monitor |
| `Policy` | `PolicyDenied` | PolicyEngine |
| `Storage` | `StorageUnavailable`, `StorageCorrupt` | SecureStorage |
| `ControlPlane` | `DirectoryUnavailable`, `TokenUnavailable`, `Backpressure` | providers/control client |
| `Protocol` | `ProtocolIncompatible`, `MessageTooLarge`, `ProtocolViolation` | boundary decoder/negotiator |
| `Internal` | `RotationDeferred`, `ShutdownTimeout`, `InvariantViolation` | orchestrator or invariant owner |

Новый code добавляется только вместе с recovery rule, redaction test и mapping в
wire category. Существующий code не меняет смысл в пределах major contract.

## 3. Retry и safety

Retry classes: `Never`, `Immediate` (не более двух попыток), `Backoff` (full jitter,
bounded exponential), `AfterDirectoryRefresh`, `AfterTokenRefresh`, `UserAction`.
Retry budget задаётся верхней операцией; вложенные компоненты не создают собственные
бесконечные циклы.

Safety имеет приоритет над retry. `MustBlock` всегда вызывает `emergency_block` и
переход `Blocked`, даже если ошибка формально retryable. `Protected` разрешает
сохранить старую здоровую session или reconnect под действующим kill switch.
`NotApplicable` допустим только до успешного `ApplyingKillSwitch`.

Default recovery реализован функцией `state::recovery_action`:

1. `MustBlock` → `EnterBlocked`.
2. `Fatal` → `EnterFatal`.
3. Rotation failure при здоровом old path → `KeepOldSession`.
4. Invalid new directory signature при valid cache → отвергнуть update и retry.
5. Иначе следовать retry class.

## 4. Failure scenarios

Ниже нормативный minimum; каждый сценарий имеет integration или security test ID.

| ID | Сбой | Code / safety | Переход и восстановление |
|---|---|---|---|
| F01 | Некорректный mode/policy до connect | `InvalidConfiguration` / N/A | `Preparing → FatalError`; сеть не менялась |
| F02 | Platform не поддерживает atomic firewall | `PlatformUnsupported` / MustBlock | `ApplyingKillSwitch → Blocked`; connect запрещён |
| F03 | Применение kill switch частично завершилось | `KillSwitchApplyFailed` / MustBlock | emergency block, `Blocked`, user/admin action |
| F04 | Независимая проверка rules не совпала с lease | `KillSwitchVerificationFailed` / MustBlock | emergency block; Tor не запускается |
| F05 | Crash оставил старые rules | none if recoverable | `Preparing`; `recover` сохраняет block и выдаёт новую generation |
| F06 | Tor bootstrap timeout | `TorBootstrapTimeout` / Protected | `BootstrappingTor → Reconnecting`, bounded backoff; KS остаётся |
| F07 | Tor process/Arti завершился в Connected | `TorUnavailable` / Protected | `Connected → Reconnecting`; новые flow отвергаются |
| F08 | Onion stream не открылся | `TorStreamFailed` / Protected | выбрать новый isolated circuit/gateway с backoff |
| F09 | Нет cache и directory service недоступен | `DirectoryUnavailable` / Protected | `LoadingDirectory → Reconnecting`; traffic blocked |
| F10 | Новый каталог имеет плохую подпись | `DirectorySignatureInvalid` / Protected | update отвергается; valid cache остаётся, иначе reconnect |
| F11 | Каталог hard-expired | `DirectoryExpired` / Protected | не выбирать gateway; refresh; без успеха reconnect |
| F12 | Sequence ниже сохранённого | `DirectoryRollback` / Protected | документ отвергнуть, security event без payload; refresh другого origin |
| F13 | Gateway count/string/list превышает limit | `MessageTooLarge` / Protected | отвергнуть весь каталог до allocation-heavy decode |
| F14 | Нет role/country/capability combination | `GatewayUnavailable` / Protected | один refresh, затем `Degraded` при old path или reconnect |
| F15 | TLS SPKI не совпал с каталогом | `GatewayIdentityMismatch` / Protected | немедленно закрыть transport, invalidate descriptor, security backoff |
| F16 | Нет общего protocol major/minor | `ProtocolIncompatible` / Protected | другой gateway; если весь каталог несовместим — `FatalError` upgrade required |
| F17 | Token service недоступен | `TokenUnavailable` / Protected | bounded backoff; old session работает до TTL |
| F18 | Gateway отверг token как expired/spent | `TokenRejected` / Protected | invalidate, один fresh token; затем другой gateway/backoff |
| F19 | Gateway frame > 64 KiB или DATA > 32 KiB | `MessageTooLarge` / Protected | protocol session закрывается; reconnect к другому gateway |
| F20 | Повтор sequence, неизвестный critical feature, invalid stream ID | `ProtocolViolation` / Protected | session fail; никаких частичных permissive actions |
| F21 | Session heartbeat timeout | `GatewayTimeout` / Protected | `Connected → Reconnecting`; KS блокирует новые flow |
| F22 | Session/token hard TTL истёк | `SessionExpired` / Protected | scheduled make-before-break; expired session не re-auth |
| F23 | Rotation candidate не построен, old path здоров | `RotationDeferred` / Protected | `Rotating → Degraded`, old path остаётся, jitter retry |
| F24 | Rotation failed и old path потерян | `ProtectedPathLost` / Protected | `Rotating → Reconnecting`; packet events reject/backpressure |
| F25 | Packet queue/session window исчерпаны | `Backpressure` / Protected | pause reads, reject new flow; memory bound не расширять |
| F26 | UDP/QUIC/BitTorrent/SMTP25 request | `UnsupportedTransport` или `PolicyDenied` / Protected | локальный reject; никакого fallback |
| F27 | Protected DNS timeout/malformed response | `DnsResolutionFailed` / Protected | SERVFAIL/local failure; system resolver не вызывается |
| F28 | Обнаружен system DNS во время tunnel | `DnsLeakDetected` / MustBlock | emergency block, `Blocked`, security diagnostic |
| F29 | Secure storage временно недоступно | `StorageUnavailable` / MustBlock для trust/rollback state | `Preparing/LoadingDirectory → Blocked`; не сбрасывать state |
| F30 | Secure storage integrity failure | `StorageCorrupt` / MustBlock, Fatal | emergency block, `FatalError`, controlled reprovision |
| F31 | Shutdown drain timeout | `ShutdownTimeout` / MustBlock до cleanup | force-close resources; KS снимается только после verify |
| F32 | Невозможный state transition/lease mismatch | `InvariantViolation` / MustBlock, Fatal | emergency block, `FatalError`; crash-safe diagnostic |
| F33 | Health collector недоступен | control-plane warning / Protected | bounded local drop/aggregate; connection не ухудшается |
| F34 | Clock сильно отклонён, validity нельзя доказать | `DirectoryExpired` / Protected | не принимать новый catalog/token; user action, traffic blocked |
| F35 | Exit DNS rebinding ведёт в forbidden range | `PolicyDenied` / Protected | flow блокируется после повторной IP policy check |

## 5. State-specific recovery

- До `ApplyingKillSwitch`: безопасно вернуться через `Disconnecting` в
  `Disconnected`, если OS state подтверждён чистым.
- В `ApplyingKillSwitch`: ошибка всегда `Blocked`; нельзя продолжать Tor bootstrap.
- В bootstrap/directory/select/auth: retries выполняются с engaged и verified kill
  switch. Пока нет Active session, packet engine не принимает пользовательский flow.
- В `Connected`: частичная потеря health → `Degraded`; потеря единственного protected
  path → `Reconnecting`; uncertain firewall/DNS protection → `Blocked`.
- В `Rotating`: успех атомарно меняет default session; ошибка не закрывает healthy old
  session. Старый DNS cache очищается только после готовности replacement.
- В `Disconnecting`: любая ошибка удаления firewall rules означает `Blocked`, не
  `Disconnected`.
- Из `FatalError` автоматический reconnect запрещён; разрешён только cleanup через
  `Disconnecting` и явное действие/upgrade/reprovision.

## 6. Boundary mapping

Внешний peer не должен узнавать внутреннюю топологию. Gateway переводит internal
errors в ограниченный registry: `INVALID_INPUT`, `UNSUPPORTED`, `UNAVAILABLE`,
`AUTHENTICATION`, `POLICY`, `PROTOCOL`, `RESOURCE_EXHAUSTED`, `INTERNAL`. Например,
Tor errors никогда не уходят Internet peer, а token rejection не различает unknown,
expired и spent для клиента сверх общего `TokenRejected`.

Correlation ID создаётся заново на каждой trust boundary. Он не переносится между
account issuance, token redemption, gateway session и health report.

## 7. Тестовые требования

- Unit test для каждого mapping `origin → code/retry/safety`.
- Property test: `MustBlock` никогда не выдаёт recovery, разрешающий traffic.
- Snapshot test redaction всех error/debug/tracing fields.
- Fuzz decoder: malformed frame не вызывает panic, unbounded allocation или rich
  error echo.
- Integration test всех F01–F35; наиболее критичные F03/F04/F15/F19/F28/F30/F32
  выполняются также как fault-injection/security tests.

