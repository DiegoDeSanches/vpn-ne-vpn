# OnionRoute: обязательная privacy model

- Статус: normative, release-blocking.
- Версия: 1.0.
- Дата: 2026-07-17.
- Владельцы: `security/threat-model` (policy), владельцы систем (enforcement), `qa/integration` (verification).

## 1. Цель и запреты верхнего уровня

Privacy goal OnionRoute — не позволять штатной системе или роли одновременно получать account/payment identity,
реальный IP клиента и destination. Это уменьшение коррелируемости, а не обещание абсолютной анонимности.

Обязательные запреты:

- нет user-level network analytics;
- нет persistent destination/DNS/payload logging;
- нет реального IP, account, device или payment ID в data plane;
- нет payment-to-session join key — явного, хешированного, зашифрованного или вычислимого;
- нет общего correlation/session/request ID между billing/control issuance, telemetry и gateway redemption;
- нет arbitrary telemetry labels, URL, hostname, IP, token, onion ID, route/isolation/session ID;
- нет silent consent, forced telemetry или privacy-ослабления в debug/incident mode;
- нет объединённого data lake, IAM role или backup domain для billing и network telemetry.

Если функция требует нарушить запрет, она не реализуется до нового privacy review, LINDDUN update, ADR и явного
изменения product promise. Согласие пользователя не легализует destination history или payment-to-session join.

Текущий параллельный [component review tokens](auth-tokens-threat-model.md) описывает MVP issuance как не blind,
что конфликтует с ADR-0003 и требованиями этой модели. Разделение middleware/issuer уменьшает случайные утечки,
но не даёт криптографической unlinkability от скомпрометированного control service. Такой профиль остаётся
experimental и release-blocked до blind issuance, independent review и тестов ST-054/ST-056.

## 2. Принципы

### Data minimization

Собирать можно только поле из утверждённой schema registry с назначением, owner, TTL, sensitivity и тестом.
Отсутствующее поле запрещено. IP/hostnames/DNS/payload/token/session/account identifiers не редактируются после
сбора — они вообще не должны попадать в event. Метрика, необходимая только для удобства анализа, не является
достаточной целью.

### Purpose limitation

Каждый dataset имеет одну цель: account/billing, token issuance, gateway authorization, operational health,
security admin audit или support по запросу. Вторичное использование, ML training, advertising, user scoring,
fraud enrichment внешними datasets и cross-purpose joins запрещены без нового review. Abuse controls могут
ограничивать текущий anonymous capability, но не создавать историю посещений.

### Separation of duties

Billing/account, token issuer, gateway redemption, directory signing, observability, update signing и production
operations используют разные service accounts, keys, stores, deployment roles и approvers. Ни одна штатная роль
не читает одновременно billing rows и gateway/client telemetry. Break-glass требует двух лиц, TTL и audit.

### Coarse telemetry

Client telemetry выключаема, отправляется через Tor, использует закрытые enums и случайный одноразовый report
nonce. Временные отметки округляются минимум до суток на клиенте и отправляются с jitter; gateway operational
metrics агрегируются минимум в часовые buckets. Перед доступом аналитика применяется cohort threshold `k >= 100`;
малые cohorts объединяются в `other` или подавляются. Country, gateway, plan и error нельзя комбинировать так,
чтобы получить редкий набор. Individual event drill-down отсутствует.

### Deletion verification

TTL — свойство primary, replicas, queues, search indexes, caches, object storage, snapshots и восстановлений.
Удаление подтверждается автоматическим manifest/counter evidence без содержимого записи. Ежеквартальный restore
test обязан доказать, что просроченные records не возвращаются. Для immutable backup применяется documented
cryptographic erasure/expiry; legal hold разрешён только для billing records и не распространяется на network data.

## 3. Классы данных и TTL

TTL начинается с указанного события; более длинный срок запрещён. Более короткий допустим. `Не собирать` означает
отсутствие persistence, structured event, packet capture, core dump и third-party export.

| Данные | Где допустимы | Цель | Persistence / TTL | Запрещено |
|---|---|---|---|---|
| Destination IP/hostname/port и DNS wire | Только volatile client core и terminal exit на время flow | Выполнить текущий flow/query | Не собирать; volatile state уничтожить не позднее 60 секунд после close/timeout | Logs, metrics, traces, audit, support bundle, backups, blocklist history |
| Payload/packet bytes | Application, volatile transport buffers | Передача текущего потока | Не собирать; bounded buffer zeroize/release при close, core dumps off | DPI capture, debug dump, sampling, analytics |
| Реальный IP клиента | Локальная OS; неизбежно access ISP/Tor guard | Network access | OnionRoute stores: не собирать | Gateway/control/telemetry field, proxy access log |
| Tor source IP на control endpoint | Frontend может технически видеть Tor exit | DDoS transport only | Не писать в app logs; volatile rate state максимум 10 минут | Account enrichment, long-lived hash, export |
| Account/email/entitlement | Account/control domain | Authentication, subscription support | Пока account активен; удалить/анонимизировать в 30 дней после запроса, кроме legal billing records | Data plane, telemetry, directory, token body |
| Payment record | Billing domain | Оплата, возвраты, statutory accounting | Только минимальный законный срок по юрисдикции; documented schedule | Session/network timestamps, gateway/mode/country/token fields |
| Blinded token request | Token service volatile memory | Blind issuance | Не собирать; удалить после ответа/timeout, максимум 60 секунд | Logs, traces, retry store с account linkage |
| Unblinded capability token | Client secure storage; gateway volatile verifier | Authorization | Token lifetime максимум 15 минут; client удаляет в течение 1 часа после expiry/redemption | Logging, crash reports, reuse between hops |
| Issuance transaction | Account-side control store | Quota, billing dispute, issuer abuse | 30 дней; только account, coarse capability class, result и day bucket | Token bytes/nullifier, gateway, session, route, exact redemption time |
| Redemption nullifier | Gateway-local replay store | Запрет replay | До `exp + 5 min` clock skew; hard-delete не позднее 24 часов после expiry | Account/issuance reference, destination, cross-gateway global ID |
| Gateway session/stream/isolation ID | Volatile component-local state | Multiplexing/lifecycle | Не собирать; удалить ≤60 секунд после teardown | Cross-service propagation, telemetry, support bundle |
| Local split-tunnel allowlist | Устройство | Пользовательская routing preference | До удаления пользователем/app uninstall; только local encrypted settings | Control/data telemetry или account sync без отдельного review |
| Client health report | Health ingest через Tor | Coarse reliability | Raw queue ≤24 часа; approved aggregate ≤30 дней | Stable ID, account/IP/session/gateway/destination, arbitrary labels |
| Gateway counters | Gateway-local then separate collector | Capacity/reliability/security aggregate | Local raw buckets ≤1 часа; aggregate ≤30 дней | Per-token/per-session/per-destination drill-down |
| Closed-schema operational log | Соответствующий isolated service | Диагностика coarse state/errors | 7 дней online, затем delete; security aggregate без identifiers ≤30 дней | Destination/DNS/token/IP/account/session/route/onion address |
| Admin/KMS/signing audit | Isolated immutable audit | Accountability privileged actions | 365 дней, затем delete unless regulatory requirement documented | User network data or shared query with billing/network stores |
| Support bundle | Локально, затем isolated support intake по явному действию | Конкретный support case | До отправки — по контролю пользователя; server copy 7 дней | Secure storage, packet capture, destination, token, silent upload |
| Public signed directory | Public CDN/client cache | Gateway discovery | До expiry на клиенте; public history допустима | Client/account targeting fields или per-client variant без transparency |
| Abuse in-memory digest/counter | Один gateway process | Rate/fanout/current-token abuse | Максимум 10 минут, keyed per-process secret, purge on restart | Destination list, stable user fingerprint, central history |

Значение token TTL является security profile, не изменением текущего opaque wire contract. До утверждения
алгоритма и profile через security review gateway остаётся reject-all. Если business/legal owner не может назвать
точный законный срок billing record, запись не попадает в production schema.

## 4. Purpose и доступ

| Domain | Разрешено видеть | Не разрешено видеть | Production access |
|---|---|---|---|
| Account/billing | Account, entitlement, payment records | Token, nullifier, gateway/session/destination, network telemetry | Billing role; не gateway/observability role |
| Token issuance | Authenticated entitlement result, blinded request, coarse capability | Unblinded token, redemption, destination, gateway session | Token issuer role; key use через isolated service/KMS |
| Directory | Public inventory, pins, roles, capacity bucket | Account/client/payment/clearnet gateway IP | Publisher + separate two-person signing approvers |
| Client core | Локально account session, verified directory, unblinded token и current flows | Ничего не экспортирует как join | OS process boundary; secrets via secure storage |
| Entry/relay | Neighbor hop, volatile timing/bytes, role token | Destination/DNS/account/real IP | Gateway role-scoped service account |
| Exit | Current destination/DNS и volatile flow | Account/payment/real IP; persistent history | Exit role; no billing/control DB route |
| Health/observability | Approved coarse aggregates | Raw identifiers, destination, account/payment, token/session | Read-only aggregate analyst; no raw event access |
| Support | User-reviewed redacted bundle | Secure storage, destinations, packet captures, admin secrets | Ticket-scoped JIT access, 7-day auto-delete |
| Security operations | Coarse alerts/admin audit | Browsing history или payment/network join | JIT, MFA, two-person approval for capture/config changes |

## 5. No payment-to-session join key

Запрещены не только одинаковые UUID. Запрет охватывает:

1. account/payment/device ID, email, client IP или их hash/HMAC в gateway/health schema;
2. перенос issuance transaction/correlation/request ID в token bytes, redemption или client telemetry;
3. один и тот же random nonce/report ID между control и data plane;
4. общий encryption key/partition key, позволяющий привязать rows;
5. точные timestamps и уникальные capability combinations, делающие deterministic join практически возможным;
6. общий warehouse, search index, dashboard datasource, backup, IAM role или support export;
7. внешний analytics/ad-fraud identifier, доступный обоим доменам.

CI обязан сканировать protobuf/JSON/log/metric schemas и data-flow manifests. Integration test генерирует
issuance/redemption/health datasets и доказывает отсутствие общего и квази-уникального поля. Попытка добавить
такое поле требует contract proposal и всё равно блокируется privacy gate до независимого review.

## 6. Unique subscription fingerprinting

Token capabilities должны происходить только из versioned allowlist coarse profiles. Произвольные per-user
limits, exact expiry, country, promotion, payment channel и A/B cohort в token запрещены. Product owner до выпуска
профиля подтверждает account-side cohort не менее 1 000 активных subscriptions за 30 дней; это вычисление не
получает network events. Меньший cohort объединяется с общим профилем. Issuance time округляется/батчится, а
expiry не кодирует момент оплаты. Gateway не экспортирует capability distribution по малым buckets.

## 7. Access control и separation of duties

- MFA + hardware-backed admin identity; shared accounts запрещены.
- JIT grant максимум 1 час для production read и 15 минут для signing/KMS operation.
- Два разных человека одобряют directory root/update root/token issuer key operation и privacy-sensitive config.
- Deploy role не имеет query к telemetry; analyst не имеет shell/KMS; billing analyst не имеет gateway datasets.
- Gateway security groups не имеют route к account/billing/token issuance DB.
- Break-glass создаёт immutable alert, требует case ID, автоматически отзывается и не включает raw packet capture.
- Quarterly access review и immediate offboarding; unused grants revoke.
- Secrets и datasets разделены по environment; production не копируется в staging/developer systems.

## 8. Logging, tracing и error handling

Разрешённый event состоит из component/version, closed error/state enum, day/hour bucket согласно domain, queue/
duration bucket и random component-local nonce только на время обработки. Formatting untrusted values запрещено.
`Debug`, `Display`, panic, tracing span fields и metrics labels secret-bearing types проходят compile/test review.

Production build не имеет runtime switch для payload/DNS/destination logging. Изменение closed schema требует code
review от system owner и `security/threat-model`, generated schema diff и negative canary test. Ошибки клиенту
coarse; gateway не возвращает внутренние DNS/IP/policy детали, пригодные для enumeration.

## 9. Deletion lifecycle и доказательства

1. Dataset registry генерирует TTL policy и owner dashboard без row contents.
2. TTL worker публикует signed count/age evidence; oldest-row age не превышает TTL + 10%.
3. Queue/DLQ/search/cache имеют отдельные expiry assertions; DLQ не является бессрочным архивом.
4. Backup catalog хранит `expires_at` и key lineage. По expiry key уничтожается, объект удаляется по provider SLA.
5. Ежеквартально clean-room restore запускает policy scanner до подключения восстановленной системы к сети.
6. User deletion проверяется tombstone без распространения account ID в data plane.
7. Incident hold на network/destination data запрещён: таких данных не должно существовать. Legal hold применяется
   только в billing domain и не создаёт новые network joins.
8. Любое нарушение TTL — privacy incident и release/operations gate до remediation и проверенного удаления.

## 10. Privacy review gate для нового поля

До merge owner отвечает письменно:

- Какой единственный purpose и почему aggregate не подходит?
- Может ли поле прямо или совместно идентифицировать account, устройство, session, route или destination?
- Каков minimum TTL, deletion evidence, backup behavior и доступная роль?
- Можно ли поле соединить с billing/network domain по ID, времени, capability или key?
- Как пользователь узнаёт о сборе и может ли отключить необязательную telemetry?
- Какой LINDDUN threat и negative test обновлены?

Нет ответа или test ID — поле запрещено.

## 11. Privacy acceptance criteria

- Schema/static audit не находит destination, DNS, payload, IP, token, session/account/payment identity вне
  разрешённого volatile domain.
- Network и billing stores не имеют общего field, credential, warehouse, IAM principal или точного event clock.
- Telemetry достигает `k >= 100` до human query и не допускает user/session drill-down.
- Все TTL выполняются на primary, replicas, queues, exports и восстановленных backups.
- Support/incident/update paths соблюдают те же запреты, что normal operation.
- UX прямо сообщает об exit visibility, app-level identifiers, malicious device и global timing correlation.

Невыполнение любого пункта блокирует release согласно [release gates](release-gates.md).
