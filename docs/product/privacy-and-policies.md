# Privacy, threat model и политики

## Статус этого текста

Ниже приведены обязательные публичные тексты и release requirements. Они могут быть
опубликованы как описание работающего сервиса только после проверки соответствующих
privacy/security gates. До этого header MUST содержать `Предварительная архитектура;
production-гарантии ещё не подтверждены`.

## Краткая модель угроз

### Пользовательский текст

> OnionRoute разделяет знания о пользователе и его трафике между account plane, Tor
> и gateway roles. Это снижает возможность одной штатной роли одновременно увидеть
> account, реальный IP и назначение. Это не абсолютная анонимность.

| Сторона | Что может видеть | Чего OnionRoute не обещает скрыть от неё |
|---|---|---|
| Локальная сеть / ISP | Реальный IP, факт и время использования Tor, объём и pattern трафика | Сам факт Tor activity и доступность сервиса. |
| Tor guard | Реальный IP клиента и timing/volume Tor traffic | Guard compromise и долгосрочное наблюдение. |
| Промежуточный Tor relay | Соседние участки Tor route и timing | Активное замедление, tagging или denial of service. |
| Private entry/relay | Соседний hop, role-scoped session и временные timing/byte patterns | Сговор с другими hops или cloud observer. |
| Private exit | Текущее назначение/DNS и plaintext приложения, если нет end-to-end TLS | Destination visibility необходима для egress. Exit по дизайну не получает account ID или реальный IP клиента. |
| Public Tor exit в Direct Tor | Текущее назначение и незашифрованный application traffic | Поведение и reputation публичного exit. |
| Посещаемый сайт | IP exit, переданные данные, account/login, cookies и fingerprint | Сайт может узнать пользователя по прикладным идентификаторам. |
| Account/billing plane | Account, entitlement и необходимые payment records | Факт наличия account/subscription. По дизайну здесь нет destination history. |
| Глобальный наблюдатель | Может видеть оба конца и сопоставлять timing, объём и burst pattern | OnionRoute не заявляет защиту от end-to-end correlation или traffic confirmation. |

OnionRoute не защищает от root/kernel compromise устройства, вредоносного
приложения с доступом к содержимому, принуждения пользователя, собственных логинов и
cookies, а также ошибок сайтов. TLS/HTTPS остаётся необходимым: private gateway и
Tor exit не заменяют end-to-end encryption.

### Режимы и угрозы

- Standard отделяет access network от private exit посредством Tor, но exit видит
  назначение.
- Enhanced разделяет private entry и exit. Это уменьшает знание одного gateway, но
  collusion и timing correlation остаются.
- Maximum добавляет relay и административные границы. Он не является доказанной
  защитой от глобального пассивного наблюдателя.
- Direct Tor убирает private gateway, использует публичный Tor exit и не даёт
  country guarantee.

## Privacy account

### Публичный текст после прохождения release gate

> Account нужен для входа, подписки и поддержки. Account plane может хранить email,
> entitlement и минимальные платёжные записи. Private gateways не получают email,
> имя, account/payment ID или постоянный device ID через штатный data-plane
> протокол.

> Gateway авторизует короткоживущую capability, а не account. Billing и network
> telemetry используют разные хранилища, credentials, роли и backup domains; общего
> payment-to-session identifier нет.

Это обещание означает schema/IAM separation, а не отсутствие всех способов
корреляции. Точные времена issuance/redemption, редкие capability combinations,
скомпрометированные сервисы или collusion могут уменьшить anonymity set.

### Обязательное pre-release предупреждение о токенах

Пока blind issuance и тесты ST-054/ST-056 не пройдены, production-релиз блокируется.
Если experimental build доступен ограниченной аудитории, он MUST показывать:

> Экспериментальный account flow: текущий token service технически может
> сопоставлять выдачу capability с её содержимым или временем использования. Эта
> сборка не подтверждает криптографическую несвязываемость account и gateway session.

Слово `анонимный token` без этого пояснения запрещено для experimental profile.

## Privacy gateway

### Публичный текст

> Private exit должен знать текущее назначение, чтобы открыть соединение в Internet.
> Он может видеть DNS и незашифрованное содержимое приложения, если сайт или
> приложение не использует end-to-end TLS. По штатной схеме exit не получает
> реальный IP, email, account/payment ID или постоянный device ID пользователя.

> Destination, DNS, payload, token и session identifiers существуют только в
> ограниченном volatile state, необходимом для текущего соединения. Они не должны
> попадать в logs, metrics, traces, support bundles или backups.

Entry/relay не разрешено выполнять terminal DNS или Internet dial. Directory
signature подтверждает, что gateway разрешён оператором, но не доказывает его
честность. Защита от compromised gateway требует end-to-end TLS и независимой
операционной проверки.

## Конкретная политика логирования

Фраза «минимальные логи» без таблицы запрещена. Публичная policy MUST перечислять
поле/категорию, цель, место и срок.

| Категория | Сохраняется? | Где и зачем | Максимальный срок |
|---|---|---|---|
| История сайтов, destination IP/hostname/port, DNS wire | Нет | Только volatile client/exit state для текущего flow | Уничтожить не позднее 60 секунд после close/timeout; без persistence |
| Содержимое пакетов и application payload | Нет | Только bounded transport buffer | Освободить/очистить при close; core dumps и packet sampling выключены |
| Реальный IP клиента | Нет в системах OnionRoute | Необходим локальной OS; неизбежно виден ISP/Tor guard | Не записывать в gateway/control/telemetry/access logs |
| Account/email/entitlement | Да | Изолированный account/control domain | Пока account активен; удалить/анонимизировать в течение 30 дней после запроса, кроме обязательных billing records |
| Payment record | Минимально необходимое | Изолированный billing domain | Точный срок по каждой юрисдикции MUST быть опубликован до production; без network fields |
| Issuance transaction | Да, coarse | Quota, billing dispute, issuer abuse; account + result + day bucket | 30 дней; без token ID, gateway, route или redemption time |
| Capability token | Только client secure storage и volatile verifier | Короткоживущая авторизация | Lifetime ≤15 минут; client deletion ≤1 часа после expiry/redemption; не логировать |
| Replay nullifier | Да, gateway-local | Не принять capability повторно | До `exp + 5 min`; hard-delete ≤24 часов после expiry |
| Client health report | Только если telemetry включена | Coarse reliability через Tor; без stable ID/account/IP/session/gateway/destination | Raw queue ≤24 часов; approved aggregate ≤30 дней |
| Gateway counters | Coarse aggregate | Capacity/reliability | Local raw bucket ≤1 часа; aggregate ≤30 дней |
| Operational logs | Closed-schema states/errors | Диагностика сервиса | 7 дней online; identifier-free security aggregate ≤30 дней |
| Admin/KMS/signing audit | Да | Accountability privileged actions | 365 дней, затем удаление, если иной точный legal срок не опубликован |
| Support bundle | Только по явной отправке | Конкретный support case, после preview/redaction | Server copy 7 дней |
| Split-tunnel allowlist | Да, локально | Выбор пользователя | До удаления пользователем/uninstall; без account sync |
| Abuse rate/fanout state | Только volatile | Ограничить текущую нагрузку без истории | ≤10 минут, keyed per-process; purge on restart; наружу только coarse aggregate |

Запрещены user-level network analytics, destination/DNS/payload logging, общий ID
между billing и network data, точные cross-domain timestamps, произвольные labels,
silent telemetry и runtime debug-switch для packet/destination capture.

## Политика допустимого использования и abuse

### Публичный текст

OnionRoute предназначен для законной защиты приватности. Запрещено использовать
сервис для:

- несанкционированного доступа, сканирования и эксплуатации чужих систем;
- DDoS, credential attacks, malware/C2, phishing и распространения вредоносного
  содержимого;
- нарушения прав других лиц или применимого законодательства;
- BitTorrent в MVP;
- отправки SMTP через TCP/25;
- обхода protocol, port, rate, entitlement или gateway restrictions;
- перепродажи, кражи или повторного использования capabilities.

### Как применяется policy

OnionRoute блокирует запрещённые protocol/port/range classes, ограничивает число
текущих flows и нагрузку, может закрыть текущую anonymous session, временно
ограничить capability class или вывести gateway из directory. Anti-abuse не должен
создавать историю сайтов или stable user fingerprint.

Gateway может держать keyed in-memory rate/fanout state не более 10 минут. Key не
экспортируется и не связывает gateways. Внешние события — только coarse aggregate
без destination, token/nullifier, session, IP, port или account.

### Жалобы

Operator принимает жалобу, сохраняет сам ticket по его legal/support schedule и
может принять fleet/gateway/policy меры. По архитектуре exit event не содержит
mapping к account; policy не обещает идентифицировать пользователя по IP private
exit. Нельзя тайно включать destination или payload logging ради расследования.

Если безопасный контроль abuse требует такую слежку, продукт сокращает рискованную
возможность или отключает gateway, а не меняет privacy promise без review и
публичного уведомления.

## Transparency policy

### Обязательства

OnionRoute SHOULD публиковать transparency report каждые шесть месяцев и отдельное
уведомление о существенном privacy/security incident без неоправданной задержки.
Каждый report включает:

- период, дату публикации и применимые юридические лица/юрисдикции;
- число legal requests по типу, число удовлетворённых/оспоренных и категории реально
  раскрытых данных;
- число abuse complaints по coarse category и принятые fleet/policy меры;
- список действующих gateway countries и существенные изменения operators/failure
  domains;
- изменения logging, retention, abuse, token, directory и split-tunnel policies;
- security audits, их scope/date и статус исправлений без ложного слова `certified`;
- incidents/outages, повлиявшие на fail-closed или privacy controls;
- количество user deletion requests и долю завершённых в срок;
- перечень claims из реестра с версией последнего evidence.

Zero report публикуется с нулями, а не пропускается. Если закон запрещает раскрыть
деталь, report указывает существование ограничения настолько конкретно, насколько
разрешено. Warrant canary не используется без отдельного legal review: исчезновение
canary не является надёжным техническим доказательством.

### Изменения продукта

Существенное ослабление privacy policy, добавление UDP, нового identity field,
destination filtering/history, нового analytics vendor или payment/network join
требует до включения:

1. обновлённых threat/LINDDUN model и ADR;
2. публичного changelog с датой вступления;
3. migration/deletion plan;
4. новых negative tests и independent review;
5. явного уведомления пользователя, если меняется его риск.

## Deletion policy

### Запрос пользователя

Пользователь может запросить удаление account из приложения или support channel.
Сервис MUST:

1. подтвердить получение без раскрытия account третьему лицу;
2. прекратить новую token issuance и отозвать account sessions в control plane;
3. удалить/анонимизировать account/email/entitlement не позднее 30 дней;
4. удалить support bundles не позднее 7 дней независимо от общего account window;
5. удалить issuance records по их 30-дневному TTL;
6. сообщить категории и точные сроки billing records, которые требуется сохранить
   по закону;
7. подтвердить завершение по account-side tombstone, не распространяя account ID в
   data plane.

Network history не включается в export/deletion response, потому что она не должна
собираться. Это нельзя формулировать как «мы удалили историю сайтов», если такой
dataset не существовал; корректно: `OnionRoute не хранит историю сайтов, поэтому в
account deletion нет такого набора данных`.

### Реплики, очереди и backups

TTL применяется к primary DB, replicas, queues/DLQ, indexes, caches, object storage,
exports и backups. Backup имеет `expires_at` и key lineage; применяется физическое
удаление по provider SLA или документированное cryptographic erasure. Quarterly
clean-room restore MUST доказать, что expired records не возвращаются.

Legal hold допустим только для конкретных billing/admin records, если это требуется
законом. Он не создаёт и не удерживает network/destination data. Нарушение TTL —
privacy incident.

## Acceptance criteria

- Public privacy page содержит таблицу logging/TTL, а не только общий принцип.
- Exit visibility и необходимость HTTPS видны без перехода в полный threat model.
- Account privacy не называется `unlinkable`, пока blind issuance не проверена.
- Abuse policy не обещает невозможную attribution и не разрешает hidden logging.
- Transparency report имеет фиксированную периодичность и проверяемый состав.
- Deletion охватывает replicas/queues/backups и отделяет legal billing retention.

