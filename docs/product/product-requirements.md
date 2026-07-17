# OnionRoute: продуктовые требования и позиционирование

## 1. Продуктовое обещание

OnionRoute — **system-wide Tor client** и **Tor-based privacy tunnel** для
поддерживаемого системного TCP- и DNS-трафика. В режимах с частной инфраструктурой
Tor приводит соединение к **private onion gateway**, после чего трафик выходит в
Internet через управляемый шлюз. Для таких режимов продукт предлагает
**country-selectable Tor egress**.

Короткая формулировка для первого экрана:

> Системный Tor-клиент для поддерживаемого TCP-трафика. OnionRoute направляет трафик
> через Tor и выбранный частный шлюз, блокируя прямой fallback при сбое.

Пояснение рядом с любым сравнением с VPN:

> OnionRoute выглядит как VPN-клиент, потому что создаёт системный туннель, но между
> устройством и выходом используется Tor, а не WireGuard, OpenVPN или IPsec.

## 2. Цели MVP

OnionRoute MUST:

- перехватывать поддерживаемый системный TCP-трафик;
- разрешать DNS только внутри защищённого маршрута;
- блокировать прямой clearnet fallback при connect, reconnect, rotation, crash и
  shutdown;
- до первого подключения объяснять, что произвольный UDP не поддерживается, а QUIC
  блокируется;
- показывать фактически активный режим и выбранную страну private exit;
- не переходить незаметно на другой режим или страну;
- отделять account/billing plane от data plane;
- сообщать ограничения каждого режима на том же экране, где режим выбирается;
- выдавать безопасные, конкретные и не содержащие чувствительных данных ошибки.

## 3. Не-цели и запрещённые обещания

OnionRoute не обещает:

- абсолютную анонимность или невозможность деанонимизации;
- невозможность отслеживания или end-to-end timing correlation;
- «военный уровень» защиты;
- скорость выше VPN или Tor;
- гарантированную страну, конкретный IP или совпадение всех GeoIP-баз;
- невозможность блокировки Tor, onion services или gateway;
- защиту скомпрометированного устройства;
- удаление cookies, логинов, browser fingerprint или account identity сайта;
- поддержку произвольного UDP, QUIC, BitTorrent или SMTP на TCP/25;
- защиту трафика, который пользователь явно исключил через split tunneling.

Если один из этих тезисов нужен в сравнительном материале, рядом MUST быть видимое
пояснение ограничения. Сноска, tooltip или ссылка после CTA недостаточны.

## 4. Аудитории и основные задачи

1. Пользователь публичной сети хочет направить системный TCP и DNS через Tor без
   прямого fallback.
2. Пользователь хочет выбрать страну управляемого private exit, понимая, что
   доступность и стороннее GeoIP-определение не гарантированы.
3. Пользователь чувствительного сценария хочет разделить управляемые gateway roles,
   принимая дополнительную задержку и остаточный риск корреляции.
4. Пользователь хочет сменить сетевой маршрут, не считая это очисткой browser/app
   identity.
5. Пользователь хочет исключить приложение из туннеля и заранее видеть, что оно
   сможет раскрывать реальный IP и DNS вне OnionRoute.

## 5. Режимы

Названия — это конфигурации маршрута, а не числовая шкала гарантированной
анонимности. UI SHOULD использовать заголовок «Режим маршрута», а не «Уровень
анонимности».

| Режим | Каноническое описание в UI | Маршрут | Честное ограничение |
|---|---|---|---|
| Standard | **Лучший баланс для большинства сценариев.** Tor и один private exit gateway; ниже задержка среди режимов с частным шлюзом. | `User → Tor → private exit → Internet` | Exit видит назначение, но по дизайну не получает account ID или реальный IP клиента. |
| Enhanced | **Entry и exit разделены.** Дополнительная административная граница уменьшает объём данных у одного private gateway; скорость обычно ниже. | `User → Tor → entry → encrypted transport → exit → Internet` | Не защищает от сговора entry и exit или глобальной корреляции. |
| Maximum | **Дополнительные управляемые hops.** Максимальная ожидаемая задержка; только для чувствительных сценариев, где важнее разделение ролей. | `User → Tor → entry → relay → exit → Internet` | Больше hops не означает абсолютную анонимность и не устраняет timing correlation. |
| Direct Tor | **Tor с публичным Tor exit.** Может быть больше CAPTCHA и блокировок; выбор страны private gateway недоступен. | `User → Tor → public Tor exit → Internet` | Страна выхода не гарантируется; публичный exit видит назначение и незашифрованный прикладной трафик. |

Требования выбора режима:

- Standard MUST быть рекомендованным режимом по умолчанию.
- Enhanced и Maximum MUST показывать ожидаемое увеличение задержки до подтверждения.
- Maximum MUST иметь пояснение «не защищает от глобального наблюдателя» без
  дополнительного раскрытия.
- Direct Tor MUST отключать country selector и объяснять причину.
- Недоступность topology выбранного режима MUST сохранять прежний подтверждённый
  маршрут или блокировать новые соединения; silent downgrade запрещён.

## 6. Требования к состояниям и решениям пользователя

- Статус «Подключено» разрешён только при подтверждённых kill switch, Tor route,
  gateway topology (кроме Direct Tor) и protected DNS.
- UI MUST различать: «Подключено», «Переподключение — трафик заблокирован»,
  «Предыдущий защищённый маршрут активен — новое изменение не применено» и
  «Заблокировано из-за ошибки защиты».
- Статус MUST показывать активные, а не только выбранные mode/country.
- Любой выбор, повышающий раскрытие — Direct Tor или исключение приложения — требует
  явного действия пользователя и локального предупреждения.
- Ошибка MUST предлагать безопасное действие: повтор, проверку времени/сети,
  обновление directory/token, выбор другой страны пользователем или диагностику.
- Отключение kill switch не предлагается как recovery action.

## 7. Информационная архитектура

До первого connect пользователь MUST увидеть:

1. что OnionRoute использует Tor и отличается от обычного VPN;
2. что MVP поддерживает TCP и protected DNS, но блокирует arbitrary UDP/QUIC;
3. ограничения выбранного режима;
4. смысл country selection;
5. fail-closed поведение kill switch;
6. риск split tunneling.

В основном окне MUST быть доступны активный маршрут, страна/Automatic, статус Tor,
статус gateway, состояние kill switch и ссылка «Что поддерживается».

## 8. Реестр проверяемых утверждений

Ни одно утверждение ниже нельзя публиковать как факт только на основании design doc.

| Claim | Разрешённая формулировка | Evidence gate |
|---|---|---|
| System-wide Tor client | «Направляет поддерживаемый системный TCP и DNS через Tor» | Platform-specific TUN/packet-tunnel coverage; IPv4/IPv6/DNS/QUIC leak tests; documented OS exclusions. |
| Tor-based privacy tunnel | «Использует Tor для клиентской части защищённого маршрута» | Integration capture показывает только разрешённый Tor bootstrap/traffic на physical interface; direct socket backend отсутствует. |
| Private onion gateway | «Подключается к управляемому private gateway через Tor v3 onion service» | Проверены v3 onion endpoint, terminal TLS pin, role, loopback-only ingress и отсутствие публичного proxy listener. |
| Country-selectable Tor egress | «Пытается использовать доступный private exit в выбранной стране» | Подписанный directory role/country; фактический egress probe; UI для unavailable; отсутствует automatic wrong-country fallback. |
| Fail-closed | «При потере защищённого маршрута поддерживаемый трафик блокируется» | Leak tests connect/rotation/reconnect/crash/shutdown/network change и независимая verification firewall lease. |
| Protected DNS | «DNS обрабатывается внутри защищённого маршрута» | System resolver negative tests; DNS timeout возвращает local failure; approved exit resolver evidence. |
| Account/data separation | «Gateway не получает account, email или payment ID по штатному протоколу» | Schema audit, IAM/network separation и no-join integration test. Это не равно криптографической несвязываемости issuance/redemption. |
| No destination logging | «Мы не сохраняем историю сайтов, DNS или содержимое трафика» | Closed schema audit, negative canary, core-dump prohibition, TTL/backup restore evidence и независимый review. |
| Mode role separation | «Enhanced/Maximum разделяют gateway roles» | Подписанный directory, distinct role identities/failure domains и route conformance tests; для Maximum — независимые admin/KMS domains до claim «разные операторы». |

Marketing owner MUST хранить рядом с каждым опубликованным claim ссылку на test ID,
дату последней проверки, платформу и версию. Просроченный или неполный evidence
понижает текст до «планируется» либо удаляет его.

## 9. Критерии приёмки продукта

- Неспециалист после onboarding может правильно ответить, поддерживается ли UDP.
- Ни один экран режима не обещает защиту от глобальной корреляции.
- Country selector нигде не использует слова «гарантированно» или «точное
  местоположение».
- Identity reset до подтверждения сообщает о закрытии соединений и сохранении
  cookies/logинов/fingerprint.
- Split-tunnel исключение показывает конкретное следствие: direct IP и system DNS.
- Тексты логирования перечисляют данные, место, цель и TTL, а не говорят только
  «минимальные логи».
- Все ошибки из [канонического реестра](error-copy.md) имеют безопасное первичное
  действие и не предлагают отключить kill switch.
- Release claims имеют актуальное техническое доказательство.

## 10. Предположения

- Документы описывают MVP с TCP и protected DNS; будущая поддержка UDP требует
  нового threat/privacy review и обновления copy.
- Страна gateway означает страну, заявленную и проверенную оператором в signed
  directory, а не гарантию внешней GeoIP-классификации.
- Private gateway roles управляются OnionRoute; независимость операторов между
  hops пока не заявляется без infrastructure evidence.
- Privacy promises являются release requirements. Текущий non-blind MVP token
  profile остаётся experimental и не позволяет заявлять issuer unlinkability.

