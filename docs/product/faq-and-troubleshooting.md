# FAQ и устранение неполадок

## FAQ

### OnionRoute — это VPN?

OnionRoute создаёт системный tunnel и поэтому внешне похож на VPN-клиент. Но это
system-wide Tor client: поддерживаемый TCP и DNS идут через Tor. В Standard,
Enhanced и Maximum Tor приводит соединение к private onion gateway; WireGuard,
OpenVPN или IPsec между пользователем и сервером не используются.

### OnionRoute делает меня анонимным?

Он уменьшает объём данных, доступный одной штатной стороне, но не обеспечивает
абсолютную анонимность. ISP и Tor guard видят реальный IP и Tor activity; exit видит
назначение; сайт видит cookies, login и fingerprint; глобальный наблюдатель может
сопоставлять timing и объём. Скомпрометированное устройство обходит сетевые
гарантии.

### Чем отличаются режимы?

- Standard: Tor и один private exit; лучший баланс и меньшая задержка.
- Enhanced: private entry и exit разделены; выше задержка, меньше данных у одного
  gateway.
- Maximum: добавлен управляемый relay; максимальная задержка, только для
  чувствительных сценариев.
- Direct Tor: публичный Tor exit; больше CAPTCHA/блокировок, без private country
  selection.

Enhanced/Maximum не устраняют collusion или end-to-end timing correlation.

### Почему не работает UDP?

MVP передаёт TCP. Для безопасного произвольного UDP ещё нужны отдельные routing,
leak, backpressure и abuse controls. Поэтому UDP, включая QUIC/HTTP/3 и многие
WebRTC/game/voice flows, блокируется локально без прямого fallback.

### Почему сайт всё же открывается, если QUIC заблокирован?

Браузер может сам повторить HTTP/3-запрос по TCP с HTTP/2 или HTTP/1.1. Это решение
браузера; OnionRoute не отправляет QUIC напрямую.

### Поддерживается IPv6?

IPv6 не является разрешённым egress MVP и должен блокироваться, пока его
end-to-end поддержка и leak tests не подтверждены. Отсутствие parser support не
разрешает bypass.

### Почему выбранная страна определяется иначе?

OnionRoute выбирает private exit, заявленный в signed directory для выбранной
страны. Сторонний сайт использует собственную GeoIP-базу, которая может быть
устаревшей или классифицировать IP иначе. Выбор не гарантирует IP, город или доступ
к геоограниченному сервису.

### Может ли OnionRoute незаметно выбрать другую страну?

Нет. При ручном выборе другой country exit не является безопасным fallback. Если
compatible gateway недоступен, OnionRoute сохраняет предыдущий подтверждённый
маршрут либо блокирует новые соединения и предлагает выбор пользователю.

### Меняется ли IP при ротации?

Не гарантированно. Ротация создаёт fresh Tor isolation/gateway session для новых
connections, но тот же gateway может использовать тот же public egress IP. Уже
открытые TCP flows могут завершаться по прежнему маршруту.

### Что делает «Новая личность»?

Это hard reset сетевой сессии: active connections закрываются, создаётся новый Tor
isolation context, очищается временный DNS state и заменяется gateway session. Он не
удаляет browser cookies, логины, local storage или fingerprint и не гарантирует
новый IP/страну.

### Что видит private exit?

Текущее назначение и DNS, а без end-to-end TLS — также application plaintext. По
штатному data-plane протоколу exit не получает реальный IP, email, account/payment
ID или persistent device ID. HTTPS остаётся необходимым.

### Какие данные логируются?

OnionRoute не должен сохранять destination/DNS/payload и реальный IP клиента.
Closed-schema operational logs хранятся до 7 дней, identifier-free aggregates — до
30 дней, support bundle после явной отправки — 7 дней, admin audit — 365 дней.
Account data удаляются/анонимизируются в течение 30 дней после запроса, кроме
минимальных billing records с отдельно опубликованным законным сроком. Полная
таблица находится в [privacy policy](privacy-and-policies.md#конкретная-политика-логирования).

### Зачем нужен account, если gateway не знает пользователя?

Account plane проверяет подписку и выдаёт короткоживущую capability. Gateway
проверяет capability локально без account lookup. Но полную cryptographic
unlinkability можно заявлять только после blind issuance и независимых тестов;
текущий non-blind experimental profile для production заблокирован.

### Что делает kill switch?

Он блокирует трафик, предназначенный для OnionRoute, пока защищённый route не готов
или потерян. Rules устанавливаются и проверяются до Tor bootstrap и сохраняются во
время rotation/reconnect. System DNS и неподдерживаемый UDP не становятся fallback.

### Что происходит с исключённым приложением?

Оно работает по обычному маршруту вне OnionRoute и может раскрывать real IP,
system DNS и destinations. Kill switch OnionRoute намеренно не защищает явно
исключённый трафик. Allowlist хранится локально.

### Разрешён ли BitTorrent или SMTP?

Нет. BitTorrent запрещён policy, arbitrary UDP блокируется, исходящий SMTP TCP/25
запрещён. Обнаружение обфусцированного BitTorrent поверх TCP не заявляется как
идеальное, но это не меняет acceptable-use policy.

### Почему стало больше CAPTCHA?

Tor/public/private exit IP могут использовать многие соединения, и сайты применяют
собственные anti-abuse controls. Direct Tor обычно сталкивается с CAPTCHA чаще.
OnionRoute не может гарантировать доступность конкретного сайта.

### Может ли сеть заблокировать OnionRoute?

Да. ISP, local network, Tor blocking, onion-service DDoS или gateway outage могут
сделать маршрут недоступным. В таком случае продукт блокирует трафик вместо прямого
fallback; он не обещает невозможность блокировки.

## Безопасный порядок диагностики

1. Прочитайте точный статус: активен ли предыдущий защищённый маршрут или весь
   трафик заблокирован.
2. Нажмите `Повторить` один раз и дождитесь результата bounded retry.
3. Убедитесь, что обычное сетевое подключение существует и OS date/time/timezone
   корректны.
4. Проверьте системные разрешения tunnel/firewall и наличие обновления OnionRoute.
5. Если сеть блокирует Tor, попробуйте другую доверенную сеть. OnionRoute не должен
   открывать direct fallback.
6. Обновите signed directory/token через предложенное UI action.
7. Экспортируйте redacted diagnostics только после preview и отправьте support.

Не отключайте kill switch для диагностики. Это убирает fail-closed гарантию и не
исправляет Tor, gateway, directory или приложение.

## Tor не запускается

Симптом: `Tor не удалось подготовить`.

- Повторите подключение после backoff.
- Проверьте OS clock и доступность сети.
- Попробуйте другую доверенную сеть, если текущая блокирует Tor.
- Проверьте update приложения/Tor bundle.
- Если ошибка повторяется, отправьте redacted diagnostics.

До готовности Tor трафик остаётся заблокирован.

## Private gateway недоступен

- Повторите после directory refresh.
- При ручной стране откройте список и самостоятельно выберите другую страну либо
  `Автоматически`.
- При Enhanced/Maximum проверьте, доступен ли полный набор roles; приложение не
  должно незаметно перейти на Standard.
- Если старый healthy route активен, завершите важную работу до следующей попытки.

Прямое соединение и автоматический Direct Tor fallback запрещены.

## Directory устарел или время неверно

Expired directory нельзя использовать для нового gateway selection.

- Включите автоматические дату, время и timezone ОС.
- Нажмите `Обновить список шлюзов`.
- Проверьте доступность control connection.
- Не очищайте secure rollback state вручную; corruption/rollback требует controlled
  reprovision.

До подтверждения fresh signed directory новые соединения блокируются или остаются
на прежнем valid route.

## Доступ/token не обновляется

- Проверьте статус подписки в account screen.
- Нажмите `Обновить доступ` один раз.
- Проверьте OS time: capability короткоживущая и time-bound.
- Повторно войдите в account только если UI явно сообщает об account session, а не о
  gateway rejection.

Remote token rejection не должен раскрывать, был token unknown, spent или expired.
Gateway не получает account ID при refresh.

## Приложение работает частично или не работает

1. Откройте `Что поддерживается` и проверьте, требуется ли приложению UDP/QUIC,
   WebRTC, ICMP или запрещённый port/protocol.
2. В браузере временно отключите HTTP/3 только в самом браузере, если организация
   допускает это; OnionRoute всё равно продолжает блокировать QUIC.
3. Проверьте, поддерживает ли приложение TCP mode официально.
4. Не добавляйте приложение в split tunneling, не прочитав предупреждение о real
   IP/system DNS.

## Captive portal

OnionRoute не создаёт автоматическое firewall-исключение для portal: это могло бы
раскрыть другой трафик.

1. Нажмите `Проверить сеть снова` — иногда OS уже завершила авторизацию.
2. Если возможно, используйте другую доверенную сеть без portal.
3. Если portal требует прямой вход, сохраните работу и выберите явное
   `Завершить защищённое подключение`. Продолжайте только после статуса
   `Отключено — cleanup проверен`, выполните вход в portal и сразу подключите
   OnionRoute заново.

Это контролируемое завершение tunnel, а не отключение kill switch как способ
починки. UI не должен автоматически открывать portal или ослаблять rules в
protected state. Platform-specific безопасный captive flow остаётся release
requirement.

## Redacted diagnostics

До отправки пользователь видит manifest. Bundle MUST исключать:

- destinations, DNS wire, packet/payload, browser history;
- account/payment ID, token, nullifier, PoP material;
- real/client IP, gateway onion address;
- session, route, flow или cross-boundary correlation IDs;
- split-tunnel application list без отдельной необходимости и согласия.

Разрешены component/version, closed error/state enums, coarse duration/queue buckets
и platform capability state. Server copy удаляется через 7 дней.

## Когда обращаться в support

Обращайтесь после повторяемой ошибки на актуальной версии, если безопасные шаги не
помогли. Укажите OS/version, OnionRoute version, coarse error code и примерное время
с точностью не выше необходимой для локального поиска. Не прикладывайте список
сайтов, tokens, payment data или packet capture.

