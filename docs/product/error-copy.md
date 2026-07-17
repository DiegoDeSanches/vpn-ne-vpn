# OnionRoute: канонические UX-тексты ошибок

## Общие правила

- Ошибка говорит, что произошло, защищён ли трафик и что можно сделать сейчас.
- Primary action никогда не отключает kill switch и не создаёт direct fallback.
- Не показывать hostname, IP, onion address, token/session/route/flow ID, account ID,
  stack trace или remote free-form error.
- `{application}` допустим только как локальное display name; оно не отправляется в
  telemetry/support автоматически.
- Текст `трафик заблокирован` используется только когда это подтверждено состоянием;
  при healthy old route используется текст `предыдущий защищённый маршрут активен`.
- Не обещать success следующего retry или доступность другой страны.

## tor-bootstrap-failed

- **Внутренний mapping:** `TorBootstrapTimeout` / `TorUnavailable`, Protected.
- **Заголовок:** Tor не удалось подготовить
- **Текст:** Защищённый маршрут не создан, поэтому трафик остаётся заблокирован. Tor
  может быть временно недоступен или заблокирован этой сетью.
- **Primary action:** `Повторить`
- **Secondary action:** `Проверить сеть и время`
- **Help:** `Как устранить ошибку Tor`

## gateway-unavailable

- **Внутренний mapping:** `GatewayUnavailable`, `GatewayTimeout`,
  `TorStreamFailed`, Protected.
- **Заголовок:** Private gateway недоступен
- **Текст:** OnionRoute не смог создать выбранный защищённый маршрут. Трафик не был
  отправлен напрямую.
- **Primary action:** `Повторить`
- **Secondary action:** `Выбрать другой доступный маршрут`
- **State variant:** Если old route healthy: `Новое подключение не создано.
  Предыдущий защищённый маршрут остаётся активен.`

## selected-country-unavailable

- **Внутренний mapping:** `GatewayUnavailable` после role/country selection.
- **Заголовок:** Нет доступного exit в выбранной стране
- **Текст:** Сейчас в {country} нет исправного совместимого private exit. OnionRoute
  не подменил страну и не использовал прямое соединение.
- **Primary action:** `Выбрать другую страну`
- **Secondary action:** `Повторить`
- **Optional action:** `Выбрать автоматически` — только по явному нажатию.

## token-expired

Этот текст разрешён только когда client локально доказал expiry. Для remote
`TokenRejected` используется coarse variant ниже.

- **Внутренний mapping:** локальный capability expiry / `SessionExpired`, Protected.
- **Заголовок:** Нужно обновить доступ
- **Текст:** Короткоживущая capability истекла. Новые соединения заблокированы до
  безопасного обновления; gateway не получает данные account.
- **Primary action:** `Обновить доступ`
- **Secondary action:** `Проверить время устройства`
- **Remote rejection title:** `Не удалось подтвердить доступ`
- **Remote rejection text:** `Gateway отклонил capability. OnionRoute запросит новую
  без передачи account ID в data plane.`

## directory-expired

- **Внутренний mapping:** `DirectoryExpired`, Protected.
- **Заголовок:** Список gateway устарел
- **Текст:** Истёк срок подписанного directory. Использовать его для нового маршрута
  небезопасно, поэтому новые соединения заблокированы.
- **Primary action:** `Обновить список gateway`
- **Secondary action:** `Проверить дату и время`
- **State variant:** `Предыдущий маршрут остаётся активен, пока его состояние и
  данные подтверждены.` — только если это истинно.

## kill-switch-active

- **Внутренний mapping:** protected state `Blocked`/`Reconnecting` или MustBlock.
- **Заголовок:** Трафик заблокирован для вашей защиты
- **Текст:** OnionRoute не может подтвердить безопасный маршрут или состояние
  firewall. Kill switch предотвращает прямое соединение и утечку DNS.
- **Primary action:** `Повторить защищённое подключение`
- **Secondary action:** `Показать причину`
- **Fatal variant:** `Требуется восстановление защиты. Трафик останется
  заблокированным до проверенного cleanup или controlled reprovision.`

## udp-blocked

- **Внутренний mapping:** `UnsupportedTransport`, Protected.
- **Заголовок:** UDP не поддерживается
- **Текст:** {application} попыталось использовать UDP. OnionRoute MVP передаёт TCP,
  поэтому этот трафик заблокирован и не отправлен напрямую.
- **Primary action:** `Понятно`
- **Secondary action:** `Что поддерживается`
- **Rate rule:** Повторные события одного local application/protocol объединяются;
  destination не показывается.

## quic-blocked

- **Внутренний mapping:** `UnsupportedTransport`, Protected.
- **Заголовок:** QUIC заблокирован
- **Текст:** QUIC/HTTP/3 использует UDP, который не поддерживается в MVP. Приложение
  может само повторить соединение по TCP; прямой QUIC fallback запрещён.
- **Primary action:** `Понятно`
- **Secondary action:** `Подробнее о TCP и UDP`

## hard-rotation-warning

- **Внутренний mapping:** user-requested `HardNewIdentity`; confirmation before
  action.
- **Заголовок:** Сбросить сетевую сессию?
- **Текст:** Активные соединения закроются. OnionRoute создаст новый Tor isolation
  context, очистит временный DNS state и заменит gateway session. Загрузки и звонки
  могут прерваться.
- **Limitation:** Cookies, логины, local storage и fingerprint не изменятся. Новый
  IP или страна не гарантируются.
- **Primary action:** `Сбросить сессию`
- **Secondary action:** `Отмена`

## degraded-anonymity

Использовать только для не применившегося изменения при healthy previous route.
Если текущий route нельзя подтвердить, показывается `kill-switch-active`.

- **Внутренний mapping:** `RotationDeferred` / failed mode-country replacement with
  healthy old route, Protected.
- **Заголовок:** Новый режим не применён
- **Текст:** OnionRoute не смог подтвердить новый маршрут {mode}. Предыдущий
  защищённый маршрут остаётся активен; на более слабый режим приложение не
  переключилось.
- **Primary action:** `Повторить позже`
- **Secondary action:** `Показать активный маршрут`
- **Maximum addition:** `Maximum не является защитой от глобальной корреляции даже
  после успешного подключения.`

## unsupported-application

- **Внутренний mapping:** repeated unsupported transport/policy result attributable
  to a local app, `UnsupportedTransport` or `PolicyDenied`.
- **Заголовок:** {application} может не работать через OnionRoute
- **Текст:** Приложению нужен неподдерживаемый protocol или запрещённое соединение.
  OnionRoute заблокировал его без прямого fallback.
- **Primary action:** `Проверить требования приложения`
- **Secondary action:** `Что поддерживается`
- **Disclosure action:** `Настроить split tunneling` MAY быть доступно только после
  отдельного предупреждения о real IP/system DNS; не является primary recovery.

## captive-portal-detected

- **Внутренний mapping:** platform captive/unvalidated network state; Protected.
- **Заголовок:** Сеть требует входа
- **Текст:** Captive portal нельзя безопасно открыть внутри текущего protected state.
  Трафик остаётся заблокирован; OnionRoute не создаёт автоматическое исключение.
- **Primary action:** `Проверить сеть снова`
- **Secondary action:** `Как войти в сеть безопасно`
- **Help flow:** Предложить другую trusted network. Если требуется portal, объяснить
  явное завершение tunnel, дождаться `Отключено — cleanup проверен`, выполнить вход и
  сразу подключиться снова. Не предлагать toggle kill switch.

## Accessibility и localization

- Заголовок ≤60 символов; главное следствие находится в первых двух предложениях.
- Цвет/иконка не являются единственным различием blocked и degraded state.
- Button label описывает действие, а не `OK`, кроме информационных UDP/QUIC notices.
- Placeholder `{country}` получает локализованное display name из проверенного
  ISO-кода; remote strings не интерполируются.
- Screen reader сначала читает state, затем protection consequence, затем action.

## Copy acceptance tests

- Для каждого сообщения есть trigger, title, protection consequence и primary
  action.
- Ни один primary action не содержит отключение kill switch, direct connection или
  исключение приложения.
- Country/mode errors не выполняют silent downgrade.
- Identity reset явно перечисляет не меняющиеся application identifiers.
- Token error не раскрывает remote unknown/spent/expired distinction.

