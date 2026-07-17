# OnionRoute: модель угроз

- Статус: обязательный security baseline; до получения evidence из test matrix защиты считаются непроверенными.
- Версия: 1.0.
- Дата анализа: 2026-07-17.
- Владелец документа: `security/threat-model`.
- Область: клиент, TUN/firewall, C Tor, Tor-маршрут, private gateways, control plane, directory, tokens, billing boundary, инфраструктура, обновление и эксплуатация.

Связанные артефакты: [privacy model](privacy-model.md), [release gates](release-gates.md),
[attack trees](attack-trees.md), [abuse model](abuse-model.md), [security test matrix](security-test-matrix.md),
[audit checklist](audit-preparation-checklist.md) и [bug bounty draft](bug-bounty-scope-draft.md).

## 1. Security statement и ограничения

OnionRoute уменьшает число сторон, одновременно наблюдающих пользователя и назначение, но **не обеспечивает
абсолютную анонимность**. Компрометированное устройство, идентификаторы прикладного уровня, collusion entry/exit,
вредоносный exit и глобальное наблюдение способны деанонимизировать пользователя. Tor, multihop и смена цепочек
не являются доказанной защитой от глобального пассивного наблюдателя.

Глобальный наблюдатель, имеющий достаточное покрытие доступа клиента и egress, может сопоставлять начало,
длительность, объём, burst pattern и завершение потоков. TLS скрывает содержимое, но не эти признаки. Padding,
cover traffic и смешивание трафика не утверждены в baseline; до отдельного ADR, измерений и независимой проверки
нельзя заявлять защиту от end-to-end timing correlation или traffic confirmation. Maximum mode увеличивает число
административных границ, но не устраняет статистическую корреляцию.

## 2. Методика

Каждая угроза получает сценарий STRIDE и/или LINDDUN, качественную вероятность и влияние. Оценка residual risk
дана **после только уже документированных контролей**, а не после будущих требований. `Критический` residual risk
блокирует production; `Высокий` требует выполненного теста и принятого владельцем treatment; `Средний` требует
контроля и мониторинга; `Низкий` может быть принят владельцем с записью причины.

Вероятность: `В` — высокая, `С` — средняя, `Н` — низкая. Влияние: `К` — критическое (раскрытие реального IP/
назначения, захват trust root, массовый compromise), `В` — высокое, `С` — среднее, `Н` — низкое.

STRIDE: `S` spoofing, `T` tampering, `R` repudiation, `I` information disclosure, `D` denial of service,
`E` elevation of privilege. LINDDUN: `L` linkability, `Id` identifiability, `Nr` non-repudiation,
`Dt` detectability, `Di` disclosure, `U` unawareness, `Nc` non-compliance.

## 3. Активы и trust boundaries

Критические активы: реальный IP и сетевое положение клиента; destination/DNS; payload; account/payment identity;
capability token и nullifier; Tor isolation; kill-switch state; directory root/rollback state; TLS, mTLS, issuer,
update и signing keys; release artifacts; отсутствие payment-to-session join key; журналы, метрики и backups.

Используются TB-1…TB-8 из [trust-boundaries](../trust-boundaries.md). Анализ добавляет обязательные границы:

| Boundary | Проверяемое требование |
|---|---|
| TB-9 build/CI → signed release | Недоверенные source/dependency/runner не становятся release без hermetic build, review, provenance и threshold signing. |
| TB-10 updater → installed client | Установщик проверяет pinned update root, artifact hash/signature, channel, platform и monotonic version до записи. Ошибка оставляет старую проверенную версию. |
| TB-11 observability → operator | Закрытая coarse schema, агрегация до доступа человека, отсутствие destination, session/account/IP и экспорта raw events. |
| TB-12 billing → control/data telemetry | Физическое и IAM-разделение; ни прямого, ни вычислимого payment-to-session join key. |
| TB-13 backup/restore → live stores | TTL и deletion распространяются на snapshots; restore не оживляет просроченные privacy records. |
| TB-14 application identity → Internet peer | Cookies, login, browser fingerprint и application payload находятся вне защиты tunnel и должны быть явно объяснены пользователю. |

## 4. Threat actors

| Актор | Возможности и пределы модели |
|---|---|
| Локальный злоумышленник | Непривилегированный пользователь/процесс; может читать доступные файлы, гонять IPC и локальные порты. Root/kernel compromise считается фактическим compromise устройства. |
| Вредоносное приложение | Генерирует raw/malformed traffic, WebRTC/QUIC/DNS, high load, probes split tunnel; не должно управлять privileged helper. |
| ISP / local network | Видит IP, время и объём Tor traffic; блокирует, задерживает, инжектирует и меняет captive/network state. |
| Tor guard observer / relay | Guard видит IP и timing; relay может наблюдать, задерживать, дропать и модифицировать доступный ему слой. |
| Compromised entry/relay/exit | Контролирует соответствующий gateway и его память/логи; exit видит destination и прикладной plaintext, если нет end-to-end TLS. |
| Cloud provider | Видит VM/network/storage/control-plane metadata и может получить snapshot или co-located vantage point. |
| Глобальный пассивный наблюдатель | Наблюдает access и egress на широком масштабе, не обязан ломать криптографию. |
| Активный сетевой противник | Дропает, повторяет, задерживает, маршрутизирует и подтверждает трафик, провоцирует fallback/guard churn. |
| Token thief | Имеет bearer/token bytes и пытается replay/расширение scope до expiry. |
| Вредоносный администратор | Имеет часть production/KMS/observability доступа, меняет policy/логи/каталог или экспортирует данные. |
| Supply-chain attacker | Компрометирует dependency, build runner, maintainer, Tor/PT binary, update metadata или signing workflow. |
| DDoS attacker | Создаёт массовые сессии, медленные потоки, oversized inputs, запросы control/directory или Tor load. |
| Abuse user | Имеет действующий entitlement/token и использует egress для scan, spam, attacks, sharing или исчерпания ресурсов. |
| Billing/network correlator | Имеет законный или украденный доступ к двум доменам и пытается связать оплату с network activity. |

## 5. Каталог заявленных контролей

`A` — принятый ADR, `P` — proposed/experimental, `B` — baseline без production evidence. Ни один статус не
заменяет тест.

| Control | Статус | Заявленная защита |
|---|---:|---|
| C01 | A | Fail-closed kill switch, lease/verify/recover, запрет DNS/UDP/QUIC/fallback: [ADR-0002](../adr/0002-fail-closed-kill-switch.md). |
| C02 | A/P | Bounded IPv4/TCP parser и отсутствие direct socket backend: [ADR-0009](../adr/0009-bounded-tcp-proxy-engine.md). |
| C03 | A | Отдельный C Tor, SAFECOOKIE/ACL, bounded contexts и fresh isolation: [ADR-0010](../adr/0010-c-tor-process-supervision.md). |
| C04 | A | Ed25519 directory, pin, expiry, sequence и rotation: [ADR-0005](../adr/0005-signed-gateway-directory.md). |
| C05 | A | V3 onion + terminal TLS SPKI pin + inter-gateway mTLS: [ADR-0008](../adr/0008-multihop-terminal-encryption.md). |
| C06 | A | Физическое/API/IAM-разделение account/control/data: [ADR-0001](../adr/0001-control-data-plane-separation.md). |
| C07 | A/P | Blind/VOPRF token design, scope/expiry/replay; алгоритм ещё не утверждён: [ADR-0003](../adr/0003-anonymous-capability-tokens.md). |
| C08 | A | 64 KiB frames, credit, limits, sequence и deadlines: [gateway protocol](../gateway-protocol-v1.md). |
| C09 | P | Loopback gateway ingress, SSRF/rebinding checks, nftables и explicit DNS: [ADR-0011](../adr/0011-private-exit-gateway-fail-closed-egress.md). |
| C10 | B | Coarse closed-schema logs/telemetry, запрет destination/token/session/account fields: [trust boundaries](../trust-boundaries.md). |
| C11 | B | OS secure storage для token/root/rollback state; corruption fail-closed: [trust boundaries](../trust-boundaries.md). |
| C12 | A/B | Opaque entry/relay, terminal exit, role и разные failure domains: [ADR-0008](../adr/0008-multihop-terminal-encryption.md). |
| C13 | A | Make-before-break, fresh isolation/token, bounded drain и DNS flush: [ADR-0006](../adr/0006-make-before-break-rotation.md). |
| C14 | B | MFA/JIT/least privilege, separate keys, immutable admin audit: [trust boundaries](../trust-boundaries.md). |
| C15 | B | Privacy запреты и support-bundle redaction: [trust boundaries](../trust-boundaries.md). |

Обнаружено расхождение baseline с параллельным component review
[auth-tokens-threat-model](auth-tokens-threat-model.md): там MVP issuance прямо описан как не blind и допускающий
корреляцию control service с выданным token по памяти/timing, тогда как ADR-0003 требует blind-signature/VOPRF.
Не-blind MVP **не считается реализацией C07** и не допускается в production. Расхождение должно быть разрешено
владельцем защищённого token contract через ADR/contract proposal, independent crypto/privacy review и G-11/G-14/G-16;
этот security review не меняет token format.

## 6. Реестр угроз

В каждом разделе первая таблица задаёт актив, атакующего, предпосылки, сценарий, вероятность, влияние и
STRIDE/LINDDUN; вторая — существующую защиту, residual risk, обязательный тест и единственного primary owner.

### 6.1 Устройство и локальное принуждение

| ID | Актив | Атакующий | Предпосылки | Сценарий | P | I | STRIDE / LINDDUN |
|---|---|---|---|---|---:|---:|---|
| T-001 | Реальный IP, destination | Вредоносное приложение | Может создавать sockets/raw traffic | Обходит TUN через другой namespace/interface/helper и соединяется напрямую | С | К | T,I,E / Id,Di,Nc |
| T-002 | Firewall policy | Локальный злоумышленник | Доступен IPC privileged helper | Подменяет peer/команду или replay lease, снимая rules | С | К | S,T,E / Di,Nc |
| T-003 | Kill-switch state | OS race/активный app | Connect/reconfigure неатомарны | Пакет уходит в окно между route и firewall update | В | К | T,I / Id,Di,Nc |
| T-004 | DNS query, IP | App/OS/ISP | System resolver остаётся доступен | A/AAAA/PTR уходит вне tunnel при connect/failure | В | К | I / L,Id,Dt,Di,Nc |
| T-005 | IPv6 address/destination | App/OS/ISP | IPv6 route/extension header не покрыт | Приложение выбирает AAAA и обходит IPv4-only TUN | В | К | T,I / Id,Dt,Di,Nc |
| T-006 | LAN/public IP | WebRTC-capable app | UDP/STUN/TURN не блокирован целиком | ICE discovery раскрывает адрес или создаёт direct UDP | В | В | I / Id,Dt,Di,U |
| T-007 | IP/destination | Browser/app/ISP | HTTP/3 разрешён ОС | QUIC используется напрямую при невозможности TCP | В | К | T,I / Id,Dt,Di,Nc |
| T-008 | Split-tunnel boundary | Вредоносное приложение | Идентификация app/child/UID неоднозначна | Маскируется под allowlisted app либо наследует bypass | С | К | S,E,I / Id,Di,U,Nc |
| T-009 | Kill switch | Captive portal/ISP | Пользователю нужна portal auth | Workflow снимает firewall глобально или не возвращает его | В | К | T,I / Id,Dt,Di,U,Nc |
| T-010 | Routes/firewall/isolation | OS/ISP | Sleep/resume, interface/DHCP change | Старые rules/leases считаются valid, новый interface выпускает трафик | В | К | T,I / Id,Di,Nc |
| T-011 | Kill-switch lease | Crash/uninstaller/local attacker | Shutdown/recovery частично выполнены | Stale process/lease disengage-ит новые rules или crash оставляет сеть open | С | К | T,E,I / Id,Di,Nc |
| T-012 | Tor process/control/SOCKS | Локальный злоумышленник | Порт/cookie/data dir доступны | Управляет Tor, использует SOCKS или нарушает isolation | С | В | S,T,E,I / L,Id,Di |
| T-013 | Token, directory root/state | Локальный злоумышленник | Secure storage/backup доступен или corrupt | Крадёт token, подменяет root либо откатывает sequence | С | К | S,T,I,E / L,Id,Di,Nc |
| T-014 | Destination/token/identity | Локальный admin/support | Crash dump/debug/support bundle | Volatile secrets и flow metadata сохраняются и экспортируются | В | В | I / L,Id,Nr,Di,U,Nc |

| ID | Существующая защита | Остаточный риск | Необходимый тест | Primary owner |
|---|---|---|---|---|
| T-001 | C01,C02 | Высокий: platform bypass и privileged app не доказаны | ST-001 | `core/network-engine` |
| T-002 | C01 | Высокий: peer auth/IPC format не реализованы для всех OS | ST-002 | `client/desktop` |
| T-003 | C01 | Высокий до OS pcap race suite | ST-003 | `core/network-engine` |
| T-004 | C01,C02 | Критический до zero-leak pcap на каждой OS | ST-004 | `core/network-engine` |
| T-005 | C01,C02 | Критический: IPv6 deliberately unsupported, значит блок должен быть доказан | ST-005 | `core/network-engine` |
| T-006 | C01 | Высокий: WebRTC меняется между platform/browser | ST-006 | `client/desktop` |
| T-007 | C01,C02 | Критический до отрицательного QUIC test | ST-007 | `core/network-engine` |
| T-008 | C02 | Высокий: OS attribution имеет race/child semantics | ST-008 | `client/desktop` |
| T-009 | C01 | Критический: безопасный captive workflow не специфицирован | ST-009 | `client/desktop` |
| T-010 | C01,C03 | Критический до resume/network-change tests | ST-010 | `core/network-engine` |
| T-011 | C01 | Высокий: uninstall/crash semantics platform-specific | ST-011 | `client/desktop` |
| T-012 | C03 | Средний после ACL; root compromise не устраняется | ST-012 | `core/tor-backend` |
| T-013 | C04,C07,C11 | Высокий: device/root compromise и rollback backup остаются | ST-013 | `architecture/contracts` |
| T-014 | C10,C15 | Высокий: OS dumps/third-party crash SDK не проверены | ST-014 | `client/desktop` |

### 6.2 Tor, metadata leakage и корреляция

| ID | Актив | Атакующий | Предпосылки | Сценарий | P | I | STRIDE / LINDDUN |
|---|---|---|---|---|---:|---:|---|
| T-015 | Факт использования/доступность | ISP | Видит access link | Детектирует Tor, профилирует, throttles или блокирует bootstrap | В | В | D,I / Dt,Id,U |
| T-016 | Реальный IP + timing | Tor guard observer | Контролирует/наблюдает guard | Связывает IP с временем/объёмом OnionRoute activity | С | В | I / L,Id,Dt,Di |
| T-017 | Circuit metadata | Compromised Tor relay | Relay находится в цепи | Дроп/задержка/tagging создают узнаваемый pattern | С | В | T,D,I / L,Dt,Di |
| T-018 | Guard selection | Активный network adversary | Может selectively fail circuits | Провоцирует guard churn до контролируемого/наблюдаемого guard | С | К | T,D / L,Id,Dt |
| T-019 | Анонимность пользователя | Глобальный пассивный наблюдатель | Покрывает access и exit/destination | Коррелирует timing/volume без расшифрования | С | К | I / L,Id,Dt,Di |
| T-020 | Связь client↔destination | Активный сетевой противник | Наблюдает/воздействует на один конец и видит другой | Watermark/burst/controlled fetch подтверждает конкретный поток | С | К | T,I / L,Id,Dt,Di |
| T-021 | Destination pattern | ISP/guard/cloud/exit | Достаточно traffic traces | Website fingerprinting по размерам, burst и duration | С | В | I / L,Dt,Di |
| T-022 | Anonymity set | Observer/gateway | Пользователь выбирает редкую страну/режим/route | Редкий route/capability/time pattern выделяет subscription/session | С | В | I / L,Id,Dt,U,Nc |
| T-023 | Identity boundary | Entry/exit/observer | Rotation держит old/new sessions параллельно | Совпадающие timing/app flows связывают личности | В | В | I / L,Id,Dt |
| T-024 | Пользовательская identity | Internet destination/приложение | Login/cookie/fingerprint сохраняется | Новый circuit не меняет account/cookie/TLS/app identifier | В | К | I / L,Id,Nr,U |

| ID | Существующая защита | Остаточный риск | Необходимый тест | Primary owner |
|---|---|---|---|---|
| T-015 | C03 | Высокий; bridges/PT не гарантируют неотличимость | ST-015 | `core/tor-backend` |
| T-016 | C03 | Высокий: guard неизбежно видит IP и timing | ST-016 | `core/tor-backend` |
| T-017 | C03,C05 | Высокий: TLS не скрывает timing и selective failure | ST-017 | `core/tor-backend` |
| T-018 | C03 | Высокий: зависит от Tor guard policy | ST-018 | `core/tor-backend` |
| T-019 | Нет действенного baseline control | Критический и фундаментальный; должен быть явно принят/описан | ST-019 | `security/threat-model` |
| T-020 | C05 | Критический: active confirmation не предотвращён | ST-020 | `security/threat-model` |
| T-021 | Нет padding/cover-traffic control | Высокий; claims ограничиваются | ST-021 | `security/threat-model` |
| T-022 | C12 | Высокий: policy anonymity set не определён | ST-022 | `core/tor-backend` |
| T-023 | C13 | Средний после bounded overlap; корреляция long-lived flows остаётся | ST-023 | `core/tor-backend` |
| T-024 | C13 и только UX warning | Критический вне tunnel; технически не устраняется route rotation | ST-024 | `product/documentation` |

### 6.3 Gateway, transport и egress

| ID | Актив | Атакующий | Предпосылки | Сценарий | P | I | STRIDE / LINDDUN |
|---|---|---|---|---|---:|---:|---|
| T-025 | Route timing/next hop | Compromised entry | Entry выбран в route | Записывает timing/volume/next hop, selectively fails routes | С | В | T,I,D / L,Dt,Di |
| T-026 | Adjacent route metadata | Compromised relay | Relay в Maximum route | Коррелирует соседние hops и injects delay/drop | Н | В | T,I,D / L,Dt,Di |
| T-027 | Destination/DNS/payload | Compromised exit | Exit завершает terminal session | Логирует destination/DNS/plaintext или модифицирует незашифрованный traffic | С | К | T,I,R / L,Id,Nr,Di,Nc |
| T-028 | Client↔destination relation | Colluding entry+exit | Два hops делятся traces | Сопоставляют timing/session и deanonymize route | С | К | I / L,Id,Dt,Di |
| T-029 | Gateway traffic/keys | Cloud provider | Наблюдает hosts/network/snapshots | Коррелирует gateway links, читает disk/memory snapshot или metadata | С | К | I,E / L,Id,Dt,Di,Nc |
| T-030 | Route integrity | Malicious gateway/admin | Valid directory включает controlled descriptor | Gateway предъявляет valid pin, но намеренно наблюдает/нарушает policy | С | К | S,T,I / L,Id,Di,Nc |
| T-031 | Fleet availability/topology | DDoS attacker | Получает public catalog/onion IDs | Enumerates gateways и адресно выводит их из строя | В | В | D,I / Dt,Di |
| T-032 | Client IP, egress | Internet attacker/user | Gateway слушает public interface | Обходит Tor/onion ingress, раскрывает IP и использует open proxy | С | К | S,E,I / Id,Di,Nc |
| T-033 | Destination boundary | Malicious client/gateway | Role checks доверяют request | Entry/relay принимает terminal TCP/DNS или становится exit | С | К | S,T,E / Di,Nc |
| T-034 | Gateway identity | MITM/malicious gateway | Pin/hostname/role не проверен полностью | Подменяет terminal TLS endpoint при valid Tor path | С | К | S,T,I / L,Id,Di |
| T-035 | Inter-gateway identity | Cloud/admin attacker | Крадёт mTLS key/cert либо PKI выдаёт wrong role | Имперсонирует hop, читает/меняет opaque stream metadata | С | К | S,T,E,I / L,Di,Nc |
| T-036 | Protocol security semantics | Active peer/MITM | Client/server поддерживают версии/optional features | Заставляет выбрать старый major/minor или убрать required security feature | С | К | T,S / Di,U,Nc |
| T-037 | Session/authorization | Network/peer attacker | Replay state/sequence/session ID weak | Повторяет auth/frame/open или вызывает sequence wrap/confusion | С | В | S,T,R / L,Nr,Di |
| T-038 | Memory/availability | DDoS/malicious peer | Allocation до bounds, missing credit/deadline | Length bomb, many streams или stalled buffers исчерпывают RAM | В | К | D / Dt,Nc |
| T-039 | Cloud/management secrets | Abuse user | Exit разрешает arbitrary host/IP | Через SSRF достигает metadata, loopback, RFC1918, management или Tor control | В | К | E,I,T / Di,Nc |
| T-040 | Egress boundary | Abuse user/malicious DNS | DNS answer меняется между check/dial | Rebinding/CNAME/TOCTOU направляет socket в private range | С | К | T,E,I / Di,Nc |
| T-041 | DNS privacy | Exit/resolver/cloud | Gateway использует system/third-party resolver | Query выходит не через approved resolver, логируется или коррелируется | С | К | I / L,Id,Dt,Di,Nc |
| T-042 | Gateway availability | DDoS attacker | Onion/public reachability и valid/invalid handshakes | Slowloris, connection/open storms, auth/DNS stalls исчерпывают quotas | В | В | D / Dt |
| T-043 | Service reputation/policy | Abuse user | Egress ACL/DPI incomplete | SMTP/25, BitTorrent, scan/admin ports проходят через разрешённый flow | В | В | T,R / Nr,Nc |
| T-044 | Memory/session integrity | Malicious Internet peer | Ответы/half-close/stall недоверенны | Oversized/slow response удерживает buffers/tasks после client close | В | В | D,T / Dt,Nc |

| ID | Существующая защита | Остаточный риск | Необходимый тест | Primary owner |
|---|---|---|---|---|
| T-025 | C05,C08,C12 | Высокий: timing остаётся открыт | ST-025 | `gateway/multihop` |
| T-026 | C05,C08,C12 | Средний; компрометированный hop может DoS/tag | ST-026 | `gateway/multihop` |
| T-027 | C05,C10 | Критический: exit по дизайну видит destination | ST-027 | `gateway/egress` |
| T-028 | C12 | Критический: независимость failure domains пока policy, не доказательство | ST-028 | `infra/platform` |
| T-029 | C05,C14 | Высокий: provider-level observation/snapshot сохраняется | ST-029 | `infra/platform` |
| T-030 | C04,C05,C12 | Критический: signature доказывает authorization, не честность gateway | ST-030 | `control/directory` |
| T-031 | C04 | Высокий: catalog раскрывает fleet клиентам; onion auth plan не завершён | ST-031 | `infra/platform` |
| T-032 | C09(P) | Критический до external exposure test | ST-032 | `gateway/egress` |
| T-033 | C09(P),C12 | Критический до wrong-role/namespace tests | ST-033 | `gateway/multihop` |
| T-034 | C04,C05 | Критический до negative pin/role/name fixtures | ST-034 | `protocol/gateway-v1` |
| T-035 | C05,C14 | Высокий: key theft/CA compromise остаются | ST-035 | `infra/platform` |
| T-036 | C08 | Критический до adversarial negotiation tests | ST-036 | `protocol/gateway-v1` |
| T-037 | C07,C08 | Высокий: token/session replay integration не завершена | ST-037 | `protocol/gateway-v1` |
| T-038 | C02,C08,C09(P) | Критический до fuzz/soak с измеренным plateau | ST-038 | `protocol/gateway-v1` |
| T-039 | C09(P) | Критический до полного SSRF corpus + nftables evidence | ST-039 | `gateway/egress` |
| T-040 | C09(P) | Критический до controlled rebinding tests | ST-040 | `gateway/egress` |
| T-041 | C09(P),C10 | Критический: resolver trust/transport ещё open decision | ST-041 | `gateway/egress` |
| T-042 | C07,C08,C09(P) | Высокий; Tor/onion DDoS полностью не устраняется | ST-042 | `gateway/egress` |
| T-043 | C09(P) | Высокий: traffic classification неполна и обходится | ST-043 | `gateway/egress` |
| T-044 | C02,C08,C09(P) | Высокий до lifecycle/soak tests | ST-044 | `gateway/egress` |

### 6.4 Directory, control plane и tokens

| ID | Актив | Атакующий | Предпосылки | Сценарий | P | I | STRIDE / LINDDUN |
|---|---|---|---|---|---:|---:|---|
| T-045 | Directory authenticity | CDN/control/MITM | Клиент принимает transport success как trust | Unsigned, wrong-key, malformed или altered directory становится active | С | К | S,T,E / Di,Nc |
| T-046 | Freshness/route safety | CDN/active network/local attacker | Clock/sequence/cache можно откатить | Подсовывает expired/old vulnerable gateways или сдвигает clock | С | К | T,S / U,Di,Nc |
| T-047 | Directory signing root | Malicious admin/supply chain | Online/offline key украден | Подписывает malicious fleet/pins/policy для всех клиентов | Н | К | S,T,E,I / L,Id,Di,Nc |
| T-048 | Root rotation | Malicious admin/attacker | Emergency/next-key workflow слабее normal signing | Вставляет unauthorized next root или bypass через upgrade | Н | К | S,T,E / Di,U,Nc |
| T-049 | Consistent view | Directory operator/admin | Имеет valid signing key | Выпускает targeted, уникальные, valid catalogs разным клиентам | С | К | T,R,I / L,Id,Dt,Di,Nc |
| T-050 | Availability | DDoS/active network | Directory/control unreachable до expiry | Forced fail-closed вызывает длительный outage и update pressure | В | В | D / Dt,U |
| T-051 | Token authorization | Token thief | Получены token bytes до expiry | Replay одновременно/последовательно на том же gateway | В | К | S,R / L,Nr,Di |
| T-052 | Entitlement boundary | Malicious client/gateway bug | Expiry/nbf/audience/scope validation отсутствует | Просроченный/future/wrong-audience token принимается | С | К | S,E,T / Di,Nc |
| T-053 | Hop unlinkability | Abuse user/bug | Один token допускается на нескольких roles/routes | Redemption связывает hops или расширяет scope | С | В | S,E,I / L,Id,Di,Nc |
| T-054 | Issuance↔redemption unlinkability | Token service + gateway observer | Low-volume precise timestamps/capabilities | Коррелирует выдачу и redemption несмотря на blind token | В | К | I / L,Id,Dt,Di,Nc |
| T-055 | Subscription privacy | Gateway/observer | Capability vector/TTL/issuer уникальны для тарифа | Определяет subscription и сужает anonymity set | С | В | I / L,Id,Dt,U,Nc |
| T-056 | Token unforgeability/privacy | Supply-chain/crypto attacker | Выбран custom/unreviewed blind/VOPRF алгоритм | Forge, unblind failure, tagging или issuer linkability | С | К | S,T,R,I / L,Id,Nr,Di,Nc |
| T-057 | Issuer trust | Admin/supply chain | Issuer private key украден, revoke медленный | Массово mint-ит tokens или заставляет глобальный fail-closed | Н | К | S,E,D / Di,Nc |
| T-058 | Replay-state availability | DDoS/abuse user | Nullifier insert/check неатомарен или unbounded | Double-spend race либо state/memory exhaustion | В | В | R,D,T / Nr,Dt,Nc |

| ID | Существующая защита | Остаточный риск | Необходимый тест | Primary owner |
|---|---|---|---|---|
| T-045 | C04 | Критический до exact-byte negative corpus | ST-045 | `control/directory` |
| T-046 | C04,C11 | Высокий: secure-clock отсутствует; corruption должно fail closed | ST-046 | `control/directory` |
| T-047 | C04,C14 | Критический: root compromise не устраняется подписью | ST-047 | `control/directory` |
| T-048 | C04 | Критический до ceremony/rotation drill | ST-048 | `control/directory` |
| T-049 | C04 | Критический: transparency/gossip не спроектированы | ST-049 | `control/directory` |
| T-050 | C04 | Высокий, сознательный fail-closed availability trade-off | ST-050 | `infra/platform` |
| T-051 | C07(P) | Критический: production verifier/replay store ещё не reviewed | ST-051 | `control/auth-tokens` |
| T-052 | C07(P) | Критический до boundary/clock/audience tests | ST-052 | `control/auth-tokens` |
| T-053 | C07(P) | Высокий до per-hop unlinkability assertions | ST-053 | `control/auth-tokens` |
| T-054 | C06; C07 не реализован в описанном не-blind MVP | Критический: issuer может связать issuance; timing/batching policy не закрывает прямую видимость | ST-054 | `control/auth-tokens` |
| T-055 | C07(P) | Высокий: coarse capability anonymity threshold не определён | ST-055 | `control/auth-tokens` |
| T-056 | C07(P) | Критический и release-blocking до независимого crypto review | ST-056 | `control/auth-tokens` |
| T-057 | C07(P),C14 | Высокий: short TTL ограничивает, но не предотвращает minting | ST-057 | `control/auth-tokens` |
| T-058 | C07(P),C08 | Высокий до atomic race/load tests и bounded TTL store | ST-058 | `control/auth-tokens` |

### 6.5 Operations, supply chain, privacy и abuse

| ID | Актив | Атакующий | Предпосылки | Сценарий | P | I | STRIDE / LINDDUN |
|---|---|---|---|---|---:|---:|---|
| T-059 | Client binary/update trust | Updater/supply-chain attacker | Updater не проверяет pinned signature/metadata | Доставляет клиент с leak/backdoor или malicious root | С | К | S,T,E,I / L,Id,Di,Nc |
| T-060 | Patch freshness | CDN/active network | Rollback/freeze protection отсутствует | Удерживает клиент на известной уязвимой подписанной версии | В | В | T,D / U,Nc |
| T-061 | Source/build/release integrity | Supply-chain attacker | Dependency/runner/maintainer compromised | Вставляет код до release signing или подменяет provenance | С | К | S,T,E,R / Di,Nc |
| T-062 | Tor/PT execution boundary | Supply-chain/local attacker | Bundled executable не привязан к manifest | Подменяет Tor/PT, читает traffic/control или создаёт direct socket | С | К | S,T,E,I / L,Id,Di,Nc |
| T-063 | Production secrets | Developer/attacker | Secret попал в source/image/log/test fixture | Использует hardcoded key/token для control/gateway/KMS access | С | К | I,E,S / Di,Nc |
| T-064 | Destination/DNS/history | Вредоносный администратор | Имеет deploy/config/observability access | Включает persistent destination logging или packet capture | С | К | T,E,I,R / L,Id,Nr,Di,Nc |
| T-065 | Privacy controls | Incident responder/admin | Debug mode обходит closed schema | Raw token/session/IP/DNS попадает в временные логи и backups | В | К | T,I / L,Id,Nr,Di,U,Nc |
| T-066 | Session unlinkability | Operator/observability vendor | Общие IDs и точные timestamps в слоях | Join client/control/gateway events восстанавливает маршрут | В | К | I / L,Id,Dt,Di,Nc |
| T-067 | Payment↔network unlinkability | Billing/network correlator/admin | Общий ID, warehouse, key или precise event | Связывает payment/account с token/session/gateway activity | С | К | I,E / L,Id,Nr,Di,Nc |
| T-068 | Coarse telemetry anonymity | Analyst/operator | Малые cohorts/редкие labels доступны | Даже aggregate идентифицирует тариф, страну или единственного клиента | В | В | I / L,Id,Dt,U,Nc |
| T-069 | TTL/deletion guarantee | Admin/cloud/backup process | Records удалены только из primary DB | Backup/replica/restore сохраняет destination-like или joinable data | В | К | I,R / L,Id,Nr,Di,U,Nc |
| T-070 | Keys/data plane | Cloud provider/malicious admin | Broad IAM/snapshot/console access | Читает memory/disk/keys или меняет firewall/logging | С | К | E,I,T / L,Id,Di,Nc |
| T-071 | Telemetry/log data | Vendor/config attacker | Exporter имеет arbitrary labels/raw events | Данные покидают privacy boundary или становятся cross-customer joinable | С | В | I,T / L,Id,Di,U,Nc |
| T-072 | Control availability | DDoS attacker | Public control/directory/token endpoints | Исчерпывает rate/DB/signing/queue, препятствуя connect/renew | В | В | D / Dt |
| T-073 | Egress reputation/victims | Abuse user | Действующий token и много flows/destinations | Scan, credential attacks, reflection-like TCP load или DDoS через exits | В | В | R,D / Nr,Nc |
| T-074 | Entitlement/capacity | Abuse user/token reseller | Token sharing/race/automation | Перепродаёт доступ, обходит quotas и создаёт unfair load без stable ID | В | В | S,R,D / Nr,Nc |

| ID | Существующая защита | Остаточный риск | Необходимый тест | Primary owner |
|---|---|---|---|---|
| T-059 | Полного update baseline нет | Критический; production release запрещён | ST-059 | `infra/platform` |
| T-060 | C04 применим только к directory | Высокий; update rollback design отсутствует | ST-060 | `infra/platform` |
| T-061 | C14 частично | Критический до protected build/signing/provenance gates | ST-061 | `infra/platform` |
| T-062 | C03 требует signed packaging | Критический до runtime manifest/hash test | ST-062 | `core/tor-backend` |
| T-063 | C14 | Критический до secret scans и key provenance audit | ST-063 | `infra/platform` |
| T-064 | C10,C14,C15 | Критический: privileged malicious admin требует SoD и immutable detection | ST-064 | `infra/platform` |
| T-065 | C10,C15 | Критический до production debug/redaction tests | ST-065 | `infra/platform` |
| T-066 | C06,C10 | Критический до schema/joinability audit | ST-066 | `security/threat-model` |
| T-067 | C06 | Критический до structural no-join proof | ST-067 | `control/auth-tokens` |
| T-068 | C10 | Высокий: k-threshold/coarsening policy должна быть реализована | ST-068 | `infra/platform` |
| T-069 | C10,C15 | Критический: backup deletion не описан baseline | ST-069 | `infra/platform` |
| T-070 | C14 | Высокий: provider/admin compromise остаётся | ST-070 | `infra/platform` |
| T-071 | C10 | Высокий до egress allowlist/schema enforcement | ST-071 | `infra/platform` |
| T-072 | C08 частично | Высокий; availability attack неизбежен, fail-open запрещён | ST-072 | `infra/platform` |
| T-073 | C09(P) | Высокий: privacy ограничивает attribution; нужны bounded anonymous controls | ST-073 | `gateway/egress` |
| T-074 | C07(P),C08 | Высокий до quotas/replay, без введения user ID | ST-074 | `control/auth-tokens` |

## 7. STRIDE и LINDDUN coverage

| Метод | Покрытие |
|---|---|
| STRIDE Spoofing | T-002, T-008, T-012, T-032, T-034…T-037, T-045, T-047…T-048, T-051…T-053, T-057, T-059, T-061…T-063, T-074 |
| STRIDE Tampering | T-001…T-003, T-007…T-011, T-017…T-018, T-020, T-025…T-027, T-030, T-033…T-040, T-043…T-049, T-052, T-056, T-058…T-062, T-064…T-065, T-070…T-071 |
| STRIDE Repudiation | T-027, T-037, T-043, T-049, T-051, T-056, T-061, T-064, T-069, T-073…T-074 |
| STRIDE Information disclosure | T-001…T-008, T-010, T-012…T-017, T-019…T-030, T-032, T-034…T-035, T-039…T-041, T-047, T-049, T-054…T-056, T-059, T-062…T-071 |
| STRIDE DoS | T-015, T-017…T-018, T-025…T-026, T-031, T-038, T-042, T-044, T-050, T-057…T-058, T-060, T-072…T-074 |
| STRIDE Elevation | T-001…T-002, T-008, T-012…T-013, T-029, T-032…T-035, T-039…T-040, T-045, T-047…T-048, T-052, T-057, T-059, T-061…T-064, T-067, T-070 |
| LINDDUN | Все privacy-сценарии имеют хотя бы одну категорию; особенно T-004…T-007, T-014…T-030, T-041, T-049, T-054…T-056 и T-064…T-071. |

## 8. Обязательные меры защиты

1. Считать все контроли fail-closed: неизвестный transport/version/role/key/state и timeout не создают bypass.
2. Выполнить все `ST-*` из test matrix; перечисленные в release gates тесты не имеют waiver.
3. Утвердить стандартную token scheme и библиотеку независимым cryptographic review; до этого auth experimental/reject-all.
4. Утвердить update trust model с offline/threshold root, rollback protection, provenance и recovery до первого public build.
5. Ввести directory transparency/двухстороннее наблюдение или documented alternative против targeted equivocation.
6. Проверять independent failure/admin/cloud domains для multihop как policy input, а не marketing label.
7. Закрыть telemetry schema, TTL и deletion verification согласно privacy model до включения ingestion.
8. Запретить production debug, packet capture и destination logging технически и через separation of duties.
9. Публиковать в UX ограничения: exit visibility, app identifiers, malicious device и global-observer correlation.
10. Пересматривать threat model при изменении token/directory/protocol/updater, новой OS, UDP support, resolver или cloud layout.

## 9. Открытые вопросы, требующие решения/ADR

- Выбор и независимый review blind-signature/VOPRF профиля, максимальный token TTL, clock skew и replay-store semantics.
- Разрешение конфликта ADR-0003 с описанным не-blind MVP token issuance; до принятого ADR/contract proposal production запрещён.
- Update framework, root ceremony, threshold, rollback/freeze recovery и offline reinstall path.
- Directory transparency/gossip и обнаружение valid targeted equivocation.
- Resolver transport/operator model на exit и влияние resolver на traffic correlation.
- Формальное определение независимых cloud/admin/failure domains для Enhanced/Maximum.
- Captive-portal workflow по каждой OS без ослабления protected state.
- Padding/cover traffic: либо измеренный дизайн, либо постоянное явное ограничение claims.
- Privacy-preserving abuse thresholds без destination history и user-level network analytics.

Пока эти вопросы не закрыты соответствующими review и evidence, связанные residual risks не считаются принятыми.
