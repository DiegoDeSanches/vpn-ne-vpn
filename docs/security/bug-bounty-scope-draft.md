# OnionRoute: bug bounty scope draft

- Статус: **DRAFT — не публиковать до заполнения asset inventory, контактов, SLA и legal approval**.
- Версия: 0.1.
- Дата: 2026-07-17.
- Владелец: `security/threat-model` совместно с legal/operations.

## 1. Цель программы

Приоритет — уязвимости, раскрывающие реальный IP/destination, создающие clearnet/DNS/IPv6/QUIC leak, обходящие
gateway/token/directory/update trust, позволяющие SSRF/public ingress, сохраняющие browsing data или связывающие
payment с network activity. OnionRoute не обещает абсолютную анонимность; статистическая timing correlation
глобального наблюдателя принимается как известное ограничение, но практическое усиление этой корреляции багом
может быть валидным report.

## 2. Перед запуском заполнить

- Security contact и emergency 24/7 contact: `<security@domain>` / `<pager process>`.
- PGP/age key и fingerprint: `<key>`.
- Program platform/URL и policy version: `<platform>` / `<url>` / `<version>`.
- Response SLA, validation SLA и reward currency/ranges: `<SLA>` / `<ranges>`.
- Test account/token acquisition и researcher test environment: `<instructions>`.
- Точные production/staging domains, app package IDs, repositories, onion services и IP ranges: `<inventory>`.
- Data handling, embargo, disclosure timeline, sanctions/export, tax и legal jurisdiction: `<legal text>`.

До заполнения placeholders этот файл не является разрешением тестировать production.

## 3. Proposed in-scope assets

Только явно перечисленные в опубликованной inventory версии:

| Class | Draft scope | Особый интерес |
|---|---|---|
| Desktop/mobile clients | Official signed packages и updater, конкретные package IDs/versions | Kill-switch, TUN, DNS/IPv6/WebRTC/QUIC, captive, resume, split tunnel, local IPC/Tor, secure storage |
| Open-source repositories | OnionRoute-owned code и build/release definitions | Memory safety, protocol/parser, secret/supply-chain, privacy schema |
| Gateway protocol | Test/staging onion endpoints и provided test gateway | Auth/token replay, downgrade, framing/backpressure, role/pin/mTLS |
| Exit egress | Dedicated researcher sandbox only | SSRF, DNS rebinding, forbidden ranges/ports, public ingress, resource exhaustion within limits |
| Control/directory/token | Dedicated staging endpoints/test accounts | Signature/rollback/equivocation, blind-token privacy/forge/replay, account/data-plane separation |
| Update/delivery | Official metadata/artifact endpoints and offline fixture lab | Signature/root/threshold, rollback/freeze/channel/platform confusion |
| Privacy pipeline | Synthetic researcher tenant/environment | Destination persistence, user-level analytics, billing-network join, TTL/deletion, vendor export |

Third-party Tor relays/network, cloud provider control planes, payment processors, app stores, email/SMS provider,
Internet destinations и unrelated customer systems не входят в scope без их отдельного письменного разрешения.

## 4. Priority vulnerability classes

### Critical candidates

- Любой воспроизводимый clearnet, DNS, IPv6, WebRTC или QUIC leak в protected state/lifecycle.
- Unsigned/wrong-key directory или updater acceptance; rollback к exploitable version.
- Remote code execution, signing/KMS/issuer key compromise или supply-chain path к official artifact.
- Gateway с public unauthenticated user ingress/open proxy.
- SSRF к cloud metadata, management, private network, loopback или Tor control.
- Token forgery, expired/wrong-audience acceptance, broad replay или auth fail-open.
- Persistent destination/DNS/payload logging или payment-to-session join доступный штатной роли.
- Protocol downgrade, pin/role bypass или malicious catalog, приводящий к route interception.

### High candidates

- Cross-user data/session confusion, significant memory/FD/task exhaustion with low attacker cost.
- Local unprivileged helper/Tor/secure-store compromise leading to leak or route control.
- Directory equivocation/rollback, update freeze, mTLS role confusion или issuer revocation bypass.
- Telemetry small-cohort/stable identifier leakage, backup deletion failure, support bundle secret exposure.
- Practical active traffic confirmation materially stronger than documented limitation because of implementation bug.

Severity определяется demonstrated impact, exploitability, affected users/platforms и required privileges, а не
только CVSS. Privacy deanonymization и fail-open обычно повышают severity.

## 5. Research rules

Разрешается при соблюдении опубликованного scope:

- использовать только свои test accounts, tokens, devices и synthetic destinations;
- выполнять local/offline reverse engineering, static/dynamic analysis и malformed-input/fuzz tests;
- тестировать staging/research gateway в опубликованных rate limits;
- демонстрировать минимально необходимое proof без извлечения/сохранения чужих данных;
- немедленно прекратить тест, если получен доступ к real user data, production secret или нестабильности вне своей
  test session, и сообщить emergency contact.

Запрещается:

- DDoS/load test production, resource exhaustion beyond published sandbox budget или влияние на доступность;
- social engineering, phishing, physical intrusion, employee targeting и credential stuffing;
- просмотр, изменение, скачивание или сохранение чужого traffic/account/payment data;
- сканирование/атака Internet destinations через exits, spam, malware, BitTorrent или обход acceptable-use policy;
- атака Tor relays, cloud/payment/app-store/analytics vendors или другого third party;
- persistence, lateral movement или destructive action после минимального proof;
- публичное раскрытие до согласованного срока координации.

## 6. Safe harbor draft

Если researcher действует добросовестно, строго в опубликованном scope/rules, минимизирует данные и оперативно
сообщает уязвимость, OnionRoute считает такое исследование авторизованным в пределах применимого права и не
инициирует юридическое преследование за обход наших собственных технических мер. Если third party начинает
действие, OnionRoute по возможности подтвердит добросовестность researcher.

Safe harbor не даёт разрешения нарушать права третьих лиц, законы, sanctions/export rules или тестировать чужие
системы. Финальный текст обязан проверить legal counsel в каждой применимой юрисдикции.

## 7. Out of scope как класс finding

Если нет дополнительного security impact:

- факт того, что ISP/guard видит использование Tor, и общая timing correlation глобального наблюдателя;
- malicious destination linking через собственный login/cookie/browser fingerprint;
- видимость destination exit gateway по определению архитектуры, если нет persistence/extra disclosure;
- публично известные Tor/C Tor issues без OnionRoute-specific exploit на supported version;
- self-XSS, clickjacking страницы без sensitive action, missing cosmetic headers, version banner;
- rate limit observation без demonstrated auth/privacy/availability impact;
- automated scanner output без reproduction и impact;
- obsolete client version вне support window без update rollback/freeze path;
- SPF/DKIM/DMARC и email findings, не влияющие на account takeover;
- best-practice note без exploit/security boundary violation.

`Out of scope` asset не означает разрешение тестировать его. Новый сильный impact можно сообщить без дальнейшего
эксплуатирования; команда рассмотрит scope exception безопасно.

## 8. Report requirements

Report должен содержать:

1. policy/scope version, asset и exact signed build/protocol version;
2. threat actor/prerequisites и step-by-step minimal reproduction;
3. expected vs actual fail-closed behavior;
4. impact на IP, destination, identity, authorization, integrity или availability;
5. synthetic evidence: pcap/request/response/crash/resource graph с timestamps и secrets redacted;
6. повторяемость, affected modes/platforms и cleanup performed;
7. возможный root cause/fix только если researcher уверен;
8. disclosure/contact preferences.

Не прикладывать real destination history, чужие tokens/accounts, production dumps или full secrets. Один report
может объединять общий root cause; unrelated issues подаются отдельно.

## 9. Triage и disclosure draft

- Automated receipt: `<24 hours>`.
- Human acknowledgement/emergency privacy leak response: `<24/72 hours>`.
- Initial severity/validity: `<7 days>`.
- Status update cadence: `<14 days>`.
- Coordinated disclosure target: `<90 days>`, с возможностью сократить для actively exploited leak.
- Duplicate определяется root cause + affected boundary, но новый platform/impact может получить дополнительное
  признание по policy.
- Reward выплачивается за первое качественное сообщение после fix/retest по опубликованной severity table.
- Команда предоставляет researcher remediation summary и credit по желанию после безопасного disclosure.

## 10. Internal launch checklist

- [ ] Asset inventory проверен owner-ами; production и sandbox невозможно перепутать.
- [ ] Sandbox изолирован, содержит только synthetic data и имеет bounded quotas/kill switch.
- [ ] Intake не использует обычную telemetry и удаляет report attachments по documented TTL.
- [ ] 24/7 critical leak/key compromise runbook и revoke/update capability протестированы.
- [ ] Triage team обучена privacy severity и не просит researcher собирать browsing history.
- [ ] Legal safe harbor, rewards, taxes, sanctions/export и disclosure policy утверждены.
- [ ] Security contact/PGP/SLA работают внешним тестом.
- [ ] Known limitations/findings записаны для consistent duplicate handling.
- [ ] Program сначала private/invite-only, затем расширяется после operational review.
