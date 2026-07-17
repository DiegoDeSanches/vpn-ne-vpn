# OnionRoute: attack trees

- Статус: companion к [threat model](threat-model.md).
- Нотация: `OR` — достаточно одной ветви; `AND` — нужны все дочерние условия.
- Дата: 2026-07-17.

## AT-01 Деанонимизировать пользователя и destination

```text
ROOT [OR] Связать реальный user/IP с destination
├─ [AND] Глобальная timing correlation
│  ├─ Наблюдать access link/guard timing (T-015, T-016)
│  ├─ Наблюдать exit/destination timing (T-019)
│  └─ Сопоставить volume/bursts/duration (T-020, T-021)
├─ [AND] Collusion маршрута
│  ├─ Контролировать/наблюдать entry (T-025)
│  └─ Контролировать exit и его flow metadata (T-027, T-028)
├─ [AND] Billing/network correlation
│  ├─ Получить account/payment issuance data
│  ├─ Получить gateway/health redemption data
│  └─ Найти ID, timestamp или capability join (T-054, T-055, T-066, T-067)
├─ [OR] Локальная утечка IP/destination
│  ├─ DNS/IPv6/WebRTC/QUIC (T-004…T-007)
│  ├─ Kill-switch race/captive/resume (T-003, T-009, T-010)
│  └─ Split/direct-socket bypass (T-001, T-008)
└─ [OR] Application-level identity
   ├─ Login/cookie/device fingerprint сохраняется
   └─ New Identity меняет route, но не app identity (T-024)
```

Ключевой вывод: ветвь global observation не закрывается существующим дизайном. Обязательны ограничение claims,
разделение данных и ST-001…ST-024; padding может только уменьшить сигнал и требует отдельного доказательства.

## AT-02 Выпустить пользовательский traffic в clearnet

```text
ROOT [OR] Создать direct user packet/socket
├─ [AND] Найти lifecycle gap
│  ├─ Спровоцировать connect/route/firewall race
│  └─ Отправить packet в gap (T-003)
├─ [OR] Активировать неподдержанный transport
│  ├─ IPv6 (T-005)
│  ├─ WebRTC/STUN/TURN (T-006)
│  └─ QUIC/unknown UDP (T-007)
├─ [OR] Ослабить policy workflow
│  ├─ Captive portal (T-009)
│  ├─ Sleep/resume/network change (T-010)
│  ├─ Crash/uninstall/stale lease (T-011)
│  └─ Split-tunnel impersonation (T-008)
└─ [OR] Компрометировать client
   ├─ Подписанное malicious update (T-059…T-061)
   └─ Подменённый Tor/PT создаёт socket (T-062)
```

Cut set: любой одиночный platform gap достаточен. Поэтому pcap zero-leak — не выборочный regression test, а
non-waivable gate G-01/G-02/G-12 для каждой OS и lifecycle transition.

## AT-03 Навязать вредоносный gateway route

```text
ROOT [OR] Клиент устанавливает session с attacker gateway
├─ Принять unsigned/wrong-key directory (T-045)
├─ Откатить catalog/clock к vulnerable gateway (T-046)
├─ Украсть signing root и подписать descriptor (T-047)
├─ Захватить emergency/next-key rotation (T-048)
├─ Выдать targeted valid catalog конкретному клиенту (T-049)
└─ [AND] Подменить terminal identity
   ├─ Доставить attacker hop
   └─ Обойти onion/SPKI/role binding (T-030, T-034)
```

Signature предотвращает tampering, но не злонамеренное использование valid key. Требуются isolated/threshold
ceremony, two-person inventory approval, equivocation detection и negative identity tests G-03/G-13.

## AT-04 Получить неавторизованный gateway access

```text
ROOT [OR] Использовать gateway без действующего entitlement
├─ Украсть и replay-нуть token до expiry (T-051)
├─ Передать expired/future/wrong-audience token (T-052)
├─ Переиспользовать token между roles/hops (T-053)
├─ Forge token из-за crypto/library flaw (T-056)
├─ Украсть issuer key и mint tokens (T-057)
├─ Выиграть race в nullifier store (T-058)
└─ Обойти token через public/open gateway listener (T-032)
```

Минимальные cut sets закрываются только совместно: reviewed standard crypto, max 15-minute TTL, offline complete
validation, atomic bounded replay store, per-hop scope и отсутствие public ingress. См. G-10/G-11.

## AT-05 Превратить gateway в pivot/open proxy

```text
ROOT [OR] Достичь запрещённого ресурса или выполнить abuse
├─ [OR] SSRF
│  ├─ Direct private/metadata IP literal (T-039)
│  ├─ IPv4-in-IPv6/alternate textual encoding (T-039)
│  └─ DNS CNAME/rebinding/TOCTOU (T-040)
├─ Role confusion: entry/relay открывает Internet socket (T-033)
├─ Public user ingress обходит Tor/auth (T-032)
├─ Обход SMTP/BitTorrent/admin ACL (T-043)
└─ [AND] Resource abuse
   ├─ Valid или дешёвый session/token
   └─ Scan/DDoS/many slow streams (T-042, T-044, T-073, T-074)
```

Нужны независимые application и nftables checks, revalidation immediately-before-dial, loopback-only listener,
role mTLS и bounded anonymous anti-abuse state. Destination history не допускается даже для расследования abuse.

## AT-06 Встроить backdoor через supply chain/update

```text
ROOT [OR] Запустить attacker code в клиенте/gateway
├─ [AND] Компрометировать unsigned/weak updater
│  ├─ Подменить artifact/metadata
│  └─ Пройти без pinned threshold verification (T-059)
├─ Freeze/rollback к известной vulnerable signed версии (T-060)
├─ [AND] Компрометировать build до signing
│  ├─ Dependency/maintainer/runner change
│  └─ Отсутствие independent rebuild/provenance review (T-061)
├─ Подменить bundled Tor/pluggable transport (T-062)
├─ Извлечь hardcoded release/production secret (T-063)
└─ Злоупотребить signing/KMS admin access (T-047, T-057, T-070)
```

Подпись конечного artifact не защищает от compromised build. Нужна цепочка source review → hermetic build →
SBOM/provenance → independent rebuild → threshold signing → updater rollback/freeze checks (G-08/G-09/G-15).

## AT-07 Создать скрытую историю network activity

```text
ROOT [OR] Получить persistent destination/user-session dataset
├─ Вредоносный admin включает destination/packet logging (T-064)
├─ Incident/debug mode пишет raw values (T-065)
├─ Общие trace/session IDs создают cross-layer join (T-066)
├─ Billing и network stores имеют общий/quasi join (T-067)
├─ Малые telemetry cohorts идентифицируют пользователя (T-068)
├─ TTL удаляет primary, но не backup/replica/export (T-069)
├─ Cloud snapshot/admin console раскрывает memory/store (T-070)
└─ Observability vendor получает arbitrary labels/raw events (T-071)
```

Prevention важнее redaction: закрытые схемы, отсутствие raw fields, раздельные stores/IAM/keys, k-threshold до
доступа человека и deletion restore tests. Любая ветвь является stop-ship G-07/G-14.

## AT-08 Лишить сервис доступности и спровоцировать unsafe recovery

```text
ROOT [AND] Нарушить availability и добиться privacy downgrade
├─ [OR] Исчерпать ресурс
│  ├─ Gateway frames/streams/slow peers (T-038, T-042, T-044)
│  ├─ Replay/nullifier state (T-058)
│  └─ Control/directory/token endpoints (T-050, T-072)
└─ [OR] Спровоцировать unsafe response
   ├─ Clearnet/Direct Tor fallback
   ├─ Expired directory acceptance
   ├─ Auth fail-open
   └─ Captive/debug firewall relaxation
```

Первая половина полностью не устраняется; вторая должна быть невозможна. Правильный исход overload/outage —
bounded отказ, старый ещё valid защищённый route или `Blocked`, никогда не fallback.

## Traceability

| Дерево | Threats | Главные gates |
|---|---|---|
| AT-01 | T-001…T-024, T-027…T-029, T-054…T-055, T-066…T-067 | G-01, G-02, G-12, G-14, G-16 |
| AT-02 | T-001, T-003, T-005…T-011, T-059…T-062 | G-02, G-09, G-12, G-15 |
| AT-03 | T-030, T-034, T-045…T-049 | G-03, G-13 |
| AT-04 | T-032, T-051…T-058 | G-10, G-11, G-16 |
| AT-05 | T-032…T-033, T-039…T-044, T-073…T-074 | G-05, G-06, G-10, G-11 |
| AT-06 | T-047, T-057, T-059…T-063, T-070 | G-08, G-09, G-15 |
| AT-07 | T-064…T-071 | G-07, G-14 |
| AT-08 | T-038, T-042, T-044, T-050, T-058, T-072 | G-02, G-05 |
