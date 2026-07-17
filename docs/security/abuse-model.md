# OnionRoute: abuse model

- Статус: mandatory design constraints; не разрешает user-level surveillance.
- Дата: 2026-07-17.
- Primary owners: `gateway/egress`, `control/auth-tokens`, `infra/platform`.

## 1. Принцип

Abuse prevention не отменяет privacy model. OnionRoute не хранит destination history, не делает DPI/content
logging, не добавляет persistent user ID и не объединяет billing с network activity. Если abuse нельзя расследовать
без такого dataset, принимается ограничение сервиса, coarse egress policy, current-token rate limit или отключение
конкретного gateway — не скрытая слежка.

Разрешённый механизм на gateway: bounded in-memory counters/sketches с keyed per-process digest, окном не более
10 минут и purge при restart. Key не экспортируется; digest не сопоставляется между gateways и не переживает окно.
События наружу — только coarse count/reason bucket после aggregation, без destination, token/nullifier, session,
IP, port или account. Token replay nullifier живёт отдельно и только до срока из privacy model.

## 2. Abuse actors

- Пользователь с действующим entitlement/token.
- Token thief/reseller без законного account control.
- Remote DDoS actor без token, атакующий onion/control/public infrastructure.
- Malicious destination, провоцирующий большие/stalled responses.
- Вредоносный оператор, использующий anti-abuse как повод для deanonymization.
- Third-party complainant, требующий невозможную связь exit activity с account.

## 3. Реестр abuse cases

| ID | Актив/жертва | Актор и сценарий | Prevent/detect с privacy | Response | Residual risk | Test | Owner |
|---|---|---|---|---|---|---|---|
| A-01 | Internet hosts, exit reputation | Valid user fan-out scans many hosts/ports | In-memory 10m fanout sketch, coarse connection-rate bucket, block admin/reserved ports | Throttle/current session close; short token class cooldown без account join | Высокий: распределённый slow scan трудно отличить | ABT-001 / ST-073 | `gateway/egress` |
| A-02 | Victim availability | Valid users создают TCP application-layer DDoS | Per-session/per-token concurrent-flow, byte/credit и open-rate quotas; fleet load aggregate | Reject new opens, drain, revoke issuer class/key only при systemic incident | Высокий: low-and-slow и many tokens | ABT-002 / ST-073 | `gateway/egress` |
| A-03 | Mail infrastructure/reputation | Попытка SMTP spam | Block TCP/25 независимо в parser policy и nftables; optional fixed blocked-port set | Fail closed с coarse policy error | Средний: submission ports 465/587 могут злоупотребляться | ABT-003 / ST-043 | `gateway/egress` |
| A-04 | Peers/copyright/reputation | BitTorrent tracker/peer traffic поверх TCP | MVP блокирует known ports/signatures только без payload retention; arbitrary UDP blocked | Close current flow; publish limitation, не обещать perfect classification | Высокий: encrypted/obfuscated TCP detection неполна | ABT-004 / ST-043 | `gateway/egress` |
| A-05 | Credentials/web services | Credential stuffing/automated login через exits | Coarse current-token connection/open limits; destinations сами применяют auth/rate controls | Throttle, gateway capacity isolation; no browsing history | Высокий: содержимое и destination не анализируются | ABT-005 / ST-073 | `gateway/egress` |
| A-06 | Internal/cloud control plane | SSRF к metadata/private/management/Tor control | Parse/resolve/re-resolve/dial IP validation + namespace nftables deny | Reject before dial; alert only coarse SSRF-range class counter | Низкий после доказанных G-06 tests | ABT-006 / ST-039,040 | `gateway/egress` |
| A-07 | Gateway memory/CPU/FD | Malformed frames, slowloris, many streams, stalled DNS | Pre-allocation bounds, deadlines, credit, session/global budgets | Cheap reject/close, load shedding; never auth/fallback bypass | Средний: capacity loss остаётся | ABT-007 / ST-038,042,044 | `protocol/gateway-v1` |
| A-08 | Token capacity/revenue | Sharing/reselling valid tokens | 15m TTL, proof/replay, scope, bounded concurrency; no device binding | Reject replay; rotate compromised issuer class only if necessary | Высокий: voluntary transfer до first use возможен | ABT-008 / ST-051…058,074 | `control/auth-tokens` |
| A-09 | Entitlement | Forge/alter capability or reuse between hops | Reviewed blind/VOPRF library, issuer/audience/role scope, independent per-hop token | Reject and coarse auth-failure aggregate; no account lookup | Критический до crypto review | ABT-009 / ST-052,053,056 | `control/auth-tokens` |
| A-10 | Fleet availability | Gateway enumeration и targeted onion DDoS | Onion service auth, capacity diversification, rate/resource isolation, no clearnet inventory | Remove unhealthy descriptor by signed directory; no unsafe fallback | Высокий: authorized clients видят catalog | ABT-010 / ST-031,042 | `infra/platform` |
| A-11 | Control/directory/token service | Public request floods, expensive blind issuance | Pre-auth cheap bounds, Tor-aware rate buckets, queue/budget, cached signed directory | Shed load; valid cached directory until hard expiry; no relaxed auth | Высокий: fail-closed outage возможен | ABT-011 / ST-050,072 | `infra/platform` |
| A-12 | Gateway/operator reputation | Malware/C2/phishing uses exit | No payload/destination logging; published acceptable-use policy; coarse capacity controls | Respond with exit explanation; block only documented threat class/range via reviewed policy | Высокий: privacy tunnel неизбежно может быть misused | ABT-012 | `product/documentation` |
| A-13 | Users/privacy | False complaint pressures operator раскрыть account | По архитектуре mapping exit flow→account не существует | Standard response states non-attributability; preserve only admin/legal ticket | Средний: legal/operational pressure | ABT-013 / ST-067 | `product/documentation` |
| A-14 | Privacy model | Admin включает packet/destination logging «для abuse» | Config/collector technically lack raw schema; deploy + observability SoD; immutable policy diff alert | Stop pipeline/rollout, privacy incident, verified deletion | Критический при colluding admins | ABT-014 / ST-064…071 | `infra/platform` |
| A-15 | Support staff/users | Social-engineered support bundle содержит secrets/history | Local manifest preview, fixed redaction, explicit user action, 7d server TTL | Quarantine/delete bundle, rotate exposed secrets, notify user | Средний: user can manually attach external data | ABT-015 / ST-014 | `client/desktop` |
| A-16 | Exit capacity | Malicious destination sends endless/slow/oversized responses | Per-flow credit, idle/absolute deadline, bounded reverse buffer | Reset current flow and release all tasks/FDs | Средний | ABT-016 / ST-044 | `gateway/egress` |
| A-17 | Directory/signing operations | Abuse insider advertises private/unapproved gateway | Four-eyes inventory, isolated signer, transparency/equivocation monitor | Revoke descriptor/key, emergency signed directory, incident review | Высокий until transparency is designed | ABT-017 / ST-030,047…049 | `control/directory` |

## 4. Разрешённые и запрещённые abuse signals

| Разрешено | Запрещено |
|---|---|
| Current process counts: active sessions/streams, queue/CPU/memory buckets | Destination IP/hostname/domain/port list или DNS wire |
| Coarse policy reason enum: `reserved_range`, `blocked_port_class`, `rate_limit` | Packet/payload sample, URL, SNI, certificate, credential pattern |
| 10-minute non-exported keyed fanout sketch | Stable per-user/device/token hash или cross-gateway digest |
| Token nullifier только для replay и только до expiry window | Join nullifier с issuance/account/payment или destination |
| Fleet aggregate capacity/error rate after k-threshold | Exact session timestamps/route/gateway choice доступные analyst |
| Signed admin policy diff и deployment identity | Admin ability включить arbitrary packet capture через normal deploy |

## 5. Enforcement hierarchy

1. Protocol allowlist и network namespace: запретить невозможное независимо от application bug.
2. Bounded resource quotas до expensive crypto/DNS/allocation, не раскрывая identity.
3. Short-lived anonymous capabilities и replay protection.
4. Fleet-level coarse health/load shedding.
5. Published acceptable-use policy и transparent handling complaints.
6. Только если предыдущих мер недостаточно — отказаться от risky capability; не добавлять surveillance.

## 6. Abuse test requirements

- `ABT-001…017` выполняются до production и после изменения policy/token/gateway layout.
- Каждый тест проверяет одновременно enforcement, bounded resources и **отсутствие** запрещённых fields в logs,
  traces, metrics, support и backups.
- Synthetic destinations принадлежат test environment; DDoS/scan не проводится против third parties.
- Threshold tuning использует synthetic/load data, не реальную destination history.
- False-positive test доказывает, что overload приводит к coarse throttle/close, а не к identity collection.

## 7. Открытые вопросы

- Какие submission/admin ports кроме TCP/25 блокируются без превращения policy в destination profiling?
- Как распространять reviewed threat-range denylist и независимо аудировать её изменения?
- Какой onion-service authorization lifecycle уменьшает enumeration, не создавая stable user fingerprint?
- Какие coarse quotas совместимы с blind tokens и не делают capability vector уникальным?
- Как отвечать на abuse complaints в каждой юрисдикции без несуществующей attribution capability?
