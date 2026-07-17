# Product/documentation iteration report — 2026-07-17

## Что реализовано

- Product requirements для MVP, позиционирование и реестр технически проверяемых
  marketing claims.
- Честные описания Standard, Enhanced, Maximum и Direct Tor без обещания абсолютной
  анонимности.
- Полный onboarding до первого подключения с обязательным раскрытием TCP-only,
  UDP/QUIC blocking, fail-closed и split-tunnel risk.
- User documentation для supported traffic, country selection, automatic circuit
  rotation, identity reset, kill switch и split tunneling.
- Threat model summary, account/gateway privacy, конкретная logging/TTL table,
  abuse, transparency и deletion policies.
- FAQ, безопасные troubleshooting playbooks и redacted support guidance.
- Канонический UX copy для 12 запрошенных error/warning states.
- Структурный test полноты, error primary actions и local Markdown links.

## Добавленные файлы

- `docs/product/README.md`
- `docs/product/product-requirements.md`
- `docs/product/onboarding.md`
- `docs/product/traffic-and-routing.md`
- `docs/product/privacy-and-policies.md`
- `docs/product/faq-and-troubleshooting.md`
- `docs/product/error-copy.md`
- `tests/product-documentation/validate_product_docs.py`
- `docs/iteration-reports/product-documentation.md`

## Публичные интерфейсы

Публичные code/wire/API interfaces не создавались и не изменялись. Документы задают
canonical product copy и acceptance requirements для последующей интеграции
владельцами clients/control/gateway. `proto/`, `crates/common-types/`, root
`Cargo.toml`, CI, directory и token formats не изменялись.

## Предположения

- MVP поддерживает TCP и protected DNS; arbitrary UDP, QUIC, IPv6 egress,
  BitTorrent и SMTP/25 не разрешены.
- Страна — verified directory property private exit, не GeoIP guarantee.
- Standard рекомендуется по умолчанию; название mode описывает topology, а не
  гарантированный уровень анонимности.
- Identity reset является hard network-session reset, а не browser/app identity
  reset.
- Privacy architecture является release requirement, а не автоматически
  подтверждённым свойством текущего implementation state.

## Ограничение репозитория

В workspace отсутствует usable `.git`, поэтому Git сообщает `not a git repository`.
Обязательную ветку `product/documentation` нельзя создать или проверить. Изменения
изолированы в новых product-documentation/test paths и этом iteration report.

## Тесты проходят

- Bundled Python:
  `tests/product-documentation/validate_product_docs.py` — pass.
- Проверено 7 обязательных product documents, 12 error states, наличие canonical
  positioning/modes/sections, отсутствие unsafe primary action и целостность local
  Markdown file links.

## Тесты не проходят / не запускались

- Application UI snapshot/localization tests не запускались: client locale и UI
  implementation не входят в эту итерацию.
- Platform leak/integration/security tests не запускались этой ролью; соответствующие
  claims остаются gated до evidence владельцев компонентов и QA.

## Зависимости от других агентов

- `security/threat-model`: review публичного summary и mode/residual-risk wording.
- `control/auth-tokens`: blind issuance и ST-054/ST-056 до production account
  unlinkability claim.
- `qa/integration`: platform leak evidence и claim registry dates/test IDs.
- `client/desktop` и `client/mobile`: интеграция canonical copy, state variants,
  accessibility и onboarding comprehension tests.
- `control/directory` / `gateway/egress`: verified country/role/egress evidence и
  logging/deletion schema evidence.
- Legal/privacy owner: точные billing retention schedules по юрисдикции и review
  transparency/legal-request language.

## Найденные security-риски

- Global timing correlation, compromised device и application identifiers не
  устраняются ни одним mode.
- Maximum может создать ложное чувство безопасности, если подать его как «самый
  анонимный» без residual-risk warning.
- Private/public exit видит destination и plaintext без end-to-end TLS.
- Редкая country/mode combination уменьшает anonymity set.
- Soft rotation не меняет route уже открытых TCP flows; hard reset не меняет
  cookies/logins/fingerprint и может сохранить тот же egress IP.
- Split-tunnel exclusions раскрывают direct IP/system DNS и не покрываются kill
  switch OnionRoute.
- Автоматический captive-portal bypass ослабил бы firewall protection; безопасный
  platform workflow ещё не специфицирован полностью.
- Текущий non-blind token profile допускает issuer correlation и остаётся
  release-blocked нормативной privacy model.

## Contract proposals

Не создавались: protected contracts и публичные code interfaces не менялись.

## Готово к интеграции

Product requirements, canonical Russian copy, help/policy content, error state
matrix и automated structural validation. Claims помечены evidence gates и не
должны публиковаться как реализованные до прохождения соответствующих тестов.

## Открытые вопросы

1. Будет ли UI переименован с «Уровень анонимности» на «Режим маршрута»?
2. Какие OS/system services и platform exclusions входят в доказанный system-wide
   coverage каждого release?
3. Каков approved captive-portal workflow для Windows, macOS, Linux, Android и iOS
   без автоматического firewall bypass?
4. Какие точные billing/admin audit retention сроки требуются по каждой юрисдикции?
5. Кто владеет полугодовым transparency report и независимой проверкой claims?
6. Какие infrastructure facts разрешают говорить о независимых admin/KMS domains
   между Enhanced/Maximum hops?
7. Когда blind token issuance и no-join evidence снимут account privacy release
   blocker?
8. Нужна ли отдельная локализационная стратегия для терминов `private onion
   gateway`, `country-selectable Tor egress` и `kill switch`?

