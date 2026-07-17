# Общий контекст для всех агентов

## Проект

Проект: **OnionRoute**.

OnionRoute — системный privacy tunnel, внешне похожий на VPN-клиент, но не использующий WireGuard, OpenVPN или IPsec между пользователем и сервером.

Базовый маршрут:

```text
Application
→ TUN / системный packet tunnel
→ локальный flow engine
→ Tor
→ Tor v3 Onion Service
→ собственный private exit gateway
→ Internet
```

## Основные возможности

- Перехват системного TCP-трафика.
- DNS внутри защищённого маршрута.
- Kill switch.
- Защита от DNS-, IPv6- и QUIC-утечек.
- Выбор страны выхода.
- Автоматическая смена Tor-цепочек.
- Ручная функция «Новая личность».
- Разные уровни анонимности.
- Управляемый мультихоп.
- Собственные private exit gateway.
- Split tunneling.
- Анонимные capability tokens.
- Отсутствие постоянного user ID в data plane.
- Минимальная телеметрия.
- Fail-closed поведение.

## Ограничения MVP

- Поддерживается TCP.
- Произвольный UDP не поддерживается.
- QUIC блокируется.
- BitTorrent запрещён.
- SMTP port 25 запрещён.
- Прямой clearnet fallback запрещён.
- Системный DNS запрещён во время активного tunnel.
- При сбое соединения пользовательский трафик блокируется.

## Язык и стек

Основной язык общего ядра и gateway: **Rust**.

Предпочтительный стек:

- Rust.
- Tokio.
- `tracing`.
- `serde`.
- `rustls`.
- Protobuf через `prost`.
- C Tor для первого MVP.
- Абстракция для последующего подключения Arti.
- PostgreSQL в control plane.
- OpenTofu/Terraform.
- Ansible.
- nftables.
- Prometheus.
- Grafana.
- systemd.
- Vault или cloud KMS.

## Уровни анонимности

### Standard

```text
User → Tor → private exit gateway → Internet
```

### Enhanced

```text
User → Tor → entry gateway → encrypted transport → exit gateway → Internet
```

### Maximum

```text
User → Tor → entry gateway → relay gateway → exit gateway → Internet
```

### Direct Tor

```text
User → Tor → public Tor exit → Internet
```

## Общие требования

- Не использовать самодельную криптографию.
- Не заявлять абсолютную анонимность.
- Не логировать историю сайтов.
- Не логировать содержимое пользовательского трафика.
- Не передавать реальные IP в data plane.
- Не объединять платёжную аналитику и сетевую телеметрию.
- Все сетевые протоколы должны быть версионированы.
- Все входные данные должны иметь лимиты размера.
- Все сервисы должны корректно обрабатывать backpressure.
- Production-код должен иметь unit-, integration- и fuzz-тесты.
- Все архитектурные предположения должны быть явно записаны.
- Публичные интерфейсы между компонентами должны документироваться.

## Структура монорепозитория

```text
onionroute/
├── docs/
├── proto/
├── crates/
│   ├── common-types/
│   ├── gateway-protocol/
│   ├── client-core/
│   ├── tor-backend/
│   ├── circuit-manager/
│   ├── packet-engine/
│   ├── dns-engine/
│   ├── policy-engine/
│   ├── gateway-daemon/
│   ├── gateway-directory/
│   └── auth-tokens/
├── services/
│   ├── control-api/
│   ├── directory-service/
│   ├── token-service/
│   ├── billing-adapter/
│   └── health-collector/
├── clients/
│   ├── desktop/
│   ├── android/
│   └── ios/
├── infrastructure/
│   ├── opentofu/
│   ├── ansible/
│   └── images/
└── tests/
    ├── integration/
    ├── leak-tests/
    ├── performance/
    └── security/
```

## Обязательные правила для каждого агента

- Работать только в своей зоне ответственности.
- Не менять чужие публичные интерфейсы без ADR.
- Создавать mocks для ещё не готовых зависимостей.
- Документировать API и форматы данных.
- Добавлять тесты.
- Не добавлять скрытую телеметрию.
- Не ослаблять kill switch ради удобства разработки.
- Возвращать список открытых вопросов.
- Создавать ADR для важных решений.
- Отмечать экспериментальный код.

## Правила параллельной работы

### Ветки и зоны ответственности

Все агенты должны работать в отдельных ветках:

- `architecture/contracts`
- `core/network-engine`
- `core/tor-backend`
- `protocol/gateway-v1`
- `gateway/egress`
- `control/directory`
- `control/auth-tokens`
- `infra/platform`
- `security/threat-model`
- `client/desktop`
- `client/mobile`
- `qa/integration`
- `gateway/multihop`
- `product/documentation`

### Защищённые общие файлы и контракты

Общие файлы и контракты нельзя менять напрямую без согласования с архитектором:

- `proto/`
- `crates/common-types/`
- Корневой `Cargo.toml`
- Конфигурация CI
- Public API
- Directory format
- Token format

### Изменение контрактов

При необходимости изменить контракт агент создаёт документ:

```text
docs/contract-proposals/CP-XXXX.md
```

Документ должен содержать:

- Проблему.
- Текущий контракт.
- Предлагаемое изменение.
- Затронутые команды.
- Совместимость.
- Миграцию.
- Риски.
- Тесты.

До принятия предложения агент использует adapter или mock и не меняет защищённый контракт напрямую.

### Отчёт агента в конце итерации

Каждый агент в конце итерации возвращает:

- Что реализовано.
- Какие файлы добавлены.
- Какие публичные интерфейсы созданы.
- Какие предположения сделаны.
- Какие тесты проходят.
- Какие тесты не проходят.
- Какие зависимости ожидаются от других агентов.
- Какие security-риски найдены.
- Какие contract proposals созданы.
- Что готово к интеграции.
