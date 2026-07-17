# ADR-0002: fail-closed kill switch как prerequisite

- Статус: Accepted
- Дата: 2026-07-16

## Контекст

Прямой fallback или transient OS route gap раскрывает IP/destination именно во время
сбоев, rotation и shutdown. Firewall APIs платформ различаются и могут завершиться
частично; одного успешного return value недостаточно.

## Решение

`client-core` устанавливает kill switch после `Preparing`, до Tor bootstrap и любого
control/data connection. `KillSwitch::engage` возвращает generation lease, затем
вызывается независимый `verify`. Неуспех/timeout/неопределённость вызывает
`emergency_block` и состояние `Blocked`.

Rules сохраняются во всех protected states, rotation и reconnect. Shutdown идёт в
обратном порядке; `disengage` вызывается последним и только с актуальным lease. Crash
recovery сначала инспектирует оставшиеся rules. System DNS, arbitrary UDP, QUIC и
неявный clearnet fallback запрещены.

## Последствия

- При ошибке firewall пользователь может временно потерять сеть; это ожидаемый
  security trade-off и должно объясняться UI.
- Platform team реализует atomic update, lease generation, verify и crash recovery.
- Development/test окружения обязаны использовать mock/namespace, а не выключать KS.

## Проверка

- Leak tests во время connect/rotation/crash/shutdown и network change.
- Stale lease не снимает новые rules.
- Невозможный state transition после KS failure проверяется unit/property tests.

