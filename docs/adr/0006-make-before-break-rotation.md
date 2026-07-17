# ADR-0006: make-before-break rotation

- Статус: Accepted
- Дата: 2026-07-16

## Контекст

Периодическая или ручная New Identity должна менять Tor isolation и gateway session.
Break-before-make создаёт длительный outage и может провоцировать опасный fallback;
неуправляемое одновременное использование путей размывает identity boundary.

## Решение

В `Rotating` старый route/session остаётся default и защищён kill switch. Параллельно
создаются fresh isolation route и unlinkable token, затем новая gateway session.
Только после `Active` orchestrator атомарно направляет новые flow в replacement и
очищает DNS cache. Old session входит в `Draining`: существующие TCP flow завершаются
до bounded deadline, новые туда не назначаются. После close старый circuit retire.

Если replacement не готов, а old path здоров, rotation откладывается (`Degraded`) с
jitter backoff. Потеря обоих путей ведёт в `Reconnecting`; прямой маршрут не создаётся.

## Последствия

- На время rotation выше resource usage и одновременно существуют две sessions.
- Старые long-lived TCP flows сохраняют прежнюю identity до drain deadline; UI не
  должен обещать мгновенную смену для уже открытых соединений.
- Нужны строгие session/route ownership и idempotent retirement.

## Проверка

- Load test atomic new-flow switch и bounded dual-route resources.
- Failure injection до/после Active; healthy old path не закрывается раньше времени.
- DNS cache flush и fresh token/isolation assertions.

