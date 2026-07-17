# ADR-0007: runtime-neutral TorBackend

- Статус: Accepted
- Дата: 2026-07-16

## Контекст

MVP использует C Tor, но долгосрочно возможен Arti. Если control port, process handles
или конкретные async/runtime types попадут в client-core, замена потребует изменения
всех компонентов и платформ.

## Решение

В `common-types::contracts::v1` вводится platform-neutral `TorBackend`: bootstrap,
v3 onion stream, explicit Direct Tor stream, coarse status и shutdown. Асинхронность
через runtime-neutral `BoxFuture`, поток через `ByteTransport`. C Tor/Arti internals,
control protocol и process lifecycle скрыты implementation.

`CircuitManager` использует `TorBackend` и владеет route leases/isolation/rotation;
client-core не обращается к C Tor напрямую. Isolation key случайный per route и не
производится из user/device identity.

## Последствия

- Небольшой abstraction cost и необходимость adapters к Tokio/C Tor/Arti streams.
- Некоторые backend-specific capabilities недоступны до versioned extension.
- Один contract/mock позволяет client, circuit и gateway teams работать параллельно.

## Проверка

- Одна contract suite для mock, C Tor и будущего Arti.
- Compile-time отсутствие platform/C/Tokio dependencies в `common-types`.
- Isolation, cancel, deadline, shutdown и resource leak tests.

