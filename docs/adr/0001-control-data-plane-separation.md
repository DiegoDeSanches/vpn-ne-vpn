# ADR-0001: разделить control plane и data plane

- Статус: Accepted
- Дата: 2026-07-16

## Контекст

Control plane знает account entitlement и управляет каталогом/политикой. Data plane
обрабатывает privacy-sensitive TCP/DNS и не должен связывать session с account. Общая
модель/БД/API сделали бы случайную корреляцию и lateral compromise слишком простыми.

## Решение

Control и data plane имеют разные protobuf packages, сервисы, deployments, ключи,
хранилища, access roles и telemetry pipelines. `gateway.proto` импортирует только
`common.proto`; account/control types недоступны gateway implementation.

Account authentication завершается на control API. Gateway получает только
short-lived capability token. Gateway redemption не делает synchronous account или
billing lookup. Billing analytics и network health нельзя соединять общим ID.

`client-core` — единственное место, где control artifacts (verified directory,
unblinded token) соединяются с локальным data session. Эти объекты не содержат
account ID.

## Последствия

- Команды control/gateway могут выпускаться независимо через versioned contracts.
- Entitlement revocation не может мгновенно query account DB на каждом flow; нужны
  короткий token TTL и issuer key revocation.
- Operations сложнее: отдельные базы, IAM, dashboards и incident procedures.
- Privacy audit может доказать отсутствие identity field статически и динамически.

## Проверка

- CI запрещает imports control → gateway и identity-like fields в gateway descriptors.
- Integration audit сравнивает issuance/redemption logs и не находит join key.
- Account/control outage не завершает уже действующую gateway session до её TTL.

