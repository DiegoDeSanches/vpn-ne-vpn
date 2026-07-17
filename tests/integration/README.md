# Integration scenarios

`test_full_route.py` выполняет настоящий loopback byte route через authenticated
Mock Tor и 0/1/2/3 private-hop mocks. `test_lifecycle.py` проверяет fail-closed
state oracle для first launch, connect/disconnect, mode/country/rotation/identity,
crash, network и reboot. Mocks заменяются реальными компонентами по одному без
изменения public v1 contracts. Mock results не являются release evidence.
