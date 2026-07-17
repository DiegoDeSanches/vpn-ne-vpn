# Linux local integration lab

Этот lab создаёт четыре изолированных namespace на flat hostile bridge. Прямая
видимость client→fixture намеренна: leak suite должна доказать, что kill switch
блокирует её, сохраняя client→Tor transport. Адреса из benchmark range
`198.18.0.0/24` используются только внутри disconnected lab без default route.

```text
sudo tests/integration/local-lab/setup.sh preflight
sudo tests/integration/local-lab/setup.sh up
sudo ip netns exec orqa-fixture <controlled-dns-and-tcp-fixture>
sudo ip netns exec orqa-tor <mock-tor-or-private-testnet>
sudo ip netns exec orqa-gateway <gateway-under-test>
sudo tshark -i orqa-h0 -w physical.pcapng
sudo ip netns exec orqa-client <client-and-scenario-runner>
sudo tests/integration/local-lab/setup.sh down
```

Service commands поступают из immutable build artifacts; script не содержит
clearnet fallback и не меняет production firewall. При существующем `orqa-*`
объекте setup отказывается продолжать. `down` удаляет только фиксированные lab
names. Windows/macOS/iOS/Android выполняют тот же topology в disposable VM/device
lab через platform adapters.
