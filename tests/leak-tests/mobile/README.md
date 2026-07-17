# Mobile leak test suite

The suite requires physical Android and iOS devices, a controlled Wi-Fi/cellular
lab (or shielded carrier simulator), packet capture on the access network, a Tor
test network and private gateways. It covers every requested handoff, lifecycle,
credential, failover and DNS/IPv6/QUIC scenario in `scenario-matrix.json`.

For each scenario/platform create:

```text
evidence/MLT-001-android/physical.pcapng
evidence/MLT-001-android/result.json
...
```

`result.json` contains the scenario ID, platform and boolean values for every
`required` assertion. Evidence producers must derive those booleans from OS route
snapshots, tunnel state, controlled destination logs and timestamps—not from the
app's own optimistic state alone.

Run:

```text
python tests/leak-tests/mobile/run_suite.py \
  --evidence /absolute/path/to/evidence \
  --policy /absolute/path/to/lab-policy.json
```

The policy allowlists only Tor relay/bridge endpoints and explicitly documented
platform-essential lab endpoints. `assert_no_leaks.py` fails on physical DNS,
UDP/443, any other IPv4/IPv6 destination, or supplied plaintext token/destination
markers. Keep captures bounded and rotate them between cases.

Platform conditions:

- Android: repeat with always-on+lockdown enabled and disabled. The release
  security claim uses lockdown evidence; document the non-lockdown gap.
- iOS: record Apple-excluded DHCP/captive/system traffic separately. Do not mark
  it as OnionRoute-protected or silently add it to a broad allowlist.
- Kill the UI and tunnel processes separately.
- For low memory, capture RSS/FD count before, during and after pressure.
- For invalid catalogs, include bad signature, rollback, expiry and oversize.
- For gateway failure, prove physical destinations stay limited to Tor even
  while old TCP flows fail and replacement selection occurs.

