# Mobile battery and bootstrap benchmark

Status: harness specification complete; device measurements are **not available
in this Windows workspace** and no numbers are fabricated. A release candidate
is blocked until the table below is populated from physical devices.

## Matrix

Run three devices per platform: oldest supported, median installed base and
current flagship. Test healthy Wi-Fi, weak Wi-Fi, LTE/5G, constrained/low-data,
battery saver and censored/bridge-required network. Use a conditioned battery at
20–80%, fixed brightness, fixed thermal starting state and airplane-reset between
runs. Repeat at least 10 cold and 30 warm samples.

## Workloads

| ID | Duration | Workload | Record |
|---|---:|---|---|
| B-01 | 15 min | TUN active, no app traffic | energy, CPU, wakeups, radio time |
| B-02 | 15 min | 1 DNS + short TCP flow/min | same + bytes/flow |
| B-03 | 15 min | sustained 5 Mbit/s TCP | energy, CPU, throughput, memory |
| B-04 | 30 min | screen off/device sleep | wakeups, reconnects, leaks |
| B-05 | 10 min | Wi-Fi/cellular handoff every 60 s | reconnect energy, downtime |
| B-06 | 10 runs | cold Tor bootstrap | p50/p95/p99 time + energy |
| B-07 | 30 runs | warm cached bootstrap | p50/p95/p99 time + energy |
| B-08 | 15 min | soft rotation every 5 min | dual-route peak RSS + energy |
| B-09 | 15 min | unavailable gateway/backoff | wakeups and radio churn |

Tor readiness is the structured `CIRCUIT_ESTABLISHED`/100% bootstrap event plus a
healthy onion/gateway session, not merely a timer. Record bootstrap phase tags so
network reachability and directory/circuit costs can be separated.

## Android collection

Use Android Studio Power Profiler or Macrobenchmark power metrics/system tracing.
Battery Historian is no longer actively maintained; Android recommends the newer
tools, although `dumpsys batterystats` remains useful supplementary evidence:
[Android power analysis](https://developer.android.com/topic/performance/power/battery-historian).

For every run also collect:

```text
adb shell dumpsys batterystats --reset
adb shell dumpsys deviceidle
adb shell dumpsys connectivity
adb shell dumpsys batterystats org.onionroute.mobile
adb shell dumpsys meminfo org.onionroute.mobile:tunnel
```

Do not acquire a permanent wake lock. Android warns that wake locks can quickly
drain battery and should be used only when no lighter mechanism exists:
[keeping a device awake](https://developer.android.com/develop/background-work/background-tasks/awake).

## iOS collection

Use Xcode Energy Impact/Organizer and Instruments Power Profiler on iOS 26+
devices. Apple recommends Xcode, MetricKit and Instruments and exposes CPU,
network and cellular-condition metrics:
[analyzing battery use](https://developer.apple.com/documentation/xcode/analyzing-your-app-s-battery-use),
[Power Profiler](https://developer.apple.com/documentation/xcode/measuring-your-app-s-power-use-with-power-profiler).

Record extension RSS separately from the containing app and capture jetsam logs.
Test disconnected baselines in the same conditions. Xcode can keep a paired
device awake, so screen-off runs must use on-device Power Profiler recording.

## Provisional release gates

These are engineering starting points, not measured claims; product/performance
owners must approve or replace them before beta.

- No periodic reconnect loop faster than the bounded backoff policy while offline.
- Idle tunnel adds no deliberate wake lock and no fixed-interval keepalive unless
  a measured gateway/Tor requirement justifies it.
- RSS stays below the internal 64 MiB Android / 48 MiB iOS budgets in steady state
  and below an approved transient cap during rotation.
- No monotonic handle, thread, FD, circuit or queue growth in a 24-hour soak.
- Battery saver may increase latency but never changes fail-closed routing.
- Bootstrap and handoff p95 budgets are set only after lab data; the UI must not
  publish an unmeasured “connects in N seconds” promise.

## Results template

| Platform/device/OS | Workload | n | Energy delta | CPU | Peak RSS | Bootstrap/handoff p50/p95/p99 | Pass |
|---|---|---:|---:|---:|---:|---|---|
| TBD | B-01 | 0 | TBD | TBD | TBD | n/a | blocked |

