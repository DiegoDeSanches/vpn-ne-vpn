# client-core network API

## Boundary

`PacketProcessor::process` accepts one complete bounded IP packet,
`PlatformMetadata`, an optional already-evaluated `ProtectedRoute`, and the current
`ClientConnectionState`. It returns only explicit `EngineAction` values:

- open, write or close a protected stream;
- resolve DNS through the protected DNS boundary;
- inject a synthetic packet into TUN;
- block locally;
- record a closed-schema local diagnostic.

Neither `packet-engine` nor `client-core` owns a direct socket or a system DNS
resolver. `ConnectionDispatcher` can reach the data plane only through the
supplied `GatewayConnector` and an already-established anonymous session.

## TCP ownership and flow control

The packet engine owns the local IPv4 TCP state. `ConnectionDispatcher` owns the
corresponding ordered protected stream.

- A SYN allocates a bounded flow and starts a protected open deadline.
- SYN-ACK is delayed until `GatewayConnector::open_tcp` succeeds.
- Application payload is charged to `queued_to_gateway`; its cumulative ACK is
  emitted only after the protected write and flush succeed.
- Protected payload is charged to `queued_to_application` and retained until the
  application acknowledges it. At most one bounded segment is outstanding, so
  `protected_read_capacity` returns zero while local flow-control credit is used.
- `tick` retransmits the retained segment on a fixed interval and resets the flow
  after `max_retransmissions` or the idle deadline.
- Out-of-order payload is not buffered. The current ACK is repeated and the local
  OS TCP stack is expected to retransmit.

RST closes both sides immediately. FIN is directional: remote EOF does not close
the local write half, and a local FIN does not stop protected reads. Full cleanup
occurs after both halves close, or after reset, timeout, cancellation or shutdown.
The shared transport lacks write-half shutdown until CP-0002 is accepted; the
dispatcher therefore forbids later writes locally but retains the stream for reads.

## DNS

UDP and TCP destination port 53 are terminated locally only while the protected
path state is active. A/AAAA queries use the bounded identity-scoped synthetic map;
other record types use `GatewayConnector::exchange_dns`. ECS, unsupported opcodes,
truncated queries, malformed responses and mismatched response questions fail
closed. No code path calls the operating-system resolver.

## Cancellation and shutdown

The runtime obtains `ClientCore::cancellation_handle` before starting work. Calling
`cancel` wakes and drops the current pending gateway operation without acquiring
the core lock. The runtime then calls `shutdown`, which stops new flows, emits
local resets, clears pending DNS, and closes all protected streams. The packet
tunnel is closed only after these steps; the outer orchestrator keeps the kill
switch engaged until teardown is independently verified.

`suspend` freezes monotonic deadlines. `resume` either shifts them by the sleep
duration after an independent protected-path health proof, or resets every flow.

## Integration assumptions

- Platform split tunneling excludes bypassed applications before packets enter TUN.
- The runtime schedules `tick` and cancels an in-flight dispatcher future at the
  same connection/shutdown deadline.
- The gateway protocol provides ordered bounded streams and hostname forwarding.
- Production promotion requires OS packet-capture leak tests and reference-stack
  differential/soak testing; this MVP adapter remains experimental until then.
