# Linux GTK shell

The GTK process is unprivileged and opens only
`/run/onionroute/control-v1.sock`. It requires `SOCK_SEQPACKET`, verifies root
`SO_PEERCRED`, exact daemon executable path and non-writable root ownership before
the first protobuf frame, then negotiates IPC v1 and a bounded event window.

The system daemon owns `/dev/net/tun`, nftables, Secret Service access and the
shared Rust core. Polkit authorizes installation/enrollment operations only; it is
not consulted for ordinary connect/status requests from the authorized desktop
group. Closing GTK drops its local socket without sending `Disconnect`.

