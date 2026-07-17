# Linux packaging prototype

The package creates locked service user `onionroute` and desktop group
`onionroute-desktop`, installs the daemon root-owned/non-writable, loads the
nftables recovery table atomically, then enables the socket and service units.
The service starts before `network-pre.target`; unknown recovery state keeps the
default-drop table. `/dev/net/tun` and `CAP_NET_ADMIN` exist only in the systemd
service. The GTK process receives no capabilities.

The Unix `SOCK_SEQPACKET` is root-owned mode 0660. Daemon verifies `SO_PEERCRED`
and authorized group membership; GTK verifies UID 0 plus exact root-owned daemon
image. Polkit is limited to enrollment/removal and cannot be used to broaden the
runtime socket ACL. Secret Service entries are read through a reviewed daemon
adapter and never serialized to IPC or diagnostics.

Before shipping, distribution packages must integrate the base nftables policy
without flushing unrelated tables and test NetworkManager/systemd-networkd,
suspend/resume, reboot, daemon crash, package rollback and removal on every
supported distribution.

