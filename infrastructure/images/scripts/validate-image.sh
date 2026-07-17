#!/bin/sh
set -eu

/usr/sbin/sshd -t
/usr/sbin/nft --check --file /etc/nftables.conf
/usr/sbin/apparmor_parser --replace /etc/apparmor.d/onionroute-role
/usr/bin/tor --verify-config -f /etc/tor/torrc
/usr/bin/systemd-analyze verify \
  /etc/systemd/system/onionroute-role.service \
  /etc/systemd/system/onionroute-bootstrap.service \
  /etc/systemd/system/onionroute-vault-agent.service \
  /etc/systemd/system/onionroute-tor-secret-agent.service \
  /etc/systemd/system/onionroute-node.target

test -L /opt/onionroute/current
test -x /usr/local/libexec/onionroute-verify-release
test -s /usr/share/onionroute/trust/release-signing.pub
test -s /usr/share/onionroute/trust/admin-ssh-ca.pub

if find /etc /opt /usr/local -xdev -type f \
  \( -name '*.key' -o -name '*.pem' -o -name '*.p12' -o -name '*root-signing*' \) \
  | grep -q .; then
  echo "private key material found in immutable image" >&2
  exit 1
fi

if grep -RIE '(BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|VAULT_TOKEN=|secret_id[[:space:]]*=)' \
  /etc/onionroute /opt/onionroute /usr/local/libexec 2>/dev/null; then
  echo "secret-like material found in immutable image" >&2
  exit 1
fi

systemctl disable --now ssh.socket 2>/dev/null || true
systemctl enable ssh.service
systemctl enable nftables.service onionroute-node.target
