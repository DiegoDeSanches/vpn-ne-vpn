#!/bin/sh
set -eu

case "${1:-}" in
  serve)
    runtime_dir="${2:?runtime directory is required}"
    umask 077
    mkdir -p "$runtime_dir/tls" "$runtime_dir/onion-service"
    chown debian-tor:debian-tor "$runtime_dir/onion-service"
    chmod 0700 "$runtime_dir/onion-service"
    if [ ! -s "$runtime_dir/capability-token" ]; then
      token_tmp="$runtime_dir/capability-token.tmp"
      openssl rand -hex 32 > "$token_tmp"
      mv "$token_tmp" "$runtime_dir/capability-token"
    fi
    if [ ! -s "$runtime_dir/tls/server.crt" ] || [ ! -s "$runtime_dir/tls/server.key" ]; then
      cert_tmp="$runtime_dir/tls/server.crt.tmp"
      key_tmp="$runtime_dir/tls/server.key.tmp"
      openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 2 \
        -subj "/CN=onionroute-local.invalid" \
        -addext "subjectAltName=DNS:onionroute-local.invalid" \
        -addext "basicConstraints=critical,CA:FALSE" \
        -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
        -addext "extendedKeyUsage=serverAuth" \
        -keyout "$key_tmp" -out "$cert_tmp" >/dev/null 2>&1
      mv "$key_tmp" "$runtime_dir/tls/server.key"
      mv "$cert_tmp" "$runtime_dir/tls/server.crt"
    fi
    exec /usr/local/bin/onionroute-local-prototype "$@"
    ;;
  tor-onion-service)
    until [ -d /runtime/onion-service ]; do sleep 1; done
    exec gosu debian-tor tor -f /etc/tor/torrc.onionroute-service
    ;;
  tor-client)
    exec gosu debian-tor tor -f /etc/tor/torrc.onionroute-client
    ;;
  origin|probe|probe-server|healthcheck)
    exec /usr/local/bin/onionroute-local-prototype "$@"
    ;;
  *)
    echo "expected serve, tor-onion-service, tor-client, origin, probe, probe-server, or healthcheck" >&2
    exit 64
    ;;
esac
