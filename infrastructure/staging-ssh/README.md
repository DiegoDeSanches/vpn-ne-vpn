# Experimental staging delivery over SSH

This adapter exists only for a single staging host. It does not supersede
ADR-0012, the production image-replacement controller, or the release gates.
Public SSH and mutable Docker hosts remain forbidden for OnionRoute production.

The deployed stack contains PostgreSQL, the directory service, its Tor v3 Onion
Service, the privacy-minimized health collector, the loopback administrator API,
and the revocation service. The signing service and gateway data plane are not
deployed because their production KMS/token adapters and release evidence are not
ready.

## Trust boundary

Backend CI builds one image tagged with the full commit SHA after every required
gate, publishes it to GHCR, and records its immutable registry digest on the
commit. The deploy workflow accepts only that CI-promoted digest. It signs the
bundle manifest with a second Ed25519 key before streaming it over SSH.

The server host key must be pinned out-of-band. The dedicated SSH key is installed
on the root account with OpenSSH restrict and a forced root-owned controller
command, so it cannot request an interactive shell, forwarding, a PTY, or an
arbitrary command. The server owns the separate bundle-signing public key and
rejects a validly checksummed but unsigned bundle. Compromise of the SSH delivery
key alone therefore cannot authorize attacker-controlled Compose or image input.

Runtime credentials never enter GitHub. Five distinct PostgreSQL password files
(one superuser used only by migration and one least-privilege login per service)
are generated under `/etc/onionroute-staging/secrets` on the server. The controller
serializes deploys with flock, validates compressed and expanded size limits,
checksums and signatures, rejects signed workflow-run replay/downgrade, runs the
schema gate, proves Tor bootstrap and Onion reachability, and returns to the
previous immutable local image ID if a service fails.

## One-time server bootstrap

Prerequisites are Ubuntu or Debian with OpenSSH, Docker Engine, Docker Compose v2,
flock, and OpenSSL. First obtain console/root access through the provider. Verify
the SSH host fingerprint in that console; do not populate known_hosts from an
unverified ssh-keyscan result.

Generate two distinct Ed25519 keypairs: one for the restricted SSH connection and
one for bundle signing. Copy both public keys plus these two repository files to a
temporary root-only directory, then run:

    sudo bash bootstrap-server.sh deploy-key.pub bundle-signing-key.pub onionroute-staging-deploy

Delete the temporary public-key/controller copies after installation. Do not
change the forced authorized_keys entry into an unrestricted Docker or shell key.
Re-running bootstrap atomically replaces only the marked OnionRoute forced-key
block and preserves unrelated root keys; it does not accumulate obsolete deploy
keys.

## GitHub environment

Create a protected environment named staging, restrict it to gateway/multihop,
require a reviewer where the GitHub plan supports it, and add five environment
secrets:

- STAGING_SSH_HOST
- STAGING_SSH_PORT
- STAGING_SSH_PRIVATE_KEY
- STAGING_SSH_KNOWN_HOSTS
- STAGING_BUNDLE_SIGNING_PRIVATE_KEY

STAGING_SSH_KNOWN_HOSTS must contain the provider-console-verified Ed25519 host
key, including the bracketed host and port form when a non-default port is used.
The two private keys must be distinct. The workflow is manual and requires the
exact confirmation text deploy-staging. It additionally refuses a revision without
a successful Backend CI push run and its matching immutable GHCR digest.

## Rollback and limitations

Binary rollback reuses the previous content-addressed local image ID. The previous
image is checked before migration, and custom images use `pull_policy: never` so a
rollback cannot silently fetch an unsigned replacement. Database migrations are
expand-only and are never rolled back automatically. Old release directories and
images are retained so an operator can recover; retention is an explicit follow-up
because automatic prune could delete the only rollback target.

This staging stack exposes only loopback ports 55432, 18080-18084, and Tor SOCKS/
Control ports 29050-29051. Directory traffic enters through its generated Tor v3
Onion Service. Health/admin/revocation ingresses still need reviewed mTLS proxies
before any shared or production use.
