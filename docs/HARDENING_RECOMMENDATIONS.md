# Hardening recommendations (kernel stack demo)

This repo is a *testing harness*, but the same ideas apply to real deployments of `blackcat-core` + `blackcat-config`.

## Filesystem isolation

Recommended baseline:
- container root filesystem: **read-only**
- writable mounts: only `/etc/blackcat` (runtime config, sockets) and `/var/lib/blackcat` (optional state/outboxes)
- tmpfs: `/tmp`, `/var/tmp`

Demo helper:
- `docker/minimal-prod/docker-compose.hardened-fs.yml`

## Network egress allowlist (recommended)

Strict deployments should restrict outbound traffic to reduce SSRF/data-exfil paths.

Allowlist egress to:
- your configured Web3 RPC endpoints (HTTPS)
- any required internal services (DB, cache) *only if the app must reach them*

Implementation depends on platform:
- host firewall (nftables/iptables, cloud security groups, etc.)
- container runtime policies (Kubernetes NetworkPolicy, CNI egress policies)

## MAC/LSM profiles (optional, strong)

When available, apply a mandatory access control profile:
- AppArmor or SELinux (Linux)
- restrict file reads to `/srv/blackcat` + `/etc/blackcat` and deny unexpected paths
- deny process execution syscalls where possible (many apps do not need them)

This is intentionally left as a platform-specific profile (not committed into the core repos).

## Defense in depth

Even with TrustKernel:
- avoid co-locating secrets and untrusted write surfaces (FTP/SSH) when possible
- disable/remove FTP immediately after install
- keep `/etc/blackcat` root-owned and non-writable by the web runtime
