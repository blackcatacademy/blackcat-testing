# Hardening recommendations (kernel stack demo)

This repo is a *testing harness*, but the same ideas apply to real deployments of `blackcat-core` + `blackcat-config`.

## Secrets boundary (recommended, but not always available)

The **strongest** practical protection against “RCE → instant DB/key exfiltration” is to keep secrets *out of the web
runtime*:
- do not expose DB DSN/user/pass to the web process (env/config),
- do not keep key material readable by the web process,
- release secrets only through a privileged local agent that enforces TrustKernel (`read_allowed`/`write_allowed`).

That is why the demo uses a root-owned **secrets-agent** over a UNIX socket.

Additional hardening in the demo:
- the agent enforces **peer credentials** (`SO_PEERCRED`) and allows only the web runtime UID (default: `www-data`)
  to call the socket. This reduces cross-user exfil if multiple users/processes exist on the same host.

Why this is not mandatory everywhere:
- Some platforms (shared hosting / locked-down PaaS / non-Linux) cannot run local agents, UNIX sockets, or multiple
  processes/users safely.

If you cannot run a secrets boundary:
- You still benefit from TrustKernel (policy + integrity + fail-closed behavior) and from HTTP/ini hardening.
- But you must assume: **if an attacker achieves arbitrary code execution in the web runtime, secrets in env/config can be stolen**.

Mitigations for “compat” environments (best-effort):
- keep DB on a separate host/private network (no public DB; allowlist only your app host),
- least-privilege DB users (consider separate read-only vs write roles),
- hardened PHP posture (disable dangerous functions, strict `open_basedir`, no URL fopen/include),
- read-only app filesystem + restrict writable dirs,
- remove/disable FTP immediately after deployment (treat it as a temporary installer transport).

## Filesystem isolation

Recommended baseline:
- container root filesystem: **read-only**
- writable mounts: only `/etc/blackcat` (runtime config, sockets) and `/var/lib/blackcat` (optional state/outboxes)
- tmpfs: `/tmp`, `/var/tmp`

Tx outbox note (optional, recommended):
- configure `trust.web3.tx_outbox_dir` (default demo path: `/var/lib/blackcat/tx-outbox`)
- permission model should allow the web/runner user to write without making the directory world-writable
  (example: `root:www-data 0770`)

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

Tip (practical):
- treat Web3 RPC as a dedicated “egress service” and route RPC traffic through a controlled gateway/proxy you own
  (so the allowlist is stable and auditable).

## MAC/LSM profiles (optional, strong)

When available, apply a mandatory access control profile:
- AppArmor or SELinux (Linux)
- restrict file reads to `/srv/blackcat` + `/etc/blackcat` and deny unexpected paths
- deny process execution syscalls where possible (many apps do not need them)

This is intentionally left as a platform-specific profile (not committed into the core repos).

### AppArmor example (starter skeleton)

This is only a starting point (you must adapt to your distro + web server model):

```text
#include <tunables/global>

profile blackcat-minimal-site flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
  #include <abstractions/nameservice>

  # Read-only app code
  /srv/blackcat/** r,

  # Runtime state (exactly defined)
  /etc/blackcat/** rw,
  /var/lib/blackcat/** rw,

  # Temporary dirs
  /tmp/** rw,
  /var/tmp/** rw,

  # Deny everything else by default
  deny /** wklx,
}
```

### SELinux note

Prefer a dedicated SELinux type for runtime state (`/etc/blackcat`, `/var/lib/blackcat`) and keep the application
root read-only. In Kubernetes, map this to an explicit SecurityContext + readOnlyRootFilesystem.

## Defense in depth

Even with TrustKernel:
- avoid co-locating secrets and untrusted write surfaces (FTP/SSH) when possible
- disable/remove FTP immediately after install
- keep `/etc/blackcat` root-owned and non-writable by the web runtime

## Optional: additional on-chain attestations (higher discipline)

The minimal kernel already binds:
- integrity root + policy hash (InstanceController snapshot),
- runtime config canonical hash (policy v3 attestation; recommended to lock).

You can harden further by committing additional attestations (bytes32) to the InstanceController and locking them:
- **composer.lock canonical hash** (`blackcat.composer.lock.canonical_sha256.v1`): detects dependency drift/tamper.
- **PHP fingerprint** (`blackcat.php.fingerprint.canonical_sha256.v2`): detects “silent runtime change” (PHP/ext versions).
- **image digest** (`blackcat.image.digest.sha256.v1`): detects container image swap (container platforms).

Tradeoff:
- Extremely strong provenance, but upgrades require discipline (you must update+lock attestations when changing runtime/deps/images).

Helpers:
- `blackcat-config/bin/config runtime:doctor` prints best-effort computed attestation keys/values (and warnings if missing).
- `blackcat-config/bin/config runtime:attestation:composer-lock`
- `blackcat-config/bin/config runtime:attestation:php-fingerprint`
- `blackcat-config/bin/config runtime:attestation:image-digest`
