# Security backlog (ideas + next hardening steps)

This document collects **defense-in-depth** ideas for the minimal BlackCat kernel stack:

- `blackcat-kernel-contracts` (on-chain trust root)
- `blackcat-core` (TrustKernel + guards)
- `blackcat-config` (runtime config + posture checks)
- `blackcat-testing` (production-like harness + attack flows)

Goal: capture what we should add next, why it matters, and what the trade-offs are.

---

## Status legend

- ✅ implemented
- 🧪 demo/harness only
- 🧩 planned / needs design
- ⚠️ hard trade-offs / platform dependent

---

## On-chain (kernel contracts)

✅ **InstanceController**: integrity root + policy hash + pause/upgrade + attestations.

🧩 **Attestation taxonomy**: formalize key namespaces and versioning rules (e.g. `blackcat.*.vN`) + publish in a spec repo.

🧩 **Incident signal semantics**: define stable event/attestation patterns for:
- “trust OK check-in” (positive health)
- “incident hash” (negative health / anomaly)
- “maintenance window” (planned downtime without panic)

⚠️ **Spam economics**: on-chain “check-ins” can be abused if an attacker can enqueue tx intents. Mitigations:
- keep check-ins optional (low frequency),
- enforce allowlists in relayers,
- use “event-only” mode (no storage writes) where possible,
- rate-limit off-chain enqueue and relayer broadcasts.

---

## Off-chain (TrustKernel + guards)

✅ **Fail-closed in prod** via strict policy hashes.

✅ **Guards are locked** (KeyManager + DB read/write + PDO bypass guard).

✅ **Policy v4** (optional) hardens provenance via on-chain commitments:
- runtime config canonical hash
- `composer.lock` canonical hash
- PHP fingerprint (v2; multi-SAPI stable)
- image digest (sha256)

🧩 **Keyless crypto boundary (next big win)**  
Instead of exporting raw key material to the web runtime (`get_all_keys`), move to:
- `encrypt/decrypt/hmac` operations inside the agent,
- return only ciphertext / tags / derived outputs,
- never return raw keys at all.

Trade-offs:
- larger protocol surface (more ops to audit),
- more CPU in the agent,
- needs careful API design to avoid “oracle” misuse.

🧩 **Request context binding** (optional): bind sensitive operations to a short-lived “trust session” token minted by the kernel
after a successful on-chain verification. The agent then requires that token for actions.

Trade-offs:
- additional complexity and state,
- must avoid introducing “bypass tokens” that outlive trust.

---

## Secrets boundary (secrets-agent)

✅ **Allowlist basenames + exact lengths** (reduces exfil surface).

✅ **TrustKernel enforcement inside the agent** (read/write gating).

🧪 **Peer identity enforcement**: ensure only the intended runtime user can call the UNIX socket
(Linux `SO_PEERCRED`), otherwise deny.

🧩 **Rate limiting**: token bucket per peer UID/GID for key/DB requests to reduce “rapid exfil” after RCE.

🧩 **Audit sink**: append-only local audit log (no secret material) with rotation and secure perms.

⚠️ **Platform limits**:
- UNIX sockets and peer credentials are Linux-centric.
- for “compat” environments, you may need to run without an agent (and accept higher RCE → secret exfil risk).

---

## Runtime config (blackcat-config)

✅ **Secure file policy checks** (no symlink, safe perms).

✅ **Doctor posture report** for recommended settings.

🧩 **Auto-recommend best config location** (best-effort choose the most secure writable directory per platform):
- Linux: prefer `/etc/blackcat/` + root-owned, group-readable
- containers: mount a dedicated volume
- Windows: avoid NTFS-on-/mnt/c for POSIX perms; prefer WSL FS or a docker volume

⚠️ **Strong guarantees require OS support**:
the kernel can detect tamper, but cannot “force” secure perms everywhere (e.g. some shared hosting).

---

## Deployment hardening (platform dependent)

✅ **Read-only rootfs** option in docker harness (`docker-compose.hardened-fs.yml`).

⚠️ **Egress allowlist**: restrict outbound traffic to RPC endpoints only (reduce SSRF/exfil).
Implementation depends on platform (iptables / cloud SG / k8s NetworkPolicy).

⚠️ **MAC/LSM**: AppArmor / SELinux profiles to restrict filesystem access further.

🧩 **Process separation** (best): run secrets-agent + runner in separate containers/VMs with minimal privileges.

---

## Testing strategy (blackcat-testing)

✅ **Attack flows** in unit/integration suites.

🧩 **Soak tests** on live chain (hours) with:
- steady traffic
- scheduled tamper
- scheduled RPC outage / byzantine endpoint
- verify fail-closed behavior and recovery

🧩 **Adversarial “operator mistakes” suite**:
- wrong RPC endpoint scheme
- wrong controller address
- stale config file
- unlocked attestation keys
- “forgotten FTP” simulated as unexpected file writes

---

## What we are adding next (near-term)

Planned in the next iterations:

1) ✅ secrets-agent peer credential allowlist (deny unexpected callers)
2) ✅ TxOutbox directory permission hardening (refuse world-writable outbox)
3) 🧩 relayer + tx-outbox safety improvements (rate limiting, receipts, allowlists)
