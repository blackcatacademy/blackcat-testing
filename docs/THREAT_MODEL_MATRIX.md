# Threat Model Matrix (v1)

Scope: the **minimal BlackCat security stack** as exercised by `blackcat-testing` (Docker harness + optional live chain):

- `blackcat-core` (TrustKernel, integrity verification, runtime guards)
- `blackcat-config` (runtime config loading + permission checks + runtime posture "doctor")
- `blackcat-kernel-contracts` (InstanceController + attestations + incidents)

This matrix is intentionally short and practical: what is **blocked**, what is **detected/mitigated**, and what is **out of scope**.

## Assumptions

- The attacker may control HTTP traffic and can attempt filesystem/config tamper (FTP/CI artifacts).
- The attacker may obtain **RCE** in the web runtime (worst case), but **does not** have OS root/hypervisor control.
- Database is **not** directly reachable from the internet (recommended: localhost-only network policy, ideally separate host/VM).
- For strict mode, at least `rpc_quorum` RPC endpoints are honest/available (Byzantine tolerance is quorum-limited).

## Matrix

Legend:
- **Blocked** = strict policy prevents sensitive operations (write/decrypt/crypto) or fails closed.
- **Detected/Mitigated** = detected and can trigger fail-closed, incidents, pause flows, or hardening guidance.
- **Out of scope** = not solvable purely in userland PHP + EVM; requires OS/cloud controls.

| Threat / attack class | Status | Primary mechanism(s) | Residual risk / notes |
|---|---|---|---|
| Filesystem tamper (unexpected file / modified code) | Blocked | On-chain integrity root + local re-computation; fail-closed on mismatch; optional filesystem threat scan → incident | An attacker can still **DoS/deface**, but sensitive operations should remain blocked in strict policy. |
| Runtime config tamper (redirect RPC, weaken policy) | Blocked | Runtime config attestation (policy v3+), locked attestation keys, config permission checks | If attacker can both tamper config **and** satisfy on-chain attestation (keys compromised), trust model is broken. |
| Supply-chain tamper (vendor/composer) | Detected/Mitigated | Integrity root + optional on-chain commitments (e.g., `composer.lock` hash) | Requires disciplined upgrade flow; dev can warn, prod fails closed when enabled. |
| Byzantine RPC (one endpoint lies) | Blocked | Multi-endpoint quorum; fail-closed when quorum disagree | If **quorum** of endpoints collude, on-chain truth can be spoofed off-chain. Mitigate by using independent providers + higher quorum. |
| RPC outage / partition | Detected/Mitigated | `max_stale_sec` stale window, writes blocked; optional watcher can `pauseIfStale()` | Outage can still cause availability loss; can be minimized with multiple RPCs + local caching + clear incident reporting. |
| Unauthorized on-chain actions (upgrade/attestation/incident without authority) | Blocked | Contract access control; EIP-712 authorized flows with nonces; locked keys | Key compromise remains the critical risk; recommend multisig/hardware wallets. |
| Replay of authorized actions | Blocked | Nonces on-chain (e.g., `reporterNonce`, `incidentNonce`) | Requires correct nonce handling; tested by contract test suite. |
| Host-header / fake domain routing | Blocked (when enabled) | On-chain attestation for `http.allowed_hosts` + enforcement in HttpKernel | Requires correct config + enforcement; still recommend reverse-proxy allowlists. |
| Raw PDO bypass / direct DB exfil via app code | Blocked (when enabled) | DB creds are not exposed to web runtime (boundary agent issues RO/RW credentials based on TrustKernel) | If platform cannot run an agent boundary, DB creds may be visible in runtime and RCE can steal them. |
| Key exfiltration (read raw key files) | Blocked (when enabled) | Key files owned by boundary user; web runtime denied; keyless crypto agent returns only results (never raw keys) | If keys are readable by the same user that executes the app, RCE can exfiltrate them. |
| Secrets-agent abuse (brute force / spam requests) | Detected/Mitigated | Allowlist basenames, enforce key sizes, rate-limit; audit log (counts only) | If attacker fully controls the runtime user, they can still abuse allowed ops within policy. |
| PHP runtime misconfiguration (dangerous ini posture) | Detected/Mitigated | RuntimeDoctor + hardening recommendations; prod bootstrap gate can fail-closed on critical issues | Shared hosting often cannot satisfy all hardening knobs; document downgrade and compensating controls. |
| RCE in the web runtime | Detected/Mitigated | Reduce secret visibility (agent boundaries), strict TrustKernel gates, integrity verification, tx-outbox incidents, optional watcher pause | RCE can still **DoS**, attempt lateral movement, or exfiltrate anything already visible to the process. OS isolation is required for full containment. |
| OS root compromise / hypervisor compromise | Out of scope | N/A (must be handled by OS/cloud) | Use SELinux/AppArmor, read-only FS, separate users, network policy, HSM/KMS, external watcher host. |
| Physical access / supply-chain of host machine | Out of scope | N/A | Requires operational security and hardware trust. |
| DDoS (network-level) | Out of scope | N/A | Needs CDN/WAF/rate limiting at infra layer. |

## Practical takeaway

For **production (strict)**, the goal is:
- prevent **silent** tamper and secret exfiltration,
- fail-closed on integrity/trust breaks,
- emit incidents that can be acted upon by external watchers/ops.

For **dev/warn**, the goal is:
- stay usable, but be *loud* about anything that would be a production failure.

