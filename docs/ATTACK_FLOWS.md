# Attack flows (offline)

This suite tries to model realistic attacker actions and infrastructure failures without requiring a live chain.

## Covered categories

### Integrity tamper

- Modify a file under the integrity root (hash mismatch).
- Add an unexpected file under the integrity root (strict/full mode).
- Symlink attempts (manifest build or verify should fail).

### Runtime config tamper (policy v3)

- Runtime config file is bound to an on-chain attestation (`runtime_config_commitment_*`).
- Any change to the config JSON should change canonical hash and be rejected in strict mode.

### RPC failures & quorum

- RPC outage after a previously-good state: allow **stale reads** for a short window (configured).
- RPC outage + local tamper: stale reads must be denied (integrity recheck).
- Strict mode requires `rpc_quorum >= 2` (and at least 2 endpoints) to reduce single-endpoint lies.

### Emergency stop

- Paused controller must hard-fail (no warn bypass).

### Request entry gating

- Every HTTP request enters via `BlackCat\Core\Kernel\HttpKernel` which boots the kernel and evaluates trust state.
- `/health` is an observer endpoint (allowed even when reads are denied) and must remain read-only.
- Trust evaluation is cached only within a single request (not across requests) to avoid stale-trust windows in long-lived workers.

### Forwarded-header spoofing (reverse proxy)

- Forwarding headers (`X-Forwarded-*`, `Forwarded`) must be rejected unless the request comes from a trusted proxy peer.
- If the peer is trusted, `X-Forwarded-Proto=https` can be honored to avoid HTTPS downgrade bugs behind proxies.

### Secrets boundary (prototype)

- Key files should not be readable by the web runtime user (prevents direct `file_get_contents()` bypass).
- When enabled, a privileged secrets agent can serve keys over a UNIX socket to allow crypto operations without exposing key files.
