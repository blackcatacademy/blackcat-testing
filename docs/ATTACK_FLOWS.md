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

### Emergency stop

- Paused controller must hard-fail (no warn bypass).

