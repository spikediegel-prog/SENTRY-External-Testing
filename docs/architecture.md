# Architecture and threat model

## What the Rust core enforces

The boot `Policy` controls bounded lease, intervention window, request ledger and permit capacity. Powers are fixed by typed action/resource pairs: read handbook, write scratch note, send to simulation inbox. Read is baseline; write/send require a supervisor-issued permit. The policy is copied into private core state and cannot be changed through a worker port.

`Supervisor` can recover, attest, grant within fixed scopes, cancel eligible escalation and release a hold after a newer generation and incident-specific simulated health check. Possession of that typed handle is the trust assumption. It does not authenticate an external human or hardware attestation. `Worker` can propose, record rejected protocol input, and request status. It cannot construct its own port, change generation, access the adapter, create a grant, or renew its own lease through that API.

The worker receives a new generation-bound port after recovery. The old port remains rejected. No text-based worker command is forwarded to supervisor methods. A compromised worker able only to send protocol requests cannot access those trusted fixture operations. Arbitrary code execution in the trusted host remains outside the demonstrated boundary.

## States and barriers

Core state starts at `RecoveryRequired`. Trusted fixture recovery enters `Normal`. Integrity failure, lease expiry or evidence/actuator failure revokes authority first, then records the progressive states `Degraded -> Quarantined -> SafeMode -> RecoveryRequired`. These are logical states, not proof of an OS process being isolated. Checks occur at API entry and after simulated execution; there is no independent watchdog process or cancellation of an already in-flight real operation.

Session state is available, held, or simulated isolated. An exact synthetic marker in a send proposal immediately holds the affected session, opens a fixed intervention window, and later marks it isolated. An eligible human fixture override cancels escalation but never releases access. Unrelated Bob activity and status continue subject to the fixed gate. Recovery preserves holds. Release needs a newer generation and a clean adapter check bound to the current incident, so a previous incident's check does not suffice.

The full five-layer progression (deterministic filtering, challenge, containment, isolation, authority) remains in the JavaScript reference. This Rust port concentrates on the authority gate, synthetic containment and intervention; it does not port the noise-analysis worker pool or build a new classifier. Intelligence can recommend through reference experiments, but there is no native learning model or promotion API.

## Evidence and reconciliation

Before simulated execution the core appends intent, consumes the one-use grant, checks its lease, executes, then compares observed session/action/resource/content with the request. Receipt mismatch, expired lease after adapter return, or evidence failure closes authority and holds affected access. A crash-after-effect test exercises an error returned by an adapter after it stored the simulated effect.

Native evidence is a bounded in-memory sequence of minimized event labels and request IDs. Content is kept only in the simulated adapter's in-memory effects. Neither component is persistent, encrypted, signed, externally anchored, or protected from memory compromise. Request IDs are attacker-controlled bounded labels and must not contain secrets. Evidence storage failure can prevent durable reconciliation; a closed gate is the only fail-closed property asserted. Authenticated/encrypted native persistence is future work; do not confuse it with the separate JavaScript journal implementation.

## External adversary model

The test adversary may send malformed or replayed worker lines, request unauthorized action/resource pairs, vary uncertainty, flood bounded ledgers, reuse permits, attempt supervisor commands, and retain an old worker port. Trusted fixtures may inject integrity failure, adapter mismatch, crash-after-effect, journal failure, false health checks, and time advance to exercise trusted-path failures.

The adversary does not have the supervisor handle, sink, adapter, OS administrator privileges, or native process memory. Supervisor identity spoofing, hardware attestation forgery, same-process arbitrary code execution, real sandbox escape, persistent recovery attacks, and endpoint-vendor compromise are **Unknown/Proposed** coverage. Compile-time API refusal is not runtime isolation. Rust memory safety does not prove security-policy correctness or eliminate denial of service.

All operations are local simulation. No hostile traffic, exploitation, endpoint isolation or credential revocation is sent to real systems.
