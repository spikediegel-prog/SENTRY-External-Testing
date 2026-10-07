# Trusted hardware enrollment contract — Proposed

This is an integration specification, not an implemented hardware enrollment ceremony. The optional [cryptographic verifier](cryptographic-verifier.md) can validate pinned signed enrollment records and a narrow evidence profile; it requires an independently trusted issuer and never discovers trust roots from device evidence. `RejectAllVerifier` remains the default and remains closed, including refusal to supply randomness.

## Records approved outside the intelligence and worker paths

An independently administered enrollment authority must authenticate the operator, validate the device, and sign/version these immutable records:

| Record | Required contents and validation |
|---|---|
| Identity | Public-key fingerprint over a specified canonical representation; algorithm and parameters; verified key attributes and protected authorization policy. A handle or provider label alone is insufficient. |
| Hardware provenance | Accepted hardware trust roots and endorsement identity policy; certificate validation where required; credential activation or equivalent proof binding the enrolled attestation key to the accepted TPM. A platform certificate is optional according to enrollment policy. Explicitly distinguish emulators. |
| Attestation key | Pinned public area, TPM Name, expected restricted signing attributes, algorithm, and its validated provenance binding. Bind the separate identity-signing key through certification or another independently validated enrollment procedure. |
| Boot profile | Profile version, platform-specific PCR bank/selection, approved measurement/event-log policy, Secure Boot expectations where applicable, and update authority. A matching digest alone does not establish runtime integrity. |
| Authorization | Existing policy identifier, enrolled identity and profile references, allowed renewal/recovery use, revocation status and validity. This record cannot add actions, resources, permits or privileged scope. |

The controller's current key/profile strings are references to such future records; string equality does not implement enrollment. Models, workers, learned countermeasures, emergency routing, and incident recovery cannot approve or rewrite these records.

## Verification before success

1. Obtain a new controller-session identifier and per-exchange nonce from a trusted CSPRNG. Validate generator failures; never accept worker/provider-selected randomness. Require freshness across restarts and VM snapshots; if that cannot be assured, use an independently protected durable epoch before enabling real approval.
2. Retrieve authenticated, non-revoked enrollment records; do not derive trust pins from the submitted proof.
3. Reconstruct the exact V2 challenge bytes, including session, sequence, nonce, instance, generation and policy. Verify the identity signature over those bytes and quote qualification over their SHA-256 digest. Envelope comparisons and booleans are not cryptographic verification.
4. Verify the quote signature against the enrolled AK, its structures/algorithm/PCR digest, the approved profile and applicable event-log replay. Verify the identity key's binding to the enrolled hardware. Reject unknown algorithms, missing fields and unsupported evidence.
5. Return trusted verification results only after every required check succeeds. The controller still applies its own lease, generation, scope and incident-hold rules.

The Linux collection helper supplies multiple files. The optional verifier executable now packages bounded snapshots into a strict `QuoteBundle`; encoding is not verification. Windows quote collection remains Proposed. Use official quote verification and credential activation guidance as implementation inputs, not as substitutes for the enrollment policy.

## Restart, updates and availability

V2 uses a fresh random session identifier plus a monotonically increasing sequence. There is no durable replay ledger. A fresh session prevents identical challenges across restarts only if the trusted generator actually provides fresh randomness and the verifier checks full binding. Repeating the complete session/challenge after process or VM rollback remains an unsupported condition; physical TPM clocks alone are not a substitute for binding.

Replacement keys, motherboards, firmware and profile updates require the same independent approval path, with audit evidence and revocation of superseded records. No automatic downgrade is permitted. Preserve incident holds; a new attestation does not release them.

The wrapper maintains one expiring exchange and rate-limits issuance to one per 100 ms. It has no 128-exchange lifetime ceiling. This bounds retained exchange state, not total workload or verifier runtime. Sequence overflow revokes authority. The optional child-process verifier now enforces a bounded protocol and decision deadline and terminates/reaps its supplied child on failure. This is process separation under a healthy OS, not a sandbox or hard real-time guarantee under host failure. An independently privileged watchdog and OS-enforced process-tree limits remain Proposed; arbitrary inline verification and randomness callbacks can still stall. Ordinary lease checks prevent later worker execution after expiry, but do not cancel a blocked callback or provide production actuator isolation.

## Evidence requirements

Future deployment evidence must record enrollment/profile versions, verifier implementation version, challenge hash, decision/reason, lease/generation transition, and reconciliation outcome without logging private keys or sensitive raw measurements by default. Protected durable evidence storage and authenticated transport are separate unfinished native integrations. Current tests exercise in-memory reconciliation only.

## Sources

- [Official quote verification](https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_checkquote.1/)
- [Official credential activation](https://tpm2-tools.readthedocs.io/en/stable/man/tpm2_activatecredential.1/)

**Verified:** finite mock-verifier tests after a passing identified run. **Recorded:** this contract exists. **Inferred:** independently enforced enrollment/freshness reduces particular replay and impersonation opportunities. **Recorded/Verified within named synthetic tests:** opt-in OS randomness, signed-record/cryptographic checks and child-process deadline handling. **Proposed:** actual hardware enrollment, general profiles and an independent OS sandbox/watchdog. **Unknown:** physical TPM behavior, snapshot resilience and host-compromise resistance.
