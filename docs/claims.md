# Claim register

| Claim | Classification | Evidence / limit |
|---|---|---|
| Native core rejects expanded scopes, reused permits, nonzero uncertainty and former workers | Verified on platforms with passing named tests | Rust integration tests; identified commit/toolchain |
| Logical authority expires on integrity or lease failure | Verified in local fixtures | No real hardware attestation or independent watchdog |
| Clean recovery preserves access holds | Verified in local fixtures | No durable cross-process restoration |
| Incident-specific simulated health is required before release | Verified in local fixtures | No independent production health sensor |
| Eight concurrent attempts cannot multiply a one-use grant | Verified in the named concurrency test | No throughput or fairness claim |
| Worker API cannot grant or edit generation through safe Rust public fields | Verified compile-fail checks | Not protection against host compromise |
| Worker protocol matches the JavaScript reference for the shared corpus | Verified after differential script passes | 17 cases only, not complete parity |
| Native records are retained in bounded memory during a run | Recorded | Neither authenticated nor durable |
| Linux and Windows builds are available | Verified only after each platform's CI passes | Local Windows validation alone cannot establish Linux behavior |
| Dependency-free Rust core reduces dependency surface | Inferred | No independent audit |
| Protected OS key stores, installers/services, typed integration tooling and isolated host bridge | Proposed | Roadmap only |
| Reliable attack detection, production workload resistance, real exfiltration/poisoning coverage, sandbox escape resistance | Unknown | No production evidence |

The JavaScript snapshot contains additional experimental learning and Guardian capabilities. It retains its own claims and known misses/false positives. Those are not automatically inherited by the Rust port.

## Optional hardware identity

The [TPM identity foundation](hardware-identity.md) has 24 **Verified** mock-verifier tests for challenge binding, replay, expiry, hardware/profile requirements, software-downgrade refusal and capability revocation. Helper syntax checks do not establish physical TPM correctness. Windows/Linux key/signature/quote metadata is **Recorded** when collected; real hardware behavior is **Unknown** until exercised. The optional cryptographic/process verifier is implemented and tested against synthetic evidence; real enrollment and protected evidence-key sealing remain **Proposed**. The default verifier rejects all proofs.

The V2 hardware hardening tests additionally cover repeated nonces within one session, fresh-session restart replay and relabelled envelopes under a message-binding fixture, issuance throttling/resumption, abandoned exchange expiry, more than 128 exchanges, entropy failure/zero bytes, and delayed verifier success. These are finite simulations, not cryptographic proofs. Fresh session randomness across restarts is a trusted integration requirement; persistent epochs and actual hardware enrollment remain Proposed. Optional OS randomness and child-process deadline handling are now implemented, with the trust/host limits in the cryptographic verifier documentation. See [enrollment contract](hardware-enrollment.md).

## Optional cryptographic/process verification

Thirty finite synthetic assertions verify OS random-source calls, real RSA/SHA-256 checks on synthetic identity/quote/enrollment signatures, challenge binding, PCR/event-log checks, strict schemas, record pins/expiry and child crash/output/timeout behavior. Accepted hardware provenance is delegated to independently signed enrollment assertions; EK validation/credential activation is not implemented here. No physical hardware was used. Process separation is not an OS sandbox or a hard real-time guarantee under host compromise. See [cryptographic verifier](cryptographic-verifier.md).
