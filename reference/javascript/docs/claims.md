# Claim register

All Verified claims are restricted to the local adapter and named test assertions. Reports classify individual runs and refer to retained evidence. No claim here means production readiness.

Containment-failure alert creation, targeted local access holds and denial of automatic release on acknowledgment/SENTRY instance recovery are locally Verified. Operator messages and receipts are Recorded. Real sacrificial capture, external delivery, durable whole-controller hold recovery and safe production access release remain Proposed/Unknown; see `operator-containment-alerts.md`.

The optional endpoint simulator is locally Verified for explicit host scope, collector authentication/replay rejection, suspicion-only ingestion, existing-window escalation, human cancellation, idempotent audit receipts and denial after authority loss. Defender/Falcon labels are Recorded fixture metadata. Credentialed vendor interoperability and real endpoint protection remain Proposed/Unknown; see `endpoint-integrations.md`.

**Product scope:** SENTRY does not replace traditional firewalls or endpoint security. Complementing those controls is the intended design; production interoperability remains Proposed. No claim of equivalent coverage, superior protection or safe removal of existing controls has been verified.

**Intended containment purpose — Proposed:** detect and contain exfiltration and poisoning attempts that pass conventional security controls. **Verified locally:** bounded responses to trusted simulated exfiltration events and the named synthetic poisoning-test assertions. **Recorded:** poisoning detection metrics and observed blind spots. **Unknown:** detection of real exfiltration, reliable recognition of real poisoning, and incremental coverage over conventional security products. No comparative bypass/detection study has been performed.

Attack-permutation generation, signed split checks, sample-ID separation and final-test-independent fitting are locally Verified. Same-test detector comparisons are Recorded for a finite synthetic population. Sequence-blind features and a wording-based feature collision are explicit negative proofs; general attack-permutation recognition remains Unknown. See `permutations.md`.

The protection/countermeasure additions are locally Verified for finite proposal development, ciphertext round trips, key/context/tamper rejection, ordered local transport and authority revalidation. Saved archive migration and candidate support/evaluation are Recorded. Hardening against a compromised same-user host and remote mutual TLS remain Proposed/Unknown; see `protection-countermeasures.md`. Candidate rules remain Proposed and require review, even when local trial assertions pass.

| Claim | Classification | Evidence or limit |
|---|---|---|
| Worker commands cannot mutate lease/policy or directly call adapter through the exposed protocol | Verified | policy-mutation, alternate-execution-routes, worker-process-and-continuous-learning |
| Intelligence and controller run in different processes | Verified | child-worker scenario and executable demo |
| Same-user process separation withstands arbitrary worker code execution or OS compromise | Unknown | No sandbox/ACL isolation established |
| Unsigned/replayed observations and attestations fail | Verified | replay, spoofed-telemetry-control, attestation tests |
| Model text and poisoned learning cannot create powers through the protocol | Verified | prompt-injection, learning-poisoning |
| Higher uncertainty narrows accepted proposal actions | Verified | uncertainty-and-emergency |
| One low-volume known misuse is contained among 500 noise events | Verified | noise-hidden-compromise; serial finite workload |
| Signed simulated device/session-proof signals derive classifications without an attack label | Verified | session-signal-detection, noise-hidden-compromise |
| An unexpected device and missing proof may indicate credential misuse | Inferred | Demonstration hypothesis; real-world diagnostic accuracy remains Unknown |
| General DoS resilience or intrusion recognition | Unknown | No real traffic, scheduling benchmark or detector evaluation |
| Analysis uses two processes with two threads each and preserves admitted observer order | Verified | workload tests |
| Queue bounds, signed signal reserve, control bypass, process failure and timeout keep authority unchanged in the local burst | Verified | workload tests, load demo |
| Multicore speedup or resistance to production-scale adversarial traffic | Unknown | Lightweight preflight and serialized evidence can dominate; no representative benchmark |
| Timed override is authenticated, case scoped and deadline checked | Verified | intervention-window |
| Loss of simulated attestation/lease removes worker execution capability | Verified | forged-heartbeat-attestation, self-containment tests, idle expiry test |
| Old worker capability remains invalid after clean simulated recovery | Verified | self-containment-escape-recovery |
| Worker containment cannot downgrade isolation; revoked credentials reject legitimate-looking traffic | Verified | mitigation-monotonicity |
| Integrity is independently measured from real binaries/hardware | Proposed | Fixture signs an integrity boolean |
| Successful mitigations have intent and observed reconciliation | Verified | evidence-reconciliation |
| A modeled failure after effect closes gate and captures reconciliation | Verified | controller-failure test with injected ENOSPC |
| All evidence survives total storage compromise/loss | Unknown | Emergency destination is local and may fail too |
| Journal tampering is detected during a live run | Verified | journal-tamper; HMAC, chain, in-memory head |
| Delta records reconstruct exact event data with authenticated encoded chain and periodic checkpoints | Verified | journal-delta tests; Guardian uses reconstructed receipts |
| Tamper-proof persistence across host compromise/restarts | Proposed | External anchors, key protection and replay persistence required |
| Challenge, sandbox, isolation and revoke change local modeled session state | Verified | Guardian and demo |
| Real payload containment, packet filtering or credential revocation | Proposed | No network or production adapters |
| Continuous bounded counters produce recommendations without authorization | Verified | worker-process-and-continuous-learning |
| Learning improves real-world detection | Unknown | A candidate model is trained/evaluated on synthetic batches only; unfamiliar-family coverage failed |
| Official CVE snapshots are versioned, checked and searchable as reference data | Verified | learning tests; importer run and bundled snapshots |
| Authenticated delta export minimizes raw identifiers and leaves labels unassigned | Verified | learning tests; live learning demo |
| Independent signed labels and campaign-separated synthetic data can train a frozen shadow model | Verified | learning tests and learning-demo |
| Shadow model screening or CVE text can authorize actions, training admission or promotion | Verified rejection | learning tests and existing worker command denylist |
| Candidate detects poisoning reliably across unfamiliar attack families | Unknown | First run missed all held-out rare-backdoor and camouflaged-poison batches |
| CVE-inspired simulations reproduce actual exploits | Unknown | Only generic local abstractions are implemented; no vulnerable software or exploits run |
| Pulpo supplied the separation-of-intelligence-and-authority design principle | Recorded | User-provided referenced discussion |
| Prototype inherits independently proven Pulpo implementation properties | Unknown | No source/verification artifact supplied |
| Absence of network adapters reduces immediate consequence of this lab | Inferred | Source inspection; only child-process IPC and local file writes |

Use `node --test tests/*.test.js` and `node src/guardian.js` to refresh the results. A FAIL supersedes the corresponding local Verified assertion until resolved. Proposed/Unknown rows must not be advertised as implemented features.

## Separate AI boundary exploration

See [scope and limitations](ai-boundary-exploration.md). The 27 tests in `tests/ai-boundary.test.js` provide **Verified** local assertions for action scoping, temporary permission expiry/reuse, memory quarantine, provenance withdrawal, intervention holds, recovery-bound health checks, former-worker capability rejection, authenticated replay, evidence failure, and failure of simulated actuator postconditions. Rehearsal misses/false alarms and operator snapshot data are **Recorded**. Live action integrations, isolated service wiring, real sensors and persistent recovery remain **Proposed**. Real-world poisoning/exfiltration coverage remains **Unknown**.
