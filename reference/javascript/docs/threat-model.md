# Threat model and Guardian negative proofs

## Assets and adversaries

Protect the policy envelope, lease conditions, instance capability, session credentials/routes, Intervention Window, control traffic, alert history and evidence. The tested adversary controls worker proposals/recommendations and attempts unauthorized lane messages, replay, identity spoofing and malformed inputs. Guardian also uses explicit trusted fixtures to inject known observations, integrity failures, time progression, journal corruption and recovery. Those fixtures are test privileges, not powers granted to Guardian by SENTRY.

Trusted observer compromise, supervisor/human key theft, malicious controller code, OS-user compromise and physical storage/host failure are not solved by the prototype. A forged **unsigned** observation fails; a compromised trusted observer can still misclassify traffic and trigger allowed mitigations. This distinction is essential.

## Executable adversarial matrix

| Guardian case | Attack or fault | Asserted negative proof |
|---|---|---|
| noise-hidden-compromise | 500 junk events around one credential misuse | Noise does not hide the intrusion in this finite stream; unrelated and control traffic remain intact |
| replay | Replay authenticated observer envelope | Stale sequence cannot repeat its effect |
| spoofed-telemetry-control | Invalid MAC; fake control label; hostile protected-session event | Cannot obtain trusted telemetry or protected status through labels |
| prompt-injection | Instruction text in learning input; attempted execute | Text does not become authority or executable instruction |
| policy-mutation | Worker tries changing powers/lease; unknown action | No policy mutation API; scope/action gate holds |
| forged-heartbeat-attestation | Worker heartbeat and invalid supervisor MAC | Cannot extend lease; deadline closes execution |
| alert-suppression | Worker attempts deleting alerts | No suppression API; alert persists in evidence |
| learning-poisoning | Repeated misleading recommendations | Policy digest and powers remain unchanged |
| alternate-execution-routes | Direct adapter/shell/restore/route commands | Only the checked controller path exists in this protocol |
| intervention-window | Forged cancellation, window extension, late override | Only authenticated in-window cancellation succeeds |
| uncertainty-and-emergency | High uncertainty, added emergency flag | Uncertainty narrows proposal actions; emergency flag cannot mint powers |
| self-containment-escape-recovery | Execute while quarantined, same-instance recovery, reuse old token | Failure severs execution; clean replacement does not reactivate old token |
| journal-tamper | Append unsigned evidence | Chain verification closes authority; corrupted journal cannot recover in place |
| attestation-integrity-and-replay | Replayed renewal; authenticated wrong digest | Replay cannot renew; integrity mismatch self-contains |
| evidence-reconciliation | Layered mitigation | Each successful consequential intent has exactly one corresponding reconciliation |
| malformed-and-oversized-input | Null body, oversized text, invalid uncertainty | Denied without accidentally invalidating the journal |
| worker-process-and-continuous-learning | Child worker proposals, learning, attempted supervisor command | Worker bridge always selects worker lane; learning produces recommendations only |
| mitigation-monotonicity | Reuse containment evidence after isolation; legitimate-looking traffic with revoked credential | Worker cannot downgrade isolation; revoked session routes to denied |
| session-signal-detection | Expected/unexpected device and valid/missing simulated proof | Raw signed signals derive legitimate, suspicious or misuse classification; ambiguity does not isolate |

`controller-failure.test.js` additionally injects a post-effect journal failure, checks idle wall-clock expiry without worker messages, and exercises evidence-capacity exhaustion. The injected journal fault is a trusted white-box test; it is not an attack method exposed to SENTRY.

`workload.test.js` exercises concurrent analysis, bounded admission and signal reserves, analysis process crash/timeout, resource-configuration bounds, signed control bypass, ordered observer commitment and dead-man expiry during a finite concurrent flood. Analysis workers hold no authority keys; their output is ignored for execution authorization. Application-level queue bounds do not constrain OS/IPC buffers or establish production DoS protection.

`learning.test.js` exercises CVE text as untrusted reference data, wrong record IDs and tampered snapshots, authenticated delta export, altered export/dataset/label/model signatures, campaign leakage, held-out-family separation, shadow inference and rejected model promotion/export attempts from intelligence. The first trained detector missed unfamiliar attack families and instruction-injection batches; signature checks and the authority gate remain independent. A teacher or trusted observer compromise can still supply incorrect signed data. Real key custody, label adjudication and model robustness remain outside this proof.

These assertions establish concrete counterexamples are rejected by this implementation. They are executable negative proofs over the modeled inputs, not exhaustive or formal proofs. Guardian does not perform real exploits, scan a network or run destructive actions.

## Unresolved failure modes and next proof boundaries

- **Proposed:** OS-level isolation for controller, worker, sandbox, key broker and recovery service; deny worker filesystem access to controller artifacts and external execution routes.
- **Proposed:** Actual signed integrity measurements bound to boot nonce, binary digest and measured policy; external short-lived actuator capabilities, revoked independently when the controller dies.
- **Proposed:** Host-level resource isolation, ingress/IPC buffer bounds, batched durable noise receipts and throughput benchmarks. Bounded analysis queues, signed control bypass and a signal reserve are implemented and tested locally; the finite workloads are not production DoS benchmarks.
- **Proposed:** Durable replay/generation state, key rotation, signed boot-policy distribution and protected external evidence anchors. Current HMAC-chain proof depends on trusted controller memory and test-run keys.
- **Proposed:** Clean controller replacement and forensic import that reconciles outstanding intents without restoring suspect executable state. No payload capture or execution cage exists yet.
- **Unknown:** Real-world attack detection recall/precision, safety of real session revocation, challenge usability, recovery under compromised host/storage, and preservation when every evidence destination fails.

Authority has no hot expansion path. New powers require a separately reviewed boot policy and clean trusted deployment; this prototype intentionally implements no governance deployment service.
