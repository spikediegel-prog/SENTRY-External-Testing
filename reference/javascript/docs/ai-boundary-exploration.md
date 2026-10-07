# AI boundary exploration: all proposed directions in one local rehearsal

This extension implements finite local simulations for all eight brainstorm directions, plus temporary scoped permissions and learning provenance. It adds a separate trusted fixture, not a production integration or a new LLM. Existing controller interfaces and policies are unchanged.

## Run

Requires Node 22+. The tests use ephemeral encrypted journals and run without the Windows key vault:

```text
node --test tests/ai-boundary.test.js
```

The saved demonstration uses the existing Windows user-bound private key vault:

```text
node src/ai-boundary-demo.js
```

Open `operator-dashboard.html` afterward. It is a saved local snapshot with event filters, authority state, lease time, learning provenance, holds, and rehearsal results. It sends no requests and provides no execution controls. The current snapshot uses a fixture clock, not a live intervention countdown. Sensitive source text is excluded from the journal and dashboard. Run evidence is encrypted and ignored by Git; the generated dashboard exposes minimized simulation metadata and is shareable only after review.

## Architecture and authority

`AIBoundary` is the trusted simulation object. Its policy, signing keys, permission ledger, memory, and access holds use private fields. Worker access is restricted to status, action proposals, memory submission, and countermeasure recommendations. Signed human and supervisor lanes use separate signature domains and increasing sequence numbers. The fixture owns both lanes; it must never be supplied to an untrusted model.

The fixture executes in a single trusted Node process. Private fields and signed lanes demonstrate protocol boundaries; they do not resist arbitrary code execution inside that host. The existing SENTRY controller remains separately processed, but this new fixture is not yet connected to it. A production integration must move this gate and its keys into an independently isolated enforcement service, close alternate routes, use real attestation, and verify real actuator state.

Fixed boot policy defines sessions, action/resource pairs, baseline powers, and powers eligible for temporary grants. Grants are signed by the human lane, single-use, session/action/resource specific, generation bound, and clamped to the current lease. They cannot authorize an action absent from the boot policy. Grants are consumed before attempted execution, including failure. Pressure cannot change scopes. Nonzero uncertainty denies execution; malformed uncertainty is rejected.

## Capability map

| Direction | Implemented local proof | Boundary |
|---|---|---|
| Action checkpoint | Simulated read, write, and send proposals pass scope, lease, uncertainty, hold, and permit checks | No real file, message, browser, model, or tool action |
| Exfiltration tripwires | An exact synthetic marker in a send proposal holds that session; unresolved risk can escalate after a fixed intervention window | No semantic detector, encoded marker detection, or real exfiltration coverage |
| Memory quarantine | All text starts quarantined; finite injection phrases are flagged; exact content hash and allowed source are required for signed human review | Screening is incomplete; approval means a trusted human reviewed the hash, not that content is safe |
| Countermeasure rehearsal | Challenge/contain advisory candidates are evaluated against finite labeled phrases and legitimate examples | Candidate kind does not change the phrase detector; no synthesis of novel executable defenses or automatic installation |
| Incident replay | Encrypted HMAC chain verified against fixture-held head/count, with intents matched to receipts | Authenticated records are not independent truth; externally durable anchoring remains proposed |
| Containment health | Adapter-observed session/action/resource/content hash must match expected action; mismatch revokes authority and holds access | Adapter truth is simulated; an independent production sensor remains proposed |
| Recovery rehearsal | Expiry/integrity loss closes execution; signed clean replacement requires new identity and increasing generation | No hardware attestation, OS isolation, or durable cross-process hold restoration |
| Operator dashboard | Offline interactive event filters show state, evidence, provenance, holds and rehearsal limits | No live supervision or control buttons |
| Temporary permissions | Human-authorized one-use capabilities with scope and expiry | No AI-granted permissions; no authority beyond boot policy |
| Learning provenance | Candidates retain approved input hashes and source dependencies; source withdrawal retires affected memory/candidates | No trained LLM; no causal influence tracing through model weights |

## State and recovery

The new fixture has `RECOVERY_REQUIRED -> NORMAL -> RECOVERY_REQUIRED`. This simplified action-gate state does not replace the main controller's progressive self-containment states. Signed attestation maintains a monotonic-clock lease. Failure or expiry clears grants and pending escalation; execution is closed independently of alert availability.

Session holds survive clean-instance recovery in the same fixture. Worker capabilities are revoked on expiry and rotated during recovery; the former worker cannot use the replacement worker's capability. An operator may cancel eligible escalation during its window, but this leaves the hold active. Releasing a hold requires signed human authorization, a newer generation than the held incident, and a simulated clean check bound to the exact current hold hash. A previous incident's health check cannot release a new hold. Clean-instance recovery by itself never grants access.

Action intent is written before adapter entry; observed effect is reconciled afterward. A crash after entry produces an `outcome_unknown` receipt and revokes authority. If storage becomes unavailable, durable evidence cannot be guaranteed; execution remains closed. Journal corruption blocks writes/renewal/recovery on that journal while status remains available. A fresh independently trusted journal path is required for actual recovery from storage compromise.

Collections are bounded. Memory/permit/request exhaustion rejects admission rather than expanding authority. The append-only disk journal is not quota-managed. Verifying it on every request is deliberately conservative and grows in cost; no workload scalability or production DoS resistance is claimed. Trusted fixture time advance and health-marking helpers are test infrastructure, not model-accessible commands.

## Guardian negative proofs

`tests/ai-boundary.test.js` attacks alternate execution routes, forged approvals/attestation, scope expansion, permit expiry/reuse, request replay, uncertainty, tripwire bypass of permissions, intervention-window manipulation, unreviewed/poisoned/unknown-source memory, content-hash substitution, source withdrawal, failed postconditions, crash-after-effect, journal failure/truncation/modification, memory flooding, policy/snapshot mutation, stale recovery checks, and dashboard text injection. The existing Guardian suite continues covering the original controller threat categories.

The finite rehearsal intentionally contains a camouflaged attack missed by the detector and a quoted instruction that triggers a false alarm. These outcomes must be reported alongside successful tests.

## Claim classification

- **Verified:** Named assertions passed for these local protocol and simulation properties, including refused worker authority and recovery access holds.
- **Recorded:** Demo snapshot, action receipts, signed reviews, candidate dependencies, finite rehearsal counts, and dashboard fixture times.
- **Inferred:** Separation of model inputs from gate internals reduces accidental authority coupling when deployed according to this trust model.
- **Proposed:** Connection to the isolated controller; live integrations; independent actuator sensors; persistent recovery and externally anchored evidence; live operator controls; actual model training and countermeasure synthesis.
- **Unknown:** Unseen attack coverage, resistance to host compromise, production throughput, comprehensive poisoning detection, semantic exfiltration coverage, and containment escape prevention in a real environment.

This remains complementary to firewalls and endpoint security. Passing this test suite is not a universal security proof.
