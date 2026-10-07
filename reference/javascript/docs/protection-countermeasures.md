# Countermeasure development and data protection

This addition implements finite countermeasure synthesis, encryption of new controller journals and emergency receipts, protected training artifacts, recoverable Windows user-bound key wrapping, and authenticated encryption for local child-process transport. It does not establish a production security boundary, a novel exploit defense, or remote TLS deployment.

## Countermeasures

The bounded background learner can develop up to three rules from teacher-signed, independently labeled simulated clean training batches. It groups observations by device mismatch and missing proof, requires at least eight supporting observations and 95% label agreement, then rejects rules that misclassify independently labeled validation observations. Final-test results are reported separately; they do not tune the candidate.

Rules can request CHALLENGE for one ambiguous signal or CONTAIN for both signals. They cannot contain code, regular expressions, network addresses, new powers, timing changes, policy writes or recovery commands. Every candidate remains **Proposed / review_required**. No installation or automatic promotion service exists. The current dataset explicitly marks simulated clean batches using independently signed teacher ground truth; production trust must not be inferred from the poisoning detector's score.

`worker.tryCountermeasure(candidate, observation)` is an explicit local trial interface. Matching proposals go through the existing button path. Supplied feature flags are untrusted: the controller checks the original independently observed event, fixed policy, uncertainty, live lease and instance token. A claimed malicious feature pattern cannot turn trusted suspicious evidence into authority for containment. Protected-control observations are skipped; fixed controller protection remains the independent enforcement layer. Existing intervention deadlines and escalation profiles remain unchanged. Applied responses produce the existing intent/reconciliation evidence.

The first recorded candidates recover the existing simulated signal patterns. This verifies template development and safe routing, not invention of new defenses. A compromised teacher can still provide bad signed examples. Greater uncertainty never adds powers.

## Storage and recovery

New controller journals encrypt each already HMAC-chained encoded record with AES-256-GCM. Random 96-bit nonces and authenticated purpose metadata protect each envelope. HKDF separates storage and transport key contexts. Delta compression still occurs before encryption; full-equivalent storage counters now include encryption overhead. Verification decrypts and authenticates first, then checks the original HMAC chain, sequence, delta bases and live trusted head. Protected controller journals reject plaintext downgrade. Emergency receipts are independently encrypted with a separate context; they are not a chained archive and require independent reconciliation.

New learning-demo JSON artifacts and background candidate reports use encrypted artifact envelopes. Their inner dataset/model signatures are still checked after decryption. Encryption is not a substitute for provenance, independent labels or trust in the signing key. CVE reference snapshots remain public reference data. Summary reports expose simulation results and metadata rather than raw training examples. Legacy JSON loading remains available for simulation compatibility; it does not make legacy data authenticated or confidential.

Evidence keys and artifact keys are wrapped under a vault master protected by Windows CurrentUser DPAPI. The private vault is at the workspace's `.sentry-private` directory, outside `outputs/barriers-sentry` and the ZIP. Evidence `.keyref` sidecars contain opaque references, not keys. `read-evidence.js` retrieves the wrapped key for local inspection; inspection does not establish the original HMAC chain's external trust. The user profile must be loaded, and the vault must be backed up with the profile using a separately governed recovery process. Losing the vault/profile loses recovery. The ZIP alone cannot decrypt protected artifacts on another account or computer.

Windows file mode flags do not prove Windows ACL enforcement. DPAPI binds keys to the current user, not to SENTRY versus another process running as that same user. There is no OS sandbox preventing a compromised same-user process from accessing the vault or memory. Separate identities, vault ACLs, a restricted key broker, external evidence anchors, rotation and disaster recovery remain **Proposed**. Production key custody is **Unknown**.

`protect-archives.js` encrypts retained simulation JSON and journal archives while recording pre-encryption byte hashes. Journal text is preserved byte-for-byte; JSON values are preserved with their inner signatures, while whitespace formatting can change. This does not retroactively verify journals whose original signing keys were discarded. `verify-protected-archives.js` checks stored ciphertext hashes, exact recovered journal-text hashes and readable JSON values. Previously downloaded plaintext archives remain plaintext.

## Local transport

Controller, SENTRY, background learner and analysis child-process links now carry AES-256-GCM envelopes. The trusted launcher gives each child a fresh random session key through its inherited environment; that environment variable is removed when consumed and never forwarded to another child. Direction-specific keys/contexts prevent reflection. Authenticated monotonically increasing message sequences prevent replay and reordering; session identifiers prevent cross-session reuse. Authentication/order failure closes the channel; the controller revokes authority on inbound failure, and compute workers fail closed. Packet contents are bounded, and the background learner remains limited to one job, 128 MiB JavaScript heap and 30 seconds. These are application limits, not total OS resource isolation.

Local encryption protects packet contents relative to secret session keys. It does not authenticate an executable through hardware attestation, isolate endpoints from the same user, hide memory from a compromised host, or guarantee availability. Threads inside an analysis process use in-memory worker messages; no remote network listener was added. Signed supervisor/observer/human domains remain independent of transport authentication. A worker owning its link key gains no supervisor credentials or new authority.

Remote transport is **Proposed**: TLS with independent certificate identities, approved trust roots, client authentication, rotation/revocation and no downgrade. This prototype makes no remote TLS or production network-action claim. The CVE importer continues to use the fixed official HTTPS API with redirects refused.

## Executable checks and claims

```text
node --test tests/*.test.js
node src/security-demo.js
node src/protect-archives.js
node src/verify-protected-archives.js
node src/background-demo.js <saved-learning-directory>
node src/read-evidence.js <evidence.jsonl>
```

Windows profile access is required for vault operations. The sandboxed executor may not load that profile; running with the user's normal Windows context resolves that limitation. No network or destructive action is required by these commands.

- **Verified locally:** encrypted log round trips, delta reconstruction, altered ciphertext/key/context rejection, plaintext downgrade/truncation rejection, emergency confidentiality, large-message handling, local key recovery, replay/reflection/session/order rejection, constrained candidate generation, trusted-evidence gating, reconciliation and expired-authority denial.
- **Recorded:** simulation support and validation/test results, protected artifact bytes, archived byte hashes and the local security demonstration.
- **Inferred:** reducing exposure through encrypted storage/transport and a finite proposal surface helps protect confidentiality when endpoint keys remain secret.
- **Proposed:** representative real countermeasure development, hardened key custody, independent external anchors, OS isolation and remote mutual TLS.
- **Unknown:** real-world countermeasure efficacy, adaptive poisoning resistance, compromised-host protection and production availability.

Primitive behavior follows the [Node crypto documentation](https://nodejs.org/api/crypto.html); Windows wrapping follows [Microsoft's CurrentUser data-protection scope](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.dataprotectionscope).
