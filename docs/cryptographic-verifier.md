# Opt-in cryptographic verifier — experimental

The `hardware-verifier` Cargo feature implements OS randomness, signed enrollment-record validation, a narrow RSA/SHA-256 TPM quote verifier, and a short-lived child-process adapter. It is not enabled by the ordinary demo or worker protocol. `RejectAllVerifier` remains the default. Tests never access, provision or clear a TPM.

## Build and exercise

```text
cargo test --locked --all-features
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo build --locked --release --features hardware-verifier --bin sentry-verifier
```

The last command produces the verifier **without** the `test-fixtures` fault switches. Test builds with that feature can deliberately stall, crash, emit oversized output or return malformed JSON. No fixture switch approves fake hardware. The cryptographic test suite generates deterministic, publicly reproducible RSA keys in memory; never use these seeds or keys for actual enrollment. Its expensive synthetic signing cases run serially; the controller's explicit concurrent-worker test is unaffected.

Default library builds continue to use only the standard library. The opt-in verifier uses `ring` for OS randomness, SHA-256 and RSA signature verification, and `serde`/`serde_json` for strict bounded protocols. `rsa` and `rand_chacha` are development-only synthetic signing dependencies. Lockfile updates are now required for reproducible builds. This crate forbids unsafe Rust in its own source; that does not imply its dependencies contain no unsafe code.

## Trust supplied at bootstrap

`ProcessVerifier::new` takes an absolute path to the trusted verifier executable, an independently pinned enrollment-authority RSA public key, exact signed manifest bytes, the signature, an independently pinned SHA-256 of that manifest, and a timeout between 50 and 2000 ms. Workers/models cannot choose these inputs. The host administrator must protect the executable and bootstrap configuration; canonicalizing a path is not protection against host tampering.

The trusted supervisor injects this verifier into `HardwareSupervisor`, which still owns all existing authority decisions. This integration has no new grant, resource, actuator or hold-release operation. The worker stdin protocol cannot configure or call it. Evidence is sent over anonymous local pipes; there is no network listener or destructive adapter.

Enrollment signatures are RSASSA-PKCS1-v1_5/SHA-256 over `SENTRY-ENROLLMENT-V1\n` followed by the **exact JSON bytes**. Keys are RSA-2048 and identity/root public keys use PKCS#1 DER, not PEM, SPKI or a CNG blob. Manifest fields are defined by `attestation::Enrollment`; unknown fields, duplicate serde fields, invalid identifiers, fingerprints, AK attributes/names, unordered PCR indices and unsupported provenance policy are refused. Records expire in at most 24 hours and are checked before and after verification against the host clock.

The manifest requires a `physical-tpm2` enrollment class, a `credential-activation-and-key-certification` binding method, an audit reference and endorsement-identity fingerprint. **These are signed assertions by the trusted enrollment authority. The verifier does not perform credential activation, validate EK manufacturer chains, or certify keys itself.** A signed assertion is meaningful only if the independent authority actually performed those checks and pinned the correct qualified AK name and boot profile. The synthetic test authority deliberately signs synthetic records; those passing tests are not evidence of physical hardware.

There is no supplied trusted root, approved physical-device record or private enrollment key. There is no automatic enrollment or model-controlled root acquisition. Immediate revocation requires trusted bootstrap pin removal/replacement and authority revocation; online revocation distribution remains Proposed. Expiry is not protection against a compromised host clock or VM rollback. See the [enrollment contract](hardware-enrollment.md).

## Cryptographic and measured-boot checks

The implementation validates the identity signature over every V2 challenge byte: session, sequence, nonce, instance, generation and policy. It verifies the quote signature with the signed record's AK, checks the TPM magic/type, qualified signer and SHA-256 challenge qualification, requires a safe clock flag, matches the exact enrolled PCR selection, and rejects truncated/trailing structures and unsupported algorithms.

Supported AK public areas are restricted RSA-2048 TPMT_PUBLIC values with SHA-256 names and RSASSA/SHA-256 signatures, fixedTPM/fixedParent/sensitiveDataOrigin/sign attributes, no decrypt attribute, null symmetric scheme and exponent 65537. It recomputes the AK Name. The qualified Name remains a trusted enrollment pin; its hierarchy binding must have been validated at enrollment.

Event-log validation is intentionally narrow: a maximum 16 KiB binary TCG EFI Spec ID Event03 log, at most 512 Event2 entries, SHA-256 PCR replay from zero initial values, an exact independently approved event-log SHA-256 pin, and comparison against enrolled PCR values and the quote's PCR digest. Supported additional digest banks in the log are SHA-1/384/512; only the SHA-256 bank is evaluated. StartupLocality, unsupported formats/algorithms and larger or changed logs fail closed. This is not general IMA replay, a universal boot profile, or runtime integrity verification. Event digests are replayed as measurements; the exact reviewed log pin supplies profile approval rather than assuming event payload bytes are executable binaries.

## Collection and bounded packaging

The Linux helper still collects from an independently enrolled AK and requests PCRs 0/2/7. To package its raw quote, default TSS-format signature, and an independently obtained binary event-log snapshot:

```text
sentry-verifier --package-quote quote.msg quote.sig binary_bios_measurements
```

This writes a JSON `QuoteBundle` to stdout with bounded lowercase-hex fields; it makes no verification claim. File snapshots are bounded to 2048 quote bytes, 512 signature bytes and 16 KiB log bytes. The resulting bundle is placed in `HardwareProof.quote`; identity signatures are raw bytes in `identity_signature`. The event log need not be secret-free: operators must handle it according to their data policy. The tool does not discover hardware, fetch logs or transmit data.

Linux public PEM output must be converted to the canonical PKCS#1 DER representation during trusted enrollment. Windows CNG public blobs likewise need trusted conversion; Windows quote collection is still absent. Collection-format compatibility and actual PCR profiles remain Unknown until tested against real hardware and official tools. Do not silently convert unsupported input into approval.

## Process deadline and isolation limits

Each verification uses a fresh child with cleared environment, no shell, piped input/output, discarded stderr and a hidden Windows window. Serialized requests are capped at 256 KiB and responses at 4096 bytes. Evidence and manifest sizes have additional smaller limits; decimal JSON encoding can cause an otherwise bounded proof to exceed the request ceiling, in which case it is rejected. The child must exit successfully and return an unambiguous versioned response before it can be accepted.

On expiry, excess output, crash or malformed protocol, the parent refuses evidence, terminates/reaps the child, and the existing hardware wrapper revokes authority and reconciles the failure. Deadline checks also prevent accepting a late success. Tests exercise actual child termination and revocation, rather than waiting for an inline callback to finish.

This is **process separation, not an OS sandbox or a hard real-time guarantee under host failure**. The provided verifier never launches descendants. Process creation, termination/reaping and pipe-thread scheduling rely on a healthy OS; protection against a substituted binary that forks descendants, kernel compromise, global scheduler starvation or hostile same-user process manipulation is not established. An independently privileged watchdog and OS-enforced process-tree/resource isolation remain Proposed. Directly injecting `CryptographicVerifier` instead of `ProcessVerifier` runs verification inline and does not provide the child timeout. OS randomness in the parent relies on the OS source; its unpredictability and snapshot behavior are not established by sampling tests.

Heavy load can cause legitimate verification to miss its deadline and fail closed. No throughput or uninterrupted-availability claim is made.

## Claims

- **Verified after passing named tests on an identified platform:** 30 finite synthetic cryptography/process assertions; existing controller, policy and worker-protocol checks. Includes real RSA verification of synthetic signatures, old-proof binding failures, enrollment pin/signature rejection, log/PCR mismatches, unsupported structures, child failures/timeouts and unchanged authority scope.
- **Recorded:** opt-in implementation and signed record/proof formats; helper collection outputs when explicitly run.
- **Inferred:** independent signed enrollment and full challenge binding reduce specific substitution/replay opportunities under stated trust assumptions.
- **Proposed:** actual enrollment ceremony, EK-chain validation, identity certification integration, Windows quote collector, general profile/log support, online revocation, protected native evidence storage and independent OS watchdog/sandbox.
- **Unknown:** physical TPM/tool interoperability, accepted hardware provenance, host/VM snapshot resistance, runtime integrity, scheduler behavior under adversarial workloads and production containment effectiveness.

Sources: [TCG TPM structures](https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf), [official quote collection](https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_quote.1/), [official credential activation](https://tpm2-tools.readthedocs.io/en/stable/man/tpm2_activatecredential.1/), and the pinned `ring` crate's randomness/signature documentation and source.
