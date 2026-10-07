# Optional TPM identity foundation

This adds an opt-in Rust hardware-evidence policy wrapper, Windows TPM key enrollment/signing helper, and Linux TPM signing/quote-collection helpers. **A complete hardware-attestation service is not implemented.** No TPM provisioning, clearing, eviction, reset or firmware change is performed by tests, CI, ordinary startup, or this development workflow.

## Implemented boundary

`HardwareSupervisor` takes ownership of the existing supervisor handle and revokes any previously issued software-fixture lease. Workers cannot configure its hardware policy, create challenges, verify themselves, renew authority, or approve recovery.

Challenges bind a fresh verifier-supplied 32-byte nonce to instance, generation and fixed policy identifier. Nonces are reserved once, including abandoned exchanges. One exchange is pending at a time. The finite 128-challenge budget fails closed rather than resetting automatically. Nonces must come from the independent verifier's CSPRNG; test fixtures use deterministic bytes only.

Every proof attempt consumes its exchange. Mismatch, expiry, missing/oversized evidence, verifier failure, wrong enrolled key/profile, or unverified provenance/state revoke authority. Deadlines are checked before and after verification. Accepted renewal/recovery only activates existing pre-authorized powers; renewal cannot revive an expired lease and recovery never releases holds automatically.

**The default `RejectAllVerifier` never approves authority.** An independently trusted integration must supply actual signature, enrolled-key, quote, freshness, boot-profile and event-log verification. No genuine cryptographic platform verifier is included or wired into worker stdin/the ordinary demo. `VerifiedPlatform` is a trusted verifier API, not booleans to accept from a model or provider. A malicious verifier/compromised trusted host can lie. Synchronous verifier stalls are not bounded by this wrapper; an isolated verifier service remains proposed.

## Windows helper

`hardware/windows/identity.ps1` exclusively selects **Microsoft Platform Crypto Provider**, creates an RSA-2048 signing key with export policy `None`, refuses an existing name, and refuses provider/export-policy mismatches. It exports only a public key blob and signature. `Probe` reads TPM presence/readiness without modifying state.

After an operator separately approves development-key enrollment on the target Windows machine:

```powershell
./hardware/windows/identity.ps1 -Operation Probe
./hardware/windows/identity.ps1 -Operation Provision -KeyName SENTRY-External-Testing-Identity
./hardware/windows/identity.ps1 -Operation Sign -KeyName SENTRY-External-Testing-Identity -ChallengePath ./runs/hardware/challenge.txt
```

Provision creates a persistent current-user key. It is **not a simulation** and is never automatically run. The scheme is RSASSA-PKCS1-v1_5/SHA-256; public output is a BCRYPT RSA public blob, not PEM. A verifier must pin this key through trusted enrollment and independently establish hardware provenance. Provider/export flags are Recorded observations, not remote attestation. The helper does not collect Windows platform quotes. Identity signatures alone must never set `platform_state_verified=true`.

## Linux helpers

Installed official `tpm2-tools`/OpenSSL and separately administrator-enrolled persistent keys are required. The scripts never create/overwrite TPM objects:

```text
bash hardware/linux/sign-identity.sh 0x81010001 runs/hardware/challenge.txt runs/hardware/identity-output
bash hardware/linux/collect-quote.sh 0x81010002 runs/hardware/challenge.txt runs/hardware/quote-output
```

Handles are illustrative. Signing needs an accessible unrestricted RSA/RSASSA key; quoting needs an appropriate enrolled attestation key. Unsupported authorization policies/tools fail, with no software fallback. Authentication sessions and deployment-specific protected authorization are not implemented.

Quotes qualify themselves with SHA-256 of the complete challenge and collect PCR 0/2/7 from the SHA-256 bank. This illustrative selection is not a universal boot policy. The independent verifier must validate signature, pinned AK identity, hardware provenance, approved measurements and event-log replay. Emulator output must not become hardware evidence merely because these commands succeed.

## Exact challenge bytes

`Challenge::message()` generates LF-terminated UTF-8:

```text
SENTRY-HARDWARE-IDENTITY-V1
nonce=<64 lowercase hexadecimal characters>
instance=<bounded identifier>
generation=<positive integer>
policy=<fixed policy identifier>
```

Domain binding protects protocol use only when actual signatures/quotes are independently verified. Deterministic nonce/mock-verifier tests are neither cryptographic nor hardware proofs.

## Updates and recovery

Key replacement, TPM/motherboard replacement, firmware changes and boot-profile updates require separately approved trusted enrollment/policy paths. Models cannot change pins or relax PCR expectations. Legitimate updates may alter measurements; learning/emergencies cannot approve a new profile. Maintain independently protected recovery before relying on device-bound keys. Hardware-required deployments must never silently downgrade when hardware is missing. Simulation mode remains separate.

TPMs do not prove runtime trust, prevent misuse of an authorized signing key, hide the model or eliminate poisoning/exfiltration. Bulk encryption belongs outside the TPM. Hardware-backed protection of evidence keys, a real watchdog, HSM providers and hardware human recovery approval remain Proposed.

## Claims

- **Verified:** finite mock-verifier protocol assertions and helper syntax checks on identified platforms.
- **Recorded:** helper-collected provider/key metadata, signatures and quotes, when explicitly run.
- **Inferred:** appropriately enforced non-exportable keys reduce some key-copying exposure.
- **Proposed:** built-in independent cryptographic attestation, Windows quote collection, evidence-key sealing and native deployment integration.
- **Unknown:** physical TPM behavior until tested, hardware provenance, runtime platform integrity and host-compromise resistance.

Sources: [Windows CNG providers](https://learn.microsoft.com/en-us/windows/win32/seccertenroll/cng-key-storage-providers), [CNG creation parameters](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.cngkeycreationparameters), [official tpm2_sign](https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_sign.1.md), and [TCG measurement/event-log guidance](https://trustedcomputinggroup.org/wp-content/uploads/TCG-Guidance-Integrity-Measurements-Event-Log-Processing_v1_r0p118_24feb2022-1.pdf).
