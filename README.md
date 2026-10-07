# SENTRY external testing

**Barriers by SENTRY — Rust authority-boundary experiments for Windows and Linux.**

This public repository is for reproducible external testing of a small, simulated enforcement core. It complements firewalls and endpoint security. It is not a production agent, intrusion detector, operating-system sandbox, or replacement for existing protections.

- **Verified** — a named test passed on an identified platform for this simulation.
- **Recorded** — metadata or fixture observations.
- **Inferred** — a design conclusion without a dedicated proof.
- **Proposed** — roadmap only.
- **Unknown** — no evidence (including real exfiltration coverage, poisoning coverage, and sandbox-escape resistance).

Current finite checks: **22 native controller adversarial tests, 16 hardware-policy tests using mock verifiers, 2 compile-fail boundary checks, 17 shared worker-protocol cases against a pinned JavaScript reference, and 10 negative protocol assertions.** These do not establish security against host compromise or physical TPM correctness.

Run it with the official stable Rust toolchain installed:

```text
cargo test --locked --all-features
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo run --locked --features test-fixtures -- --demo
```

If you run it on another machine, file a [test-result issue](https://github.com/spikediegel-prog/SENTRY-External-Testing/issues/new?template=test-result.yml) with platform, toolchain, commit, commands, and observed behavior.

The Rust library has no third-party dependencies. It builds as native code; the demonstration binary requires no Node runtime. Node 22+ is needed only for JavaScript comparison tools. Unsafe Rust is forbidden in this crate. These choices do not establish security against arbitrary host compromise.

## Run locally

Install the official stable Rust toolchain, then run these commands from this directory on Windows or Linux:

```text
cargo test --locked --all-features
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo run --locked --features test-fixtures -- --demo
cargo build --locked --release --features test-fixtures
```

The lab executable is `target/release/sentry-lab.exe` on Windows and `target/release/sentry-lab` on Linux. This is a simulation executable. It makes no network requests, changes no firewall rules, modifies no real user files, and runs no arbitrary shell commands.

For the finite cross-language comparisons (Node 22+):

```text
cargo build --locked --features test-fixtures
node testing/differential.mjs
node testing/negative-protocol.mjs
```

The worker-only stdin protocol accepts tab-separated proposals and read-only status. Recovery, grants, heartbeat renewal, policy mutation, learning promotion, and hold release are not exposed through stdin. See [external testing instructions](docs/external-testing.md).

## Architecture

- **Optional TPM identity foundation:** a fail-closed hardware-evidence wrapper, explicit Windows TPM key helper, and Linux signing/quote-collection helpers. The default verifier rejects all proofs. Physical TPM behavior and complete independent attestation are unverified; no hardware is provisioned by the demo or CI. See [implementation and limits](docs/hardware-identity.md).
- **Rust core:** fixed action/resource scopes, monotonic lease, generation-bound worker ports, temporary one-use permissions, synthetic tripwire containment, timed intervention, progressive self-containment, postcondition verification, preserved access holds, and clean-path recovery exercises.
- **Trusted fixture:** supervisor and adapter access are owned by test code. Test-only clock advance and clean-state marking are behind the `test-fixtures` feature. The shipped lab explicitly enables that feature and is not a production service.
- **JavaScript reference:** an unchanged snapshot of [SENTRY commit a0717b3](https://github.com/spikediegel-prog/SENTRY/commit/a0717b3752d3d5d27552cbbc4672cc82d5707869) in `reference/javascript/`. It retains Guardian, learning experiments, memory quarantine, provenance, replay and the offline dashboard. Its full saved-artifact workflow still requires Windows DPAPI.
- **Windows/Linux CI:** builds and tests native executables on both systems, checks formatting/lints, runs the demo and finite worker-protocol comparisons, and uploads simulation binaries as workflow artifacts. CI outcomes are evidence only after the runs finish successfully.

Worker and supervisor ports are separate typed interfaces within one trusted process. This is a protocol/API boundary, not OS isolation or a signed remote human identity. The native demonstration uses bounded in-memory evidence; authenticated durable Rust storage and real platform key providers are not implemented. See [architecture and threat model](docs/architecture.md) before interpreting test results.

## Evidence and claims

The finite checks listed above are not a claim that all 104 JavaScript assertions were ported. See [claims](docs/claims.md), [local validation](validation/local-windows.json), and the [CI runs](https://github.com/spikediegel-prog/SENTRY-External-Testing/actions).

## Contribute test results

Report your platform, toolchain, exact commit, command, expected behavior, observed behavior, and minimized synthetic reproduction. Identify false positives and missed cases as carefully as successful blocks. Use [test-result template](.github/ISSUE_TEMPLATE/test-result.yml). For sensitive vulnerabilities, follow [SECURITY.md](SECURITY.md).

The next milestones are an isolated host protocol, protected storage providers, real independent postcondition sensors, typed integration tooling, and a live operator UI. Their status is **Proposed**, not implemented. See [roadmap](docs/roadmap.md).
