# External testing instructions

Use a local lab checkout. Keep inputs synthetic. The repository does not authorize testing somebody else's network or endpoint.

1. Record the exact commit with `git rev-parse HEAD` and your OS and Rust versions.
2. Run `cargo test --locked --all-features`, then the demo.
3. Run the lint and formatting checks used by CI.
4. If Node 22+ is available, run the differential and negative protocol scripts.
5. Submit a minimal reproduction and distinguish Verified/Recorded/Unknown observations.

## Worker protocol

Run the built native binary with `--worker-stdin`. One line produces one decision; the session expires after ten seconds of monotonic fixture time. Every new binary invocation starts a fresh trusted fixture. This reset is a lab convenience, not production recovery or persistent policy.

The only action line shape is eight tab-separated fields:

```text
action<TAB>request-id<TAB>alice|bob<TAB>read|write|send<TAB>handbook|scratch|inbox<TAB>uncertainty<TAB>permit-id-or--<TAB>synthetic-content
```

`status` is a separate read-only line. Content may contain spaces but no tabs or newlines. Lines larger than 16 KiB are refused and the process stops reading. Request content is limited to 8192 bytes, IDs to 128 bytes, and ledger capacities are bounded. Worker stdin has no grant command; sending arbitrary permit IDs cannot create permission. Write/send success is tested using trusted fixtures in Rust tests and the demo, not by exposing human authority to the worker protocol.

The scripts in `testing/` produce inputs without requiring shell-specific quoting. For interactive testing, send the synthetic marker `SENTRY_SYNTHETIC_SECRET_01` in a send proposal and inspect its hold; use an unrelated Bob read request to test preserved legitimate activity.

## Targets for new negative proofs

- Try to produce an allowed unauthorized action or resource.
- Try to reuse a consumed/expired grant or a previous generation's worker.
- Try to cancel an expired intervention window or restore held access without a clean newer generation.
- Test invalid Unicode, oversized content, duplicate IDs, uncertainty values and ledger exhaustion.
- Add an adapter that lies about session/resource/content or errors after an effect.
- Add a sink that fails at each intent/reconciliation boundary.
- Report a legitimate request incorrectly held or an attack variation the exact marker misses.

A marker encoded or paraphrased so it no longer contains the literal string is outside the detector's coverage. If a trusted fixture grants that send, the gate may allow it. This is an explicitly known detection limitation, not evidence of generalized exfiltration prevention.

## CI and binaries

Open the Actions page and choose a completed successful Windows/Linux workflow. Each platform has a native lab artifact. Artifacts may require GitHub sign-in and have finite retention. These are testing artifacts, not signed installers or production releases. Rebuilding from source remains supported. Review the exact commit and CI outcome before attributing a result to a platform.

The JavaScript reference's full vault-backed suite remains Windows-specific. Its 17-case comparison uses a trusted in-memory journal fixture and works without DPAPI; it does not validate encrypted storage parity.
