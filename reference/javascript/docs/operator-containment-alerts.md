# Containment failure alerts and access status

The controller now raises local operator alerts when a containment postcondition fails, an endpoint response cannot be reconciled, or SENTRY loses protection trust. Containment response failures are labeled `CONTAINMENT_FAILURE`; integrity, evidence, transport or lease loss is labeled `PROTECTION_TRUST_FAILURE`. Neither label proves that an attacker escaped or that a sacrificial core captured one.

## Operator and access messages

Containment failure message:

> Containment response failed or could not be reconciled. SENTRY execution authority has been revoked. Verify containment through an independent trusted path and review affected access before recovery.

Access-status message:

> SENTRY privileged actions are paused. Affected access requires verified containment and authorized recovery; no automatic restoration is promised.

Do not promise “access will be granted once the sacrificial core contains the attack.” A compromised component's containment claim cannot authorize recovery. Capture or quarantine alone does not establish that credentials, endpoints, data, policy or the recovery path are clean. The prototype has no real isolated execution cage; alerts explicitly report `sacrificialCoreStatus: not_implemented` and `containmentStatus: not_verified`.

## Implemented workflow

The controller checks simulated session containment/isolation postconditions. A failed postcondition is reconciled as failed and revokes SENTRY authority. Existing endpoint audit failures also revoke authority. The gate closes before alert persistence or delivery can affect the result. Alert write failures attempt the encrypted emergency evidence path, and authority remains revoked if every destination fails.

For an already targeted failed containment operation, the controller adds a local fail-closed access hold on the affected, pre-scoped session. The simulated admission path denies that session even if the failed adapter still reports a production route. The hold does not add a remote action, isolate an arbitrary host, revoke an unrelated credential or expand the learner's permissions. Protected-control scope is excluded. Hold intent/reconciliation evidence is recorded through the journal or emergency fallback. Session route state alone must not be interpreted as effective access: the independent hold also gates admission.

Alerts identify affected sessions, reason, instance/generation and revoked authority. They expose no automatic restoration route. The recent operator view retains at most 64 alerts with a monotonic total; durable journal receipts retain the raised events where storage succeeds. Repeated panic while already quarantined does not generate duplicate alerts. A valid, independently authenticated human can acknowledge a known alert even while authority is revoked. The acknowledgment is recorded before changing the local alert view. It does not clear the alert history, lift the access hold, release endpoint containment, verify containment or grant authority.

Clean SENTRY instance recovery does not remove session holds or release previously isolated endpoints. The intelligence has no acknowledgment, hold-clearance or access-grant command. There is intentionally no hold-release endpoint in this prototype. A production release workflow must separately verify containment and resource integrity, approve any credential/device recovery, use a clean trusted path and obtain human authorization before restoring the affected access. That workflow remains **Proposed**.

Hold and acknowledgment state currently live in controller memory. They survive SENTRY instance replacement within that running controller, not a whole-controller restart. Durable hold recovery and independent reconciliation before a replacement controller can issue production capabilities remain **Proposed**; saved evidence alone is not an implemented restart/release gate.

## Delivery and proof boundary

Alerts are exposed through the local controller status and encrypted evidence only. No email, SMS, chat, pager or security-console notification is sent. Human delivery channels, independent alert services, outage handling and acknowledgments from external consoles remain **Proposed**. A compromised same-user host can still undermine process/storage isolation; this feature is not an OS sandbox or a guarantee of operator receipt.

```text
node src/operator-demo.js
node --test tests/operator-alerts.test.js
node --test tests/*.test.js
```

The demo uses a trusted white-box actuator fault; SENTRY cannot trigger that fault through its public protocol. It saves encrypted evidence, a user-vault key reference and `operator-report.json`. Windows user-profile access is required for recoverable evidence wrapping. No external notification or network action occurs.

- **Verified locally:** failure detection, revoked authority, affected-session hold, protected-control preservation, human-only acknowledgment, no release on acknowledgment/recovery, bounded recent alerts and alert-write failure handling.
- **Recorded:** local messages, receipt history and the simulated actuator-failure demonstration.
- **Inferred:** separating acknowledgment, containment verification and access restoration reduces the risk of treating an alert or capture claim as authorization.
- **Proposed:** a genuine sacrificial execution cage, independent operator delivery and trusted access-release workflow.
- **Unknown:** real attack capture, production notification reliability and safe real-world access restoration.
