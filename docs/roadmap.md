# Proposed deployment roadmap

1. **Independent enforcement process:** versioned, bounded protocol with authenticated identities, anti-replay, deadline handling and no alternate actuator routes. The model receives only a worker interface. Prove that it cannot reach human/supervisor operations.
2. **Native evidence and key providers:** use audited cryptographic implementations rather than bespoke algorithms; define authenticated encrypted records, trusted anchors, crash recovery, quotas and reconciliation. Windows user/service-bound protected storage and Linux deployment-appropriate secret stores need separate threat models. Do not fall back to plaintext keys when a provider is unavailable. The current lab needs no persistent secrets and implements no native vault.
3. **Service lifecycle:** least-privilege Windows service and Linux service packages, signed Windows releases, platform-specific filesystem permissions, and explicit upgrade/rollback behavior. Installers must not silently expand permissions. Container packaging alone will not establish an authority boundary.
4. **Real sensors/adapters:** start with read-only integration fixtures, then independently observed pre-authorized effects. Keep protected control paths separate from bulk analysis queues.
5. **Typed tooling:** evolve dashboard and connectors to TypeScript, with runtime schema validation at every untrusted boundary. Types do not replace runtime enforcement. Retain the current JavaScript reference until differences are explicitly approved and tested.
6. **Advisory learning service:** run training and recommendations outside the authority process; preserve provenance, quarantine, independent labels, held-out campaigns and explicit countermeasure rehearsal. No model-generated power or automatic promotion.
7. **External review and measured adoption:** publish reproducible Windows/Linux tests, known failures, performance measurements, and independent review results before production claims. Add architectures and distributions only after actual CI/testing.

All items above are **Proposed**. This repository is an initial test vehicle, not completion of the deployment roadmap.
