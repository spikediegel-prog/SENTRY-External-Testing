# Security testing and reports

This repository contains local simulations. Test the fixtures and worker-only protocol with synthetic data. Do not target real systems, disable endpoint security, upload private keys, or include real credentials/telemetry in public reports.

Use the public test-result issue template for minimized non-sensitive reproductions. For a sensitive finding, use GitHub's private vulnerability reporting option if it is enabled. If it is unavailable, open a minimal issue requesting a private contact path without exploit details or secrets. No private-reporting configuration or staffed response SLA is assumed.

State the affected commit, platform, violated invariant, expected behavior and observed effect. A failed test supersedes the corresponding local claim until investigated.

Native fixtures have no authenticated durable evidence, external authority authentication, OS isolation, or production containment. These are documented limitations, not implemented security guarantees.
