# Claim register

| Claim | Classification | Evidence / limit |
|---|---|---|
| Native core rejects expanded scopes, reused permits, nonzero uncertainty and former workers | Verified on platforms with passing named tests | Rust integration tests; identified commit/toolchain |
| Logical authority expires on integrity or lease failure | Verified in local fixtures | No real hardware attestation or independent watchdog |
| Clean recovery preserves access holds | Verified in local fixtures | No durable cross-process restoration |
| Incident-specific simulated health is required before release | Verified in local fixtures | No independent production health sensor |
| Eight concurrent attempts cannot multiply a one-use grant | Verified in the named concurrency test | No throughput or fairness claim |
| Worker API cannot grant or edit generation through safe Rust public fields | Verified compile-fail checks | Not protection against host compromise |
| Worker protocol matches the JavaScript reference for the shared corpus | Verified after differential script passes | 17 cases only, not complete parity |
| Native records are retained in bounded memory during a run | Recorded | Neither authenticated nor durable |
| Linux and Windows builds are available | Verified only after each platform's CI passes | Local Windows validation alone cannot establish Linux behavior |
| Dependency-free Rust core reduces dependency surface | Inferred | No independent audit |
| Protected OS key stores, installers/services, typed integration tooling and isolated host bridge | Proposed | Roadmap only |
| Reliable attack detection, production workload resistance, real exfiltration/poisoning coverage, sandbox escape resistance | Unknown | No production evidence |

The JavaScript snapshot contains additional experimental learning and Guardian capabilities. It retains its own claims and known misses/false positives. Those are not automatically inherited by the Rust port.
