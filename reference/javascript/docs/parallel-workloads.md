# Parallel workload handling

## Implemented local topology

The authority host owns a fixed pool of two separate analysis processes, each containing two Node worker threads. The OS can schedule those four analysis threads across available logical processors. `workload.json` sets the trusted boot configuration: at most 32 outstanding normal jobs, eight reserved signal jobs, a 3-second deadline measured from admission, and at most two replacements per failed process. Runtime validation limits the pool to eight analysis threads, 256 normal jobs and 64 reserved jobs. Intelligence has no configuration or resize API.

Workers perform deterministic advisory hashing and session-signal preflight in parallel. They receive no signing keys, SENTRY instance capability, policy writer, or execution adapter. Their outputs are **Proposed hints**. The controller handles the original request, independently verifies its signature, validates the fields, derives the authoritative classification, checks replay and lease state, and executes through the existing scope gate. An analysis result is never an authority certificate.

Authority execution and the delta journal remain single-writer and ordered. Analysis completions are delivered in admission order to preserve existing observer replay counters, even if threads finish in a different order. A queued proposal has no reserved authority: its capability and lease are checked when it reaches execution. Admission to a pool does not extend an Intervention Window or lease.

## Overload and independent control

When normal capacity is exhausted, callers receive `workload_overloaded`; their telemetry is **not processed or acknowledged as contained**. No production action occurs for that refused request. A caller may retry with a fresh signed sequence. The controller periodically records workload counters, while reports retain individual local test outcomes. This backpressure response is separate from a successfully executed deterministic DROP, which still has its full intent/reconciliation receipts. The pool does not silently discard action evidence.

Signed observer events for session use, suspicion and known attack signals may use reserved capacity and are selected for analysis ahead of queued normal jobs. Unsigned labels cannot claim this reserve. Final execution still follows admitted observation order, so earlier admitted noise may delay a signal; the bounded queue and job deadlines limit this modeled backlog. Protected capacity is not unlimited: a full signal reserve also returns explicit backpressure.

Authenticated supervisor, human and protected control traffic bypass the analysis queue. Protected telemetry uses a separate `control` key/domain and replay counter, so prioritizing it cannot make earlier observer events appear replayed. The controller restricts that lane to the existing protected session scope and kind. This adds a transport path, not new defensive powers. Fake control/supervisor labels do not obtain the bypass.

Worker failures return explicit `analysis_unavailable`/`analysis_timeout` errors for unfinished jobs. No adapter action has begun for those jobs. Process replacement is bounded and restores compute only; it cannot renew a lease or recover SENTRY. Per-job timers prevent a failed early analysis from blocking ordered completions indefinitely. The independent controller timer and authenticated recovery path continue separately.

## Verified and unresolved claims

**Verified locally:** two analysis process IDs and four configured analysis threads; ordered completion; bounded queues with signal reserve; explicit overflow; process-crash and hung-worker handling; invalid resource configurations rejected; a concurrent noise burst leaves signed control, the simulated intrusion signal, replay ordering, policy digest and dead-man behavior intact. `tests/workload.test.js` exercises these assertions. `load-report.json` records finite-run timings and outcomes.

**Recorded:** available logical processors and local response times. These measurements depend on this host and its storage. Analysis workers are real processes/threads, but a multicore speedup is not established by this test.

**Unknown:** production DoS resistance, optimal worker count, throughput gains, adversarial OS scheduling, host-wide memory pressure and real traffic fairness. Preflight is currently lightweight, so process coordination can cost more than it saves. The controller still synchronously writes evidence and verifies journal history; those operations can dominate heavy workloads. Node IPC and OS ingress buffers are not bounded by these application job limits. Authenticating priority requests also costs controller CPU. Same-user OS isolation remains unimplemented.

**Proposed:** representative CPU-heavy detector benchmarks, ingress-level rate limits, asynchronous trusted evidence verification with protected roots, real deployment CPU/memory quotas, and separately attested worker isolation. Thread/process scaling must never create an alternate execution route, new powers, or lease renewal conditions.
