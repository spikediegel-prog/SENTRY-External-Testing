# Learning and testing attack permutations

Guardian now creates a separate deterministic, teacher-signed permutation dataset. The background learner fits a new **unsigned review-only candidate** on this dataset, develops constrained countermeasure proposals, and reports evaluation against combinations excluded from both training and validation. The active model, controller policy, dead-man conditions and authority remain unchanged.

## Implemented finite experiment

The default seed is 90217. The dataset has 232 batches with 64 rows each: 120 training, 32 validation and 80 test batches. Each attack variant has a benign companion. Four variation axes are recorded: row order (ordered/reverse/shuffled), simulated cadence (steady/bursty/slow), dilution by background traffic (quiet/noisy), and poisoning techniques. Noisy variants affect four of 64 rows; quiet variants affect 24. Identity hashes and sources vary without becoming classifier inputs that identify the ground-truth label.

Five complete axis combinations appear in training, four different combinations in validation, and five different combinations in final testing. Training includes label flips, instruction injection, duplicate flooding, distribution poisoning and one known composition. Final testing reserves other combinations of those techniques, plus rare-backdoor and camouflaged-poisoning families absent from training and validation. These are synthetic batch manipulations, not exploitation of a real system.

Validation rejects shared combination keys between splits, inconsistent axes/family declarations, missing partition metadata, reused row IDs, campaign leakage and excluded families entering training. The teacher signature is checked before training. Neither permutation keys, row IDs, split labels nor family names become prediction features. Final-test changes cannot alter learned weights or the threshold selected from validation. This is separation within the modeled dataset, not proof that all possible semantic duplicates or real campaigns have been separated.

The experiment compares the saved original candidate and the permutation-trained candidate on the same final test population. It also reports a simple rule baseline and failures by combination. This is a new evaluation population; its percentages must not be compared directly to the original 37.5% recall on a different dataset.

## Recorded results and limits

The original candidate caught 24 of 40 poisoned test batches, with zero false flags among 40 benign companions. The permutation-trained candidate caught all 40 poisoned batches and falsely flagged two of 40 benign companions. Both figures are **Recorded**, limited to this finite seed and generator. This does not establish protection against adaptive attackers or unseen real attacks. The candidate is not installed or promoted.

The current eight-feature classifier is order-invariant. Reversing the same rows produces identical features and identical scores. Cadence does not have a direct temporal feature; it contributes only through aggregate pattern uniqueness. Generating order/cadence variants does not make the model sequence-aware. Temporal attack detection remains **Unknown / not implemented**.

The report includes explicit feature-collision probes outside the headline test metric. One synthetic instruction attempt uses wording outside the existing phrase heuristic; another reverses event order. Both have identical features to their benign comparison input. The current model cannot distinguish either pair, regardless of whether it flags both or neither. The order probe does not implement a vulnerable stateful application or demonstrate a successful temporal exploit. These negative proofs preserve a visible limit alongside the favorable finite result.

Sequence-aware features, broader independent datasets, representative low-volume intrusions, spoofed telemetry combined with poisoning, and adaptive campaign generation remain **Proposed**. Existing Guardian protocol tests already exercise spoofing, alert suppression, noise-hidden credential misuse and quarantine escape independently; this new learning dataset does not claim those attacks have become learned detectors.

## Run and evidence

```text
node src/permutation-demo.js
node --test tests/permutations.test.js
node --test tests/*.test.js
```

The demo needs a saved learning run and normal Windows user-profile access for the private vault. It saves encrypted signed `guardian-dataset.json`, encrypted `candidate.json`, the public teacher key and encrypted authority-trial evidence under a new `runs/permutations-*` directory. It writes simulation metrics and metadata to `permutation-report.json`. The private teacher key is not retained; there is no promotion interface. Existing signed observer evidence, uncertainty and live capabilities still govern every consequential proposal.

- **Verified locally:** deterministic/bounded generation, partition and identity checks, test-independent fitting, feature-collision assertions, candidate routing and unchanged authority.
- **Recorded:** synthetic seed, confusion matrices, same-test comparison, encrypted candidate artifacts and local authority trials.
- **Inferred:** training on controlled variations can improve detection of variations visible to the existing features.
- **Proposed:** temporal representations, broader independent/adaptive testing and real-world training governance.
- **Unknown:** general unseen-attack recognition, stealthy/adaptive poisoning resistance and real-world miss/false-alarm rates.
