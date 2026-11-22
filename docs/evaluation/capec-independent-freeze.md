# Independent CAPEC benchmark — freeze record

Freeze date: 2026-11-22. Repository HEAD at freeze: `4283360`.

The benchmark file was **not modified** while creating this record.

## Identity

| Field | Value |
|---|---|
| Dataset | `evaluation/datasets/capec_independent.json` |
| SHA-256 | `93128e50b5f694214f46b269979da151acc6f3a9860a06b151a718e937ad49c8` |
| Size | 32,318 bytes |
| Cases | 21 evaluable |
| Last commit touching file | `8b4fe2d` (2026-10-29) |
| Builder | `scripts/build_capec_independent.py` |
| Evaluator | `evaluation/retrieval/evaluate_capec_independent.py` |
| Run command | `python scripts/run_evaluation.py --stage capec-independent --save results/evaluation` |

## Provenance

- Queries: verbatim NVD 2.0 descriptions.
- Labels: MITRE CAPEC `Example_Instances` sentences that explicitly name a CVE;
  copied verbatim with `label_evidence`.
- Candidates: the same CWE->CAPEC expansion as the main benchmark. CWEs come
  from NVD, or from the CWE catalog `Observed_Examples` when NVD has none
  (recorded per case in `cwe_source`).
- No label was hand-written for score improvement.

## Frozen protocol

- Graded pool: identical candidate set for both rankers in each case.
- Metrics: Top-1, Recall@5, MRR; `all` counts unreachable labels as misses,
  `reachable` counts only cases whose label is in the candidate pool.
- Unreachable labels are reported as coverage failures, never as ranking errors.
- `review_status` defaults to `mitre-evidence`; clearing it removes a case from
  scoring and lists it as awaiting review.

## Frozen measurements (from `docs/analysis.md`)

| Method | Split | Top-1 | R@5 | MRR | Empty | n |
|---|---|---:|---:|---:|---:|---:|
| tfidf | all | 0.3333 | 0.5714 | 0.4444 | 0 | 21 |
| tfidf | reachable | 0.5833 | 1.0000 | 0.7778 | 0 | 12 |
| word2vec | all | 0.1905 | 0.4762 | 0.3171 | 0 | 21 |
| word2vec | reachable | 0.3333 | 0.8333 | 0.5549 | 0 | 12 |

Coverage: 12/21 = 0.571 of labelled cases have the label reachable at all.

## Interpretation rules

- This set is deliberately independent of the CWE->CAPEC closure used to build
  candidates; on it TF-IDF beats Word2Vec. Do not claim Word2Vec superiority.
- The 120-CVE `capec_benchmark.json` is circular and stays only for
  comparability with the paper. Never cite its Top-1 as ranking evidence.
- 15 of 21 cases are from 1999-2007. Results are directional, not a precise
  estimate for modern CVEs.
- MITRE examples are illustrative, not exhaustive; absence of a label is not
  evidence that a prediction is wrong.

## Re-run check

Recompute the hash before quoting any number:

```powershell
Get-FileHash evaluation\datasets\capec_independent.json -Algorithm SHA256
```

If the hash differs from the value above, this freeze record is void and the
evaluation must be re-run before citing results.
