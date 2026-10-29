# Analysis: measuring CVE → CAPEC mapping honestly

This document records what the CAPEC evaluation can and cannot show. It is the
result of auditing the tracked 120-CVE benchmark, building an independent
21-case evaluation set, and comparing TF-IDF against Word2Vec on both.

Short version: **the 120-CVE benchmark is circular and near-saturated; the
independent set reverses its conclusion.** On labels not derived from the CWE
map, TF-IDF beats Word2Vec, and the dominant failure is that the CWE→CAPEC
candidate pool does not contain the right answer at all.

---

## 1. Audit of the existing evaluation

### 1.1 Labels are the candidate generator's own closure

`evaluation/datasets/capec_benchmark.json` takes its labels from
Galeax/CVE2CAPEC. Galeax computes a CVE's CAPEC set from its CWEs
(`cwe2capec.py`: `fetch_capec_for_cwe` → `cwe_db[cwe]["RelatedAttackPatterns"]`),
which is the same relation `src/vuln2action/retrieval/capec.py` uses to build
candidates.

Measured over all 18,540 joinable CVE-2021 records: **the published CAPEC set
equals the CWE→CAPEC expansion in 100% of cases.** In the tracked 120-case file,
`capec_label == candidates_for_cwes(label_source_cwe)` for **120/120** cases.

Consequence: any method that ranks those candidates and returns *any* one of them
can be "correct" under the membership protocol. The metric measures whether
candidate expansion happened, not whether ranking works.

### 1.2 The discriminative metrics were also near-saturated or invalid

| Metric | Audit result | Verdict |
| --- | --- | --- |
| `top_1_accuracy` (membership) | 0.9417 / 0.9833 | Circular (§1.1) |
| `top_1_cwe_coverage` | 0.96 for both methods | Graded gain is derived from the *same* CWEs used to make candidates |
| `top_1_matches_best_candidate` | 0.98 for both | Near-saturated, cannot separate methods |
| `ndcg` | **computable on only 2 of 120 cases** | Reported as if it were a 120-case number — misleading |
| query leakage | 0 queries contain a `CAPEC-` id | Clean |
| candidate filtering | `max_candidates=120` never triggered | No hidden filtering |
| candidate/label coverage | candidates ⊆ labels in 116/120 cases | Confirms §1.1 |

**NDCG validity.** `_graded_relevance` assigns each candidate the share of the
CVE's CWEs it relates to. 111 of 120 cases have a *single* CWE, so every
candidate scores exactly 1.0; `_ndcg` correctly returns `None` when fewer than
two distinct gains exist. The aggregate therefore averaged NDCG over 2 cases
while printing it next to 120-case figures. This is now explicit in the report
(`ndcg_base_cases`, `ndcg_is_representative`) and flagged in the README.

The NDCG implementation itself is correct: exponential gain `2^rel − 1`, ideal
DCG from the sorted gains, discount `log2(position + 1)`, positions 1-based. The
problem was the denominator (how many cases), never the formula.

### 1.3 Data leakage

- Queries are verbatim NVD descriptions; none contain a `CAPEC-` identifier.
- Candidates are rebuilt from NVD CWEs, labels come from Galeax CWEs. These CWE
  lists are *not* identical (`nvd_cwe_matches_label_source` is recorded per
  case), so candidate/label overlap averages 27% — the labels are much larger
  than the candidate pool. This is why membership can succeed while the label is
  never actually reachable.
- No train/test contamination exists because nothing is trained on the labels.

### 1.4 Why a second evaluation set was necessary

A benchmark whose labels are produced by the same rule as its candidates cannot
falsify that rule. Fixing the metric is not enough; the labels have to come from
a different source. That is what P0.3 adds.

---

## 2. Independent evaluation set

`evaluation/datasets/capec_independent.json`, built by
`scripts/build_capec_independent.py`.

### 2.1 Label source

MITRE CAPEC `Example_Instances`: sentences where MITRE analysts describe a real
incident and cite the CVE ("… See also: CVE-1999-0906"). 59 CAPEC patterns name a
CVE this way. The label is *the attack pattern MITRE says the incident
exhibits*, not a CWE expansion.

Each case stores `label_evidence` with the verbatim sentence, e.g.

```
CVE-2004-2182 -> CAPEC-61 Session Fixation
evidence: "An attacker can hijack user sessions, bypass authentication controls
and possibly gain administrative privilege by fixating the session of a user
authenticating to the Management Console on certain versions of Macromedia JRun 4.0…"
```

A reviewer can accept or reject every mapping without opening another tool.

### 2.2 Labeling criteria

1. A label is accepted only when a CAPEC `Example_Instances` entry explicitly
   names the CVE.
2. Labels are copied verbatim; nothing is inferred, merged, or edited by hand.
3. CWEs are needed only to build candidates: NVD first, else the CWE catalog's
   `Observed_Examples` (MITRE's own). The source is recorded in `cwe_source`.
4. A case is skipped if it has fewer than 2 candidates (no ranking possible).

### 2.3 Resulting set

| Statistic | Value |
| --- | --- |
| CVEs with a MITRE example label | 59 |
| Skipped: no CWE anywhere | 29 |
| Skipped: < 2 candidates | 9 |
| **Evaluable cases** | **21** |
| Candidates from NVD CWEs | 19 |
| Candidates from CWE `Observed_Examples` | 2 |
| Label reachable in candidate pool | 12 |
| Label **not** reachable | 9 |

**Independence check.** In all 12 reachable cases the MITRE label is a **proper
subset** of the CWE-derived candidate pool, and in the other 9 it is absent from
the pool entirely. No closure-based benchmark can produce that: in the 120-case
file, the label set always equalled the closure and candidates were a subset of
labels in 116/120 cases.

### 2.4 Uncertainty (read before citing any number)

- MITRE examples are **illustrative, not exhaustive**. A CVE may exhibit attack
  patterns MITRE never documented. Absence of a label is not evidence that a
  prediction is wrong.
- The set is **old**: 15 of 21 cases are 1999–2007, because MITRE stopped adding
  CVE citations to examples. It says nothing about 2020s vulnerabilities.
- 29 of 59 CVEs had no CWE in NVD *or* the CWE catalog, so they cannot be
  evaluated by this architecture at all. That is a coverage finding, not a
  labelling failure.
- 21 cases is small. Differences are reported with their base counts; treat them
  as directional, not as precise estimates.
- `review_status` defaults to `mitre-evidence`. A human reviewer can move a case
  to `reviewed-accepted`; metrics count both. Labelled-but-unreviewed cases can
  be moved out of scoring by clearing `review_status`, and they are then listed
  under "awaiting review" instead of being scored.

---

## 3. Results

Identical candidate pools per case; same ranking code and metric definitions as
the 120-case harness (`evaluation/retrieval/evaluate_capec.py` is reused
unchanged).

`all` = every labelled case, unreachable ones counted as misses.
`reachable` = only cases whose label is inside the candidate pool.

| Method | Split | Top-1 | R@5 | MRR | Empty | n |
| --- | --- | --- | --- | --- | --- | --- |
| tfidf | all | **0.3333** | 0.5714 | 0.4444 | 0 | 21 |
| tfidf | reachable | **0.5833** | 1.0000 | 0.7778 | 0 | 12 |
| word2vec | all | 0.1905 | 0.4762 | 0.3171 | 0 | 21 |
| word2vec | reachable | 0.3333 | 0.8333 | 0.5549 | 0 | 12 |

Coverage: **12/21 = 0.571** of labelled cases have their label reachable at all.

### 3.1 The conclusion reverses

On the circular 120-case benchmark Word2Vec looked better (Top-1 0.9833 vs
0.9417; NDCG on 2 cases). On independent labels **TF-IDF wins on every metric**:
Top-1 0.3333 vs 0.1905 (all), 0.5833 vs 0.3333 (reachable), MRR 0.4444 vs
0.3171.

The mechanism is visible in the failure list: Word2Vec's mean-vector similarity
pulls toward topically related but wrong patterns. On `CVE-2001-1534` (session
credential prediction, CAPEC-59) it ranks CAPEC-196 first; on `CVE-2016-0353`
(cookie interception, CAPEC-31) it predicts CAPEC-60. TF-IDF's exact-token match
keeps a sharper signal when the description shares vocabulary with the pattern.

This is exactly the kind of conclusion the original benchmark was structurally
unable to produce.

### 3.2 Failure analysis

Two distinct failure modes, and the second dominates:

**(a) Ranking failures** — label is reachable, ranker picks something else.
`CVE-1999-0428`, `CVE-2005-4900`, `CVE-2006-6652`, `CVE-2007-2027`,
`CVE-2020-0601` place the correct pattern at rank 2–8. These are fixable with a
better ranker or by weighting the CAPEC name more strongly.

**(b) Coverage failures** — the label is not in the candidate pool, so no ranker
can succeed. Examples:

| CVE | MITRE label | NVD CWE | Why unreachable |
| --- | --- | --- | --- |
| CVE-2012-0584 | CAPEC-632 Homograph Attack | CWE-20 (51 candidates) | CWE-20 is generic; IDN homograph is not among its patterns |
| CVE-2004-2182 | CAPEC-61 Session Fixation | CWE-287 | Session fixation is not a `Related_Weakness` of CWE-287 |
| CVE-2016-0353 | CAPEC-31 HTTP Cookie Access | CWE-200, CWE-254 | Broad information-disclosure CWEs map to unrelated patterns |
| CVE-1999-0073 | CAPEC-13 Env Var Subversion | CWE-642 | Wrong CWE granularity in the old NVD record |

The pattern is consistent: **generic or coarse CWEs (CWE-20, CWE-200, CWE-287,
CWE-642) expand into large, weak candidate sets that omit the specific attack
pattern.** This is the structural limitation of the CVE→CWE→CAPEC route that the
paper's 0.4%-ExploitDB framing also implies: the taxonomy link cannot express
attacks the CWE does not name.

---

## 4. What this means for the project

1. **Keep the 120-CVE file** for paper comparability, but never cite its Top-1
   or NDCG as evidence of ranking quality. The README now says so, and the report
   carries `ndcg_base_cases`/`ndcg_is_representative`.
2. **Report the independent set as the primary evidence** for the mapping stage,
   together with its coverage ceiling (0.571) and its age bias.
3. **Do not claim Word2Vec superiority.** Measured on independent labels it is
   worse. The paper's preference for Word2Vec is not reproduced here.
4. **The architecture matters more than the ranker.** Two thirds of independent
   failures are candidate-pool gaps. Improving the ranker alone cannot fix them.

## 5. Limitations to carry into the report

- 21 independent cases; 15 of them from 1999–2007. Directional only.
- MITRE examples are non-exhaustive, so precision is measured against an
  under-specified truth.
- The Word2Vec model is trained on 615 CAPEC documents on CPU, vector size 100,
  `seed=42`, single worker — far smaller than the paper's setup.
- Coverage 0.571 is an upper bound for the *present* CWE data; newer CVEs have
  better CWE coverage but fewer MITRE example labels, so the two effects cannot
  be separated with this data.
- No human reviewer has yet promoted cases beyond `mitre-evidence`; the
  annotation path exists but is unexercised in this deliverable.

## 6. Reproducing

```bash
python scripts/download_data.py --source capec          # opt-in
python scripts/download_data.py --source cwe            # fallback CWEs
python scripts/build_capec_independent.py               # uses cached NVD data
python scripts/run_evaluation.py --stage capec-independent --save results/evaluation
python scripts/run_evaluation.py --stage capec --save results/evaluation   # 120-case, for comparison
```
