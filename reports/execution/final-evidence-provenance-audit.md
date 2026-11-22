# FINAL ARCHITECTURE AUDIT — Evidence & Provenance Trace

- Ngày: 2026-11-22 · Baseline HEAD `4283360`
- Phạm vi: READ-ONLY. Không sửa source/artifact/graph, không refactor, không Docker/training/Kaggle/benchmark, không commit/push.

## Scope note (quan trọng)

HEAD là `4283360`, nhưng **working tree có 7 file modified chưa commit**. Source được audit ở trạng thái **working tree hiện tại**, vì artifact `results/t5-demo-cve-001/report.json` được sinh ra từ source này. Riêng chuỗi `checkpoint_id` **chỉ tồn tại trong working tree**: baseline `4283360` không có `EvidenceBundle.checkpoint_id`, `Workflow.checkpoint_id`, `EvidenceCollector.add_checkpoint_id`, `flow_to_workflow(checkpoint_id=...)` và `collector.add_checkpoint_id(...)` (xem `git diff` của 5 file). Mọi nhận định về `checkpoint_id` ở dưới đều mang điều kiện này.

## 1. Executive summary

Artifact hiện tại (`results/t5-demo-cve-001/report.json`, 14.592 B) **chứng minh được execution thật và verdict PASS**, nhưng **không chứng minh được nguồn tri thức và model provenance**:

| Câu hỏi | Trả lời ngắn | Bằng chứng |
|---|---|---|
| Retrieval score có trong artifact? | **KHÔNG**. Token `score` xuất hiện 1 lần, là CAPEC mapping score (`capec.py:92`), không phải retrieval score. | `prompts.py:6-7`, `run.py:76` |
| Backend name có trong artifact? | **KHÔNG**. Token `backend` xuất hiện 0 lần. | `base.py:25-44`, `run.py:70-82` |
| Document ID/source có giữ? | **MỘT PHẦN**: chỉ `context_sources` = `["CWE-79","CWE-352","reference:..."]`; mất `kind`, `name`, `source` URL. | `run.py:76` |
| checkpoint_id từ đâu? | T5: `GeneratedFlow.checkpoint` ← `T5ProviderSettings.checkpoint`/`base_checkpoint`; rule_based: `null`. | `t5.py:276-309`, `models.yaml:23-26` |
| Evidence phân biệt rule-based/T5? | Có `provider`, nhưng **không có version/config/prompt**. | `report.provider`, `evidence.generation.provider` |
| Tái dựng workflow? | **Snapshot có** (`evidence.workflow`, `evidence.generation.output`); **tái sinh thì không** (thiếu backend/score/config/version). | `collector.py:33-40`, `run.py:83` |

Kết luận: evidence hiện tại là **audit trail của verdict**, không phải **audit trail của suy luận**.

## 2. End-to-end provenance diagram

```
data/samples/sample_cves.json
  └─ samples.py:12-28 parse_cve_dict ──> CveRecord(cve_id, description, lab_id)
       └─ cli.py:46 --sample ──> run.py:36 run_pipeline
            ├─> analyze.py:56 analyze_cve
            │    ├─ ranker.py:20-66 build_contexts_for_cve
            │    │    ├─ corpus.py:98-118 default_corpus() ──> KnowledgeDocument (doc_id, text, source URL)
            │    │    ├─ get_backend() [base.py:25-44] ──> keyword/tfidf/semantic ──> RetrievedContext(source,text,score,backend)
            │    │    └─> rank_contexts() [ranker.py:11-17]
            │    ├─ generation.get_generator() [base.py:18-31] ──> Workflow (+checkpoint_id nếu T5)
            │    └─ resolve_capec() [capec.py] ──> CapecMapping(method, score, ranked)
            ├─ ReproductionPlanner.plan() [planner.py:7] ──> ExecutionPlan (5 steps, target=localhost)
            ├─ ReproductionExecutor.execute() [executor.py:73-147]
            │    └─ select_validation_command() [executor.py:21-31] ──> labctl.py up/validate/down
            │         └─ stdout "V2A_VALIDATION_JSON:{...}" [labctl.py:132-138] ──> parse_validation_output()
            ├─ Validator.validate() [validator.py:7-63] ──> ReproductionResult(PASS|FAIL|SIMULATED|ERROR|SKIPPED)
            └─ EvidenceCollector [collector.py] ──> EvidenceBundle ──> PipelineResult.to_dict()
                 └─ save_report() [reporter.py:28-52] ──> results/<run>/report.json + report.md
```

**Điểm gãy (data-loss) nằm ở nhánh retrieval → generation** (`prompts.py:6-7`) và **executor → collector** (`command_outputs` rỗng).

## 3. Metadata lifecycle table

| # | Thông tin | Khởi tạo | Biến đổi | Bị loại bỏ ở | Lưu ở | Đọc lại ở |
|---:|---|---|---|---|---|---|
| 1 | CVE identity + source | `samples.py:12-28` từ `data/samples/sample_cves.json` | `cli.py:46` → `run.py:47` | path file nguồn không lưu | `report.cve_id`, `evidence.generation.input.cve_id/description` | `api/routes/cve.py:18`, CLI `--sample` |
| 2 | CWE/CAPEC mapping | CWE từ `nvd.py:269`/sample; CAPEC từ `capec.py:map_cve_to_capec` | `ranker.py:31-52`, `analyze.py:21-53` | catalog snapshot/version, CWE source URL | `evidence.generation.capec` (method/score/candidates/ranked), `workflow.context_summary` | `report.json` |
| 3 | KnowledgeDocument identity | `corpus.py:39-56` factory hoặc `:63` model_validate | index text 3 biến thể | `kind`, `name`, `source` URL | chỉ `doc_id` trong `generation.input.context_sources`; text trong `context_summary` | `run.py:76`, `prompts.py:7` |
| 4 | Retrieval backend | `get_backend` `base.py:25-44` | — | **không bao giờ ghi vào artifact** | không có | config/settings.yaml:9 |
| 5 | Retrieval score | backend `.search` (`keyword.py:42`, `tfidf.py:54`, `semantic.py:350`), `ranker.py:38,49,62` | rank/dedupe | `prompts.py:6-7` | **không có** (score trong report là CAPEC score) | — |
| 6 | RetrievedContext | `ranker.py:35,45,58` + 3 backend | `build_context_summary` → str | `score`, `backend`; `text` gộp vào chuỗi | `workflow.context_summary`, `generation.input.context_sources` | `report.workflow.context_summary` |
| 7 | Workflow generation method | `get_generator` `base.py:18-31` | `generate()` → Workflow | generator version, prompt template version, config snapshot | `report.provider`, `workflow.provider`, `evidence.generation.provider`, `generation.output` | report.json |
| 8 | checkpoint_id | T5: `t5.py:276-309` ← `models.yaml:23-26`; rule_based = null | `Workflow.checkpoint_id` → `EvidenceBundle.checkpoint_id` `run.py:85` | — (giá trị null với rule_based) | `workflow.checkpoint_id`, `evidence.checkpoint_id` | report.json (cả hai `null`) |
| 9 | Execution action/plan | `planner.py:7-23` → 5 PlanStep; `executor.py:21-31` chọn action | log string `executor.py:115` | `selected_action` dạng structured; stdout/stderr | `report.plan`, `execution.log`, `evidence.plan` | reporter/audit |
| 10 | Validator result | `labctl.py:109-139` (`V2A_VALIDATION_JSON:`) | `executor.py:39-50` parse → `validator.py:26-37` verdict | raw stdout/stderr (`command_outputs={}`) | `execution.validation`, `result.evidence.validation`, `evidence.validation_result` | report.json |
| 11 | EvidenceBundle | `collector.py:16` | `add_*` methods, `bundle()` `:42-43` | `command_outputs`, `http` rỗng | `report.evidence` (9 keys) | report.json |
| 12 | report.json / report.md | `reporter.py:28-52` | `PipelineResult.to_dict()` `run.py:32-33` | — | `results/t5-demo-cve-001/` | consumer bên ngoài |

## 4. Confirmed data-loss points

1. **`generation/prompts.py:6-7`**: `"\n".join(f"[{item.source}] {item.text}" ...)` — bỏ `score` và `backend`, gộp `text` vào chuỗi. Đây là điểm mất provenance retrieval lớn nhất.
2. **`pipeline/run.py:76`**: `"context_sources": [context.source for context in outcome.contexts]` — giữ mỗi `source`, không giữ object `RetrievedContext`.
3. **`reproduction/executor.py:171-179`**: `subprocess.run(..., capture_output=True)` lấy stdout/stderr nhưng chỉ ghi argv + `exit=` vào `log` (`:170,179`); raw output bị discard. `labctl.py:103` in `lab up: vulnerable=127.0.0.1:18001 patched=...` — thông tin cổng này **không có trong report**.
4. **`evidence/collector.py:18-22`** định nghĩa `add_command_output` / `add_http_metadata`, nhưng grep toàn repo cho thấy **không có caller nào** ngoài định nghĩa → `command_outputs={}`, `http=[]` trong artifact.
5. **`reproduction/executor.py:115`**: selected action chỉ tồn tại dưới dạng chuỗi log `[workflow] step lab-up selected allowlisted action validate`, không có field structured.
6. **`run.py:78-80`**: lưu `CapecMapping` (method/score/ranked) nhưng không lưu nguồn catalog (XML snapshot path/version).
7. **Không có commit hash / image digest / corpus hash bên trong report.json** (parse: token `commit`=0, `image`=0, `sha256`=0). `artifacts/demo/cve-001/manifest.json` có `repository_commit` và SHA-256 của 15 file, nhưng đó là integrity của artifact package, **không liên kết cryptographic với report nội dung nguồn tri thức**.

## 5. Current evidence capability

| Tiêu chí | Đánh giá | Bằng chứng trong artifact |
|---|---|---|
| **Execution reproducibility** | **Trung bình → tốt** | `plan` đầy đủ 5 step + target=localhost; `execution.log` có argv (`python .../labctl.py up/validate/down`) + exit=0; `validation` có checks/health. Thiếu: stdout thô, image digest, working dir, interpreter version. |
| **Retrieval provenance** | **Kém** | `context_sources` 3 ID + text trong `context_summary`; **không có backend/score/kind/source URL**. CAPEC mapping có score nhưng là score xếp hạng CAPEC, không phải retrieval score. |
| **Model provenance** | **Kém** | `provider="rule_based"`; `checkpoint_id=null`. Không có generator version, prompt version, decoding config, mapping catalog version. |
| **Evidence integrity** | **Trung bình** | `collected_at`, `result.timestamp`, 15 hash trong manifest; nhưng không có signature, không có commit hash trong JSON, không liên kết corpus/checkpoint. |
| **SIMULATED vs PASS** | **Rõ ràng** | `execution.simulated=false`, `result.status="PASS"`; enum `ReproductionStatus` có `SIMULATED` (`workflow.py:38-43`). Validator `PASS` nghĩa là fixed marker counterfactual (`labctl.py:123-128`), **không phải T5-generated payload**. |

**Tái dựng workflow**: có thể **tái tạo snapshot** từ `evidence.workflow` / `evidence.generation.output` (đều là dict đầy đủ). Không thể **tái sinh** (re-run deterministic) vì thiếu backend, score, corpus snapshot, prompt/config version.

## 6. Missing provenance

- Retrieval: backend name, per-context score, per-context backend label, document `kind`/`source` URL, corpus snapshot identity.
- Generation: generator version, prompt/template version, `T5ProviderSettings` snapshot (`models.yaml` values), checkpoint path **thực tế đã load**, seed/device.
- CAPEC: catalog snapshot identity (chỉ có `method` và `score`).
- Execution: structured `selected_action`, raw validator stdout/stderr (hoặc hash của nó), image/container digest, interpreter version.
- Repository: commit hash inside report (hiện chỉ có trong manifest artifact).

Không suy đoán: **không có bằng chứng source** cho việc lưu bất kỳ trường nào ở trên vào artifact hiện tại.

## 7. Minimal schema proposal (chỉ đề xuất)

Nguyên tắc: thêm ít trường nhất, nhóm 3 trace, mỗi trường có consumer rõ ràng.

### 7.1 `RetrievalTrace` (đặt trong `evidence.generation.retrieval`)
| Trường | Ý nghĩa | Nguồn | Thời điểm tạo | Consumer | Backward-compat |
|---|---|---|---|---|---|
| `backend` | tên backend thực tế (`keyword`/`tfidf`/`semantic`, kể cả fallback) | `RetrievalBackend.name`, `get_backend` | `build_contexts_for_cve` | audit retrieval | thêm key mới vào dict `generation` (dict[str,Any]) → **an toàn** cho `EvidenceBundle` cũ |
| `items[].source` | doc_id / CWE id / reference URL | `RetrievedContext.source` | khi tạo context | truy nguồn tri thức | đã có dưới dạng `context_sources`; chỉ chuẩn hoá |
| `items[].score` | điểm retrieval thực tế | `RetrievedContext.score` | khi rank | giải thích thứ tự ưu tiên | **mới**, strict reader cũ chỉ đọc dict `Any` → không vỡ |
| `items[].backend` | nhãn context (`record-cwe`, `cwe-lookup`, `reference-metadata`, tên backend) | `RetrievedContext.backend` | khi tạo context | phân biệt synthesis vs retrieval | mới |

Không thêm `text`: đã có trong `Workflow.context_summary`. Không thêm `kind`/`source` URL nếu chấp nhận `source` string là đủ định danh.

### 7.2 `GenerationTrace` (trong `evidence.generation`)
| Trường | Ý nghĩa | Nguồn | Thời điểm tạo | Consumer | Backward-compat |
|---|---|---|---|---|---|
| `provider` | đã có | `get_generator` | `analyze_cve` | phân biệt rule_based/T5 | hiện tại |
| `checkpoint_id` | đã có nhưng null với rule_based | `flow.checkpoint` → `workflow.checkpoint_id` | T5 generate | model provenance | **đã thêm ở working tree**; baseline reader `extra="forbid"` sẽ reject |
| `config_hash` | hash của `models.yaml` provider config | `T5ProviderSettings.model_dump_json()` / `models.yaml` | khi khởi tạo generator | tái sinh decoding | mới; dict `Any` nên an toàn |
| `prompt_version` | phiên bản template/prompt construction | `prompts.py`/`t5.build_model_input` (cần định nghĩa hằng số) | khi render | so sánh kết quả | mới |

Không thêm full config object — hash là đủ cho reproducibility.

### 7.3 `ExecutionTrace` (trong `evidence`)
| Trường | Ý nghĩa | Nguồn | Thời điểm tạo | Consumer | Backward-compat |
|---|---|---|---|---|---|
| `selected_action` | action name được chọn (`validate`) | `select_validation_command` `executor.py:21-31` | trước `_execute_real` | audit allowlist | **phải thêm vào `EvidenceBundle`** → strict reader cũ reject |
| `validator_stdout_sha256` | hash raw stdout validator | `subprocess.run(...).stdout` | trong `_run` | integrity mà không lưu log lớn | thêm vào `EvidenceBundle` → rủi ro như trên |
| `lab_manifest_sha256` | hash `lab.yaml` đã dùng | `load_lab_manifest` | `run.py:54` | pinned environment | thêm vào `EvidenceBundle` → rủi ro như trên |

Không thêm container IDs/image digests khi chạy simulated (không có) — chỉ thêm nếu `simulated=false` và thực sự thu được.

## 8. Backward compatibility risks

1. **`extra="forbid"` ở mọi contract**: `EvidenceBundle` (`domain/evidence.py:17`), `Workflow` (`domain/workflow.py:28`), `PipelineResult` (`pipeline/run.py:22`), `CapecMapping` (`capec.py:88`), `CorpusFile` (`corpus.py:27`). Reader dùng model cũ parse JSON mới có field mới → `ValidationError`. Đây là rủi ro thực tế, không giả định.
2. **Chính `checkpoint_id` là minh chứng**: field này chỉ có trong working tree. Consumer chạy code baseline `4283360` sẽ **reject** `report.json` hiện tại khi parse vào `EvidenceBundle`/`Workflow`.
3. **`report.json` top-level** do `PipelineResult.to_dict()` sinh; thêm top-level key cũng bị `extra="forbid"` chặn nếu consumer parse bằng `PipelineResult`.
4. **`evidence.generation` là `dict[str, Any]`** (`domain/evidence.py:22`) — nhóm RetrievalTrace/GenerationTrace vào đây ít rủi ro nhất; không cần đổi Pydantic model.
5. **Strict external consumers chưa được kiểm tra** — không thể khẳng định an toàn với bên ngoài repo (NOT VERIFIED).

## 9. Prioritized recommendations

- **P0 —Retrieval provenance**: ghi `backend` + `items[].source/score/backend` vào `evidence.generation.retrieval` (dict `Any`, không đổi schema cứng). Đây là lỗ hổng lớn nhất: hiện tại không trả lời được "tri thức này từ đâu".
- **P0 — Model provenance**: với T5, đảm bảo `checkpoint_id` là checkpoint **thực tế load** (hiện `T5Generator.__init__` lưu `base_checkpoint` khi `checkpoint=""` — `t5.py:214-216`), và lưu `config_hash`; với rule_based ghi rõ "no model".
- **P1 — Execution trace**: đưa `selected_action` thành field structured; lưu `validator_stdout_sha256` thay vì toàn bộ stdout.
- **P1 — Pin environment**: ghi commit hash + `lab_manifest_sha256` vào evidence (manifest artifact đã có commit nhưng rời rạc).
- **P2 — Không refactor domain model chỉ vì graph degree**; chỉ đổi `EvidenceBundle` khi đã có kế hoạch migrate strict consumers.

## 10. NOT VERIFIED items

- Consumer bên ngoài repo có parse `report.json` bằng `EvidenceBundle`/`Workflow` strict model hay không.
- Có artifact nào khác (ngoài `results/t5-demo-cve-001` và `artifacts/demo/cve-001`) lưu retrieval score/backend không — không tìm thấy trong repo, không khẳng định tuyệt đối.
- Nội dung 33 file không đại diện trong graph (23 `.ipynb`, v.v.) có chứa provenance bổ sung không.
- Không chạy test/Docker theo yêu cầu; mọi kết luận đều từ đọc source + parse artifact.

## 11. Kết luận

**Evidence hiện tại chứng minh được**: CVE identity, generation provider (tên), CAPEC mapping kèm method/score/ranked, workflow snapshot đầy đủ, execution plan + argv + exit codes, validator counterfactual PASS, và timestamp/hash của artifact package. Nó phân biệt rõ `simulated=false` và `status=PASS`.

**Không chứng minh được**: retrieval backend đã dùng, retrieval score, document kind/source URL, generator version/prompt/config/checkpoint thực tế (với rule_based là null), nguồn catalog CAPEC, raw validator output, và liên kết cryptographic giữa verdict với corpus/model đã dùng. SHA-256 trong manifest chỉ chứng minh file không đổi kể từ lúc đóng gói — **không phải provenance đầy đủ**.

**Thay đổi thực sự cần thiết**: (1) lưu retrieval trace vào `evidence.generation.retrieval`, (2) lưu generator/checkpoint identity có hiệu lực, (3) structured `selected_action` + pin lab manifest/commit. Tất cả nên đi qua dict `Any` trước khi cân nhắc sửa `EvidenceBundle` vì `extra="forbid"`. Không có thay đổi nào được thực hiện trong audit này.
