# PHASE 4 — Provenance Schema Design & Compatibility Review

- Repository: `Vuln2Action-Lab`, branch `dev`, HEAD `4283360`
- Batch: READ-ONLY. Không sửa source/test/schema/README/config; không chạy test/Docker; không Kaggle; không commit/push.
- Đọc trực tiếp: `reports/execution/final-evidence-provenance-audit.md`, `domain/{evidence,workflow,knowledge}.py`, `generation/{prompts,t5}.py`, `retrieval/{base,ranker,corpus,keyword,tfidf,semantic}.py`, `reproduction/executor.py`, `pipeline/run.py`, `evidence/reporter.py`, `cli.py`, `api/routes/{results,analysis,cve,reproduction}.py`, `config/{settings,models}.yaml`, `pyproject.toml`.

> Mọi đánh giá compatibility below là **suy luận từ source**, chưa được test chứng minh trong batch này. Không phương án nào được tuyên bố "an toàn" ở đây.

## 1. Current schema inventory

| Contract | File : line | `extra` | Trường liên quan provenance |
|---|---|---|---|
| `EvidenceBundle` | `domain/evidence.py:16-26` | `forbid` | `collected_at`, `generation: dict[str,Any]`, `workflow: dict`, `plan: dict`, `checkpoint_id`, `validation_result`, `command_outputs`, `http` |
| `Workflow` | `domain/workflow.py:27-35` | `forbid` | `provider`, `context_summary`, `lab_id`, `checkpoint_id` |
| `ReproductionResult` | `domain/workflow.py:46-54` | `forbid` | `status`, `steps_executed`, `evidence`, `timestamp` |
| `RetrievedContext` | `domain/knowledge.py:101-106` | `forbid` | `source`, `text`, `score`, `backend` |
| `KnowledgeDocument` | `domain/knowledge.py:109-125` | `forbid` | `doc_id`, `text`, `kind`, `name`, `source` |
| `ExecutionResult` | `domain/execution.py:24-31` | `forbid` | `simulated`, `completed`, `log`, `steps_executed`, `error`, `validation` |
| `PipelineResult` | `pipeline/run.py:21-33` | `forbid` | top-level report keys |
| `CapecMapping` / `CorpusFile` | `retrieval/capec.py:85-94`, `corpus.py:26-31` | `forbid` | `score`, `method`, `documents` |
| Report writer | `evidence/reporter.py:28-52` | — | ghi `report.json` (raw dict) + `report.md` (4 dòng) |
| CLI consumer | `cli.py:64-73` | — | `json.dumps(payload)` raw; `--save` gọi `save_report` |
| API consumer | `api/routes/results.py:15-26` | — | `read_json` trả raw dict; **không** parse bằng Pydantic |

Điểm mấu chốt: `generation`, `workflow`, `plan`, `validation_result` là `dict[str,Any]` — có thể chứa trace mới **mà không đổi model Pydantic**. Ngược lại, thêm field trực tiếp vào `EvidenceBundle`/`Workflow`/`PipelineResult` sẽ bị `extra="forbid"` chặn với reader cũ.

Scope note: `checkpoint_id` là thay đổi **chưa commit** trong working tree; baseline `4283360` reject artifact hiện tại nếu parse bằng `EvidenceBundle` baseline. Đây là bằng chứng thực tế về rủi ro tương thích.

## 2. Three proposed schemas (minimal)

Quy ước: `null` nghĩa "không có giá trị" (ví dụ rule_based không có checkpoint); `"NOT_AVAILABLE"` nghĩa "hệ thống hiện tại không cung cấp nguồn dữ liệu" — **không tự tạo giá trị**. Hash chỉ là định danh byte, **không phải tuyên bố tin cậy**.

### 2.1 `RetrievalTrace`

```json
{
  "schema_version": 1,
  "backend": "semantic",
  "query_fingerprint": "sha256:<hex>",
  "items": [
    {
      "rank": 1,
      "document_id": "CWE-79",
      "document_kind": "cwe",
      "source": "CWE-79",
      "source_url": null,
      "retrieval_score": 1.0,
      "context_backend": "record-cwe"
    }
  ]
}
```

| Trường | Meaning | Nguồn | Null/NA rule |
|---|---|---|---|
| `schema_version` | phiên bản trace | hằng số mới (cần phê duyệt) | bắt buộc |
| `backend` | backend được `get_backend` chọn | `RetrievalBackend.name` (`base.py:13,28-38`) | `NOT_AVAILABLE` nếu không capture được (hiện tại) |
| `query_fingerprint` | định danh query, không lưu text nhạy cảm | sha256 của `cve.description` (`ranker.py:55`) | `null` nếu không có query |
| `items[].rank` | vị trí sau dedupe/sort | index trong kết quả `rank_contexts` (`ranker.py:11-17`) | bắt buộc |
| `items[].document_id` | ID tài liệu truy vấn được | `KnowledgeDocument.doc_id` / `RetrievedContext.source` | `null` nếu context không có doc |
| `items[].document_kind` | `cwe`/`capec`/khác | `KnowledgeDocument.kind` (`knowledge.py:115`) | `NOT_AVAILABLE` cho `cwe-lookup`, `reference-metadata` (không có document object) |
| `items[].source` | định danh context | `RetrievedContext.source` (`knowledge.py:103`) | bắt buộc |
| `items[].source_url` | URL MITRE nếu có | `KnowledgeDocument.source` (`corpus.py:45,55`) | `null`/`NOT_AVAILABLE` cho synthesized context |
| `items[].retrieval_score` | điểm thực tế | `RetrievedContext.score` | `NOT_AVAILABLE` nếu backend không trả score |
| `items[].context_backend` | nhãn context (`record-cwe`, `cwe-lookup`, `reference-metadata`, backend name) | `RetrievedContext.backend` | `NOT_AVAILABLE` nếu default không rõ nguồn |

Không thêm `text` (đã có trong `Workflow.context_summary`). Không thêm timestamp riêng (dùng `EvidenceBundle.collected_at`).

### 2.2 `GenerationTrace`

```json
{
  "schema_version": 1,
  "provider": "rule_based",
  "generation_mode": "rule_based",
  "generator_version": "NOT_AVAILABLE",
  "prompt_version": "NOT_AVAILABLE",
  "generation_config": null,
  "generation_config_hash": null,
  "checkpoint_id": null,
  "model_identity": "NOT_AVAILABLE"
}
```

| Trường | Meaning | Nguồn | Null/NA rule |
|---|---|---|---|
| `provider` | tên provider đã dùng | `get_generator` (`generation/base.py:18-31`) | bắt buộc |
| `generation_mode` | `rule_based`/`t5`/`llm` | cùng `provider` | `llm` là stub (`llm.py:10-12`) — không tuyên bố chạy được |
| `generator_version` | phiên bản package | `pyproject.toml:7` (`0.2.0`) — **chưa được emit** | `NOT_AVAILABLE` cho đến khi có code emit |
| `prompt_version` / prompt hash | định danh template | chưa có hằng số nào (`prompts.py`, `t5.py:55-67`) | `NOT_AVAILABLE` |
| `generation_config` | config thực tế dùng | `T5ProviderSettings` (`config.py:44-73`, `models.yaml`) hoặc rule_based config | `null` nếu không có config object |
| `generation_config_hash` | hash của config serialized | tính từ config ở trên | `null` nếu config null |
| `checkpoint_id` | checkpoint **thực tế load** | `T5Generator.checkpoint` (`t5.py:214-216`) | `null` cho rule_based |
| `model_identity` | định danh model/checkpoint | `self.checkpoint`; không có resolved digest | `NOT_AVAILABLE` cho rule_based và khi chưa capture |

### 2.3 `ExecutionTrace`

```json
{
  "schema_version": 1,
  "execution_mode": "real",
  "selected_action": {"step_id": "lab-up", "action": "validate"},
  "plan_snapshot": {"steps": 5, "lab_id": "cve-001"},
  "argv": ["python", "validation/labctl.py", "validate"],
  "exit_code": 0,
  "stdout_ref": null,
  "stderr_ref": null,
  "lab_manifest_sha256": null,
  "repository_commit": null,
  "container_image_digest": "NOT_AVAILABLE"
}
```

| Trường | Meaning | Nguồn | Null/NA rule |
|---|---|---|---|
| `execution_mode` | `simulated`/`real` | `ExecutionResult.simulated` (`executor.py:81-89,141`) | bắt buộc |
| `selected_action` | action được chọn, structured | `select_validation_command` (`executor.py:21-31`) | `null` nếu không có step khớp (fallback `validation_command`) |
| `plan_snapshot` | bản sao plan đã thực thi | `ExecutionPlan` (`planner.py:7-23`) | bắt buộc |
| `argv` / `exit_code` | lệnh thực tế | `executor.py:165-179` | hiện chỉ có dạng chuỗi trong `log` |
| `stdout_ref` / `stderr_ref` | reference tới artifact riêng | `subprocess.CompletedProcess.stdout/stderr` (`executor.py:171-178`) | `null` khi simulated hoặc chưa capture |
| `lab_manifest_sha256` | hash `lab.yaml` | file đọc bởi `load_lab_manifest` | `null` nếu chưa capture (hiện tại) |
| `repository_commit` | git HEAD lúc chạy | `git rev-parse HEAD` — **chưa được gọi ở runtime** | `null` nếu chưa capture |
| `container_image_digest` | digest image nếu có | executor **không inspect image** | `NOT_AVAILABLE` |

Hash ở đây dùng để **định danh/so khớp artifact**, không để khẳng định verdict đúng hay nguồn tri thức đáng tin.

## 3. Dataflow mapping

| Trường | Điểm hiện có dữ liệu | Điểm mất | Capture point đề xuất | Consumer | Tái tạo được? |
|---|---|---|---|---|---|
| `backend` | `base.py:25-44` | `run.py:70-82` không ghi | `analyze_cve` (`analyze.py:63-64`) nơi biết backend đã chọn | audit retrieval | Không — config chỉ cho	default, không cho backend thực tế sau alias/fallback |
| `query_fingerprint` | `cve.description` | `prompts.py:6-7` | `build_contexts_for_cve` (`ranker.py:55`) | audit | Có nếu còn CVE description |
| `document_id/source` | `KnowledgeDocument` (`corpus.py:39-56`) | `run.py:76` chỉ giữ `.source` | `ranker.py:31-52` (có cả `by_id`) | truy nguồn tri thức | Một phần — reference context không có document |
| `retrieval_score` | backend `.search`, `ranker.py:38,49,62` | `prompts.py:6-7` | sau `rank_contexts` (`ranker.py:66`) | giải thích xếp hạng | Không sau khi đã render thành chuỗi |
| `rank` | thứ tự `rank_contexts` | không lưu thứ tự | `ranker.py:66` | audit | Có từ thứ tự hiện tại |
| `provider/mode` | `get_generator` | đã lưu ở 3 nơi | không cần thay đổi | phân biệt rule/T5 | Có |
| `generator_version` | `pyproject.toml:7` | chưa emit | khởi tạo generator hoặc `run.py` | model provenance | Có (đọc file) |
| `prompt_version` | **không tồn tại** | — | cần định nghĩa hằng số mới | so sánh prompt | Không |
| `generation_config` | `T5ProviderSettings`/`models.yaml` | chưa emit | `T5Generator.__init__` / `rule_based` | reproducibility | Có từ config |
| `checkpoint_id` | `t5.py:214-216,298,308` → `run.py:85` | rule_based = null | đã có (working tree) | model identity | Có — **nhưng giá trị là `t5-small` khi config để trống**, không phải checkpoint fine-tuned |
| `selected_action` | `executor.py:21-31,115` | chỉ còn trong log string | `executor.py:108` | allowlist audit | Có bằng parse log (giòn) |
| `argv/exit_code` | `executor.py:165-179` | vẫn có trong log | `_run` return | execution audit | Có từ log |
| `stdout/stderr` | `subprocess.run(...).stdout/stderr` | discard sau `parse_validation_output` | `executor.py:124-126` | integrity/chẩn đoán | Không |
| `lab_manifest_sha256` | `lab.yaml` trên disk | chưa hash | `load_lab_manifest` | pin môi trường | Có |
| `repository_commit` | git repo | chưa lấy lúc runtime | `cli.py:44` / `api` entry | pin code version | Có |
| `image_digest` | Docker daemon (ngoài phạm vi batch) | executor không inspect | — | — | **Không với implementation hiện tại** |

## 4. Compatibility matrix

| Option | Backward | Forward | `extra="forbid"` | CLI/API | JSON serialization | Artifact cũ | Migration | Verified? |
|---|---|---|---|---|---|---|---|---|
| **A. Thêm field vào `EvidenceBundle`** | Kém: reader baseline reject field mới | Tốt nếu reader mới update | Phá vỡ trực tiếp (`evidence.py:17`) | CLI in raw dict → vẫn in được; API trả raw dict → vẫn trả; nhưng parse nội bộ vào model cũ lỗi | Pydantic serialize field mới bình thường | Old artifact vẫn đọc được bởi reader mới nếu field có default | Cần deploy reader trước khi ghi field | **CHƯA TEST** |
| **B. Report envelope + `schema_version`** | Kém nếu thêm top-level: `PipelineResult` (`run.py:22`) reject; ổn nếu đặt trong `generation: dict` | Tốt (versioned) | Tránh được nếu nằm trong dict `Any` | CLI (`cli.py:65`) và API (`results.py:23-26`) trả raw dict → không validate | Trực tiếp | Old artifact không có envelope → reader phải xử lý thiếu | Reader branch theo version | **CHƯA TEST** |
| **C. Object provenance riêng + reference** | Tốt nhất nếu reference nằm trong `generation` dict (không đổi model); kém nếu thêm `EvidenceBundle.provenance_ref` | Tốt (file riêng versioned) | Tránh được với reference trong dict | CLI/API không đổi nếu report.json giữ nguyên | Cần ghi file thứ 3 trong `reporter.py` | Old artifact thiếu reference → null | Cần atomic write + backward fallback | **CHƯA TEST** |
| **D. Legacy export cho consumer cũ** | Tốt trong giai đoạn chuyển tiếp | Kém (duplicated schema) | Không giải quyết gốc | Cần route/flag chọn bản | Hai payload phải đồng bộ | Có thể tạo legacy từ artifact cũ | Tốn công maintain, cần sunset plan | **CHƯA TEST** |

Nhận xét: phương án **C với reference đặt trong `evidence.generation`** (`dict[str,Any]`) tránh sửa `EvidenceBundle`, `Workflow`, `PipelineResult`; nhưng vẫn cần thay `reporter.py` để ghi file đi kèm và cần test atomicity. Đây là **đề xuất**, không phải kết luận an toàn.

## 5. Test plan (không chạy trong batch này)

| Test | Hành vi đề xuất | Assertions tối thiểu |
|---|---|---|
| Old artifact → new reader | Parse `results/t5-demo-cve-001/report.json` bằng reader có trace | Không `ValidationError`; trace fields = `null`/`NOT_AVAILABLE`; verdict vẫn `PASS` |
| New artifact → old strict reader | Serialize report có field mới, parse bằng `EvidenceBundle`/`Workflow`/`PipelineResult` baseline | Ghi nhận `ValidationError` nếu field nằm trong model strict — chứng minh rủi ro, không giả định an toàn |
| Missing optional metadata | Context thiếu `kind`/`source_url`/score | Không crash; giá trị `NOT_AVAILABLE`; `context_summary` vẫn render |
| Rule-based provider | Chạy cấu hình `rule_based` (không Docker) | `generation_mode="rule_based"`, `checkpoint_id=null`, `model_identity="NOT_AVAILABLE"` |
| T5 with real checkpoint | Chỉ khi có checkpoint được cấu hình rõ trong `models.yaml` | `checkpoint_id` bằng checkpoint thực tế đã load; **không** chấp nhận `t5-small` fallback như bằng chứng T5 chạy thật |
| Retrieval backend có score | Với `keyword`, `tfidf`, `semantic` | `trace.backend` đúng alias; `items[].score >= 0`; `rank` liên tục từ 1 |
| Execution stdout/stderr | Fake `CompletedProcess` hoặc run lab-scoped có kiểm soát | artifact reference tồn tại; hash khớp nội dung; `selected_action` structured đúng `validate` |
| Hash mismatch | Thay 1 byte file provenance | Verifier báo mismatch; **không** suy ra verdict sai hay nguồn không tin cậy |
| Report serialization CLI/API | `cli.py --json-only --save`, `GET /results/{run_id}` | JSON parse được; reference có mặt; API không 500 |

## 6. Migration strategy

1. **Phase 0 (design approval)**: chọn option C (provenance file + reference trong `generation` dict). Không sửa `EvidenceBundle`.
2. **Phase 1 (additive, opt-in)**: writer ghi thêm `provenance.json`; reader mới đọc nếu có, nếu không thì dùng `null`. Giữ `report.json` shape cũ.
3. **Phase 2 (dual-run)**: sinh cả bản cũ và bản có reference; so sánh verdict bằng test.
4. **Phase 3 (consumer upgrade)**: chỉ sau khi test old/new strict reader chạy xanh, mới cân nhắc đưa field vào `EvidenceBundle` với default.
5. **Phase 4 (sunset)**: bỏ legacy export nếu không còn consumer (cần xác nhận bằng inventory — hiện chưa có).

Không bước nào được thực hiện trong batch này.

## 7. Metadata không thể chứng minh bằng implementation hiện tại

- **T5 chạy với checkpoint fine-tuned**: thư mục `models/t5-capec-flows/` tồn tại (có `model.safetensors`, `config.json`), nhưng `config/models.yaml:26` để `checkpoint: ""` → `T5Generator` fallback `t5-small` (`t5.py:214-216`). Không có bằng chứng thực thi T5 trong batch này; không tuyên bố T5 hoạt động.
- **generator_version / prompt_version**: package có `0.2.0` trong `pyproject.toml:7` nhưng không emit; không có hằng số prompt version trong `prompts.py`/`t5.py`.
- **repository_commit trong report**: git có HEAD, nhưng runtime pipeline không gọi; manifest artifact có commit — không phải cùng scope.
- **container image digest**: executor chỉ gọi subprocess labctl; không inspect image. Local image có thể không có `RepoDigests`.
- **raw stdout/stderr**: bị discard (`executor.py:171-178`); không thể tái dựng sau fact.
- **document_kind/source_url cho context tổng hợp**: `cwe-lookup`/`reference-metadata` không đi qua `KnowledgeDocument` (`ranker.py:43-65`).
- **Trust/reliability của nguồn tri thức**: không có cơ chế nào trong source; SHA-256 chỉ là byte integrity.

## 8. Recommendation cuối cùng và quyết định cần xin phép

**Khuyến nghị**: Option C — file `provenance.json` riêng, reference đặt trong `evidence.generation` (dict `Any`), giữ nguyên `report.json` shape hiện tại. Đây là phương án ít rủi ro nhất **theo suy luận source**, nhưng phải chạy test ở mục 5 trước khi tuyên bố tương thích.

Cần phê duyệt riêng trước khi code:
1. Cho phép sửa `evidence/reporter.py` để ghi file thứ 3 và đảm bảo ghi atomic.
2. Cho phép định nghĩa hằng số `prompt_version` / `schema_version` (code mới, không phải dữ liệu giả).
3. Quyết định có thêm `generator_version` từ `pyproject.toml` hay không (đụng `importlib.metadata`).
4. Quyết định có lưu commit hash runtime vào report hay chỉ giữ trong artifact manifest.
5. Quyết định có capture stdout/stderr (dung lượng, quyền riêng tư) hay chỉ lưu reference/hash.
6. Xác nhận không có strict external consumer — hiện **NOT VERIFIED**.
7. Nếu muốn dùng T5 làm bằng chứng: cung cấp checkpoint được cấu hình rõ + bằng chứng chạy thực tế; không dùng artifact `rule_based` hiện tại.

Không thực hiện refactor vì Graphify God Node; mọi đề xuất trên đều bắt nguồn từ data-loss points đã đọc source.
