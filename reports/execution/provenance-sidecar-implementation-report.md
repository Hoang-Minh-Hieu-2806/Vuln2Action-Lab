# PHASE 5B — Provenance Sidecar Implementation Report

- Repository: `Vuln2Action-Lab`, branch `dev`, HEAD `4283360` (không đổi)
- Batch: implementation có phạm vi, READ về artifact hiện có; không Docker/Kaggle, không commit/push/reset/checkout/clean.

## 1. Preflight result

- HEAD đúng `42833606ea5acba221c6289d8439201a59d7921c`, branch `dev`.
- Working tree có sẵn 7 file modified (từ các batch trước) + untracked `artifacts/`, `docs/*`, `reports/`, `tests/unit/test_evidence_provenance.py`. **Không file nào bị revert/ghi đè.**
- `src/vuln2action/evidence/reporter.py` **chưa modified** trước batch — đây là file duy nhất trong source được sửa.
- `pipeline/run.py` đã modified từ trước (dòng `add_checkpoint_id`) — **không đụng vào**.
- Consumer report JSON: `cli.py:64-73` in raw dict; `api/routes/results.py:15-26` trả raw dict qua `read_json` — không parse Pydantic, nên không bị ảnh hưởng bởi key mới trong `generation`.
- Test serialization liên quan: `tests/integration/test_pipeline.py:25-30` (`save_report`) — vẫn pass.
- Không có implementation sidecar nào tồn tại trước batch (`grep provenance_ref` trong `src` = 0). Preflight khớp giả định báo cáo.

## 2. Files changed / created

| File | Trạng thái | Nội dung |
|---|---|---|
| `src/vuln2action/evidence/provenance.py` | **mới** | Contracts + `build_provenance`, `write_provenance`, `read_provenance`, `ProvenanceError` |
| `src/vuln2action/evidence/reporter.py` | modified | Ghi sidecar **trước** report; thêm `provenance_ref` vào `evidence.generation` của payload đã lưu |
| `tests/unit/test_provenance_sidecar.py` | **mới** | 12 requirement / 13 test cases (1 parametrized) |
| `reports/execution/provenance-sidecar-implementation-report.md` | **mới** | Báo cáo này |

**Không sửa** `EvidenceBundle`, `Workflow`, `collector.py`, `pipeline/run.py`, config, README, artifact cũ, `models.yaml`.

## 3. Schema thực tế

Top-level `provenance.json` (6 keys, theo smoke chạy pipeline thật):

```
schema_version, retrieval, generation, execution, environment, integrity
```

- `retrieval`: `{backend, query_fingerprint, items[]}` — item: `rank`, `document_id`, `source`, `document_kind`, `source_url`, `retrieval_score`, `context_backend`.
- `generation`: `{provider, generation_mode, generator_version, prompt_version, generation_config, generation_config_hash, checkpoint_id, model_identity}`.
- `execution`: `{execution_mode, selected_action, plan_snapshot, argv, exit_code, stdout_ref, stderr_ref, lab_manifest_sha256, repository_commit, container_image_digest}`.
- `environment`: `{collected_at, repository_commit, container_image_digest}`.
- `integrity`: `{algorithm: "sha256", content_sha256: <hex>}` — digest của payload **canonical JSON sau khi bỏ `integrity`**.

`provenance_ref` là `"provenance.json"` — relative, không traversal, nằm trong `evidence.generation`. Các key generation cũ (`provider`, `input`, `capec`, `capec_note`, `output`) giữ nguyên giá trị (test 10).

Smoke output thực tế (pipeline rule_based, sample CVE-2024-0001):

```
REPORT_KEYS ['cve_id','evidence','execution','lab','plan','provider','result','workflow']
REF provenance.json
GENERATION_KEYS ['capec','capec_note','input','output','provenance_ref','provider']
SIDECAR_KEYS ['environment','execution','generation','integrity','retrieval','schema_version']
SIDECAR_GENERATION {"provider":"rule_based","generation_mode":"rule_based","generator_version":"NOT_AVAILABLE","prompt_version":"NOT_AVAILABLE","generation_config":null,"generation_config_hash":null,"checkpoint_id":null,"model_identity":"NOT_AVAILABLE"}
SIDECAR_RETRIEVAL backend="NOT_AVAILABLE", items=rank 1..3 từ context_sources (CWE-79, CWE-352, reference:...), mọi score/kind/backend="NOT_AVAILABLE"
SIDECAR_EXECUTION execution_mode="simulated", plan_snapshot={"steps":5,"lab_id":"cve-001"}, phần còn lại null/NOT_AVAILABLE
SIDECAR_ENVIRONMENT collected_at=<ISO>, repository_commit=null, container_image_digest="NOT_AVAILABLE"
```

## 4. Dataflow pipeline → sidecar

```
run_pipeline() -> PipelineResult.to_dict() -> cli.py:72 save_report(payload)
  -> reporter.save_report()
      -> build_provenance(payload)
         evidence.generation.input.context_sources -> retrieval.items (rank + id/source)
         evidence.generation.provider               -> generation.provider / generation_mode
         evidence.checkpoint_id / workflow.checkpoint_id -> generation.checkpoint_id
         evidence.collected_at                      -> environment.collected_at
         payload.execution.simulated                -> execution.execution_mode
         payload.plan                               -> execution.plan_snapshot (steps + lab_id)
      -> write_provenance() -> provenance.json (atomic)
      -> deepcopy(payload); evidence.generation["provenance_ref"]="provenance.json"
      -> write_json(report.json)
```

`run.py`, `collector.py` không đổi; ref chỉ có trong **report đã lưu**, không có trong in-memory `PipelineResult` hay stdout của CLI `--json-only` (CLI in payload trước `save_report`). Đây là compatibility limitation có chủ đích.

## 5. Atomic write behavior

1. `build_provenance(payload)` → `model_dump(mode="json")`.
2. Bỏ key `integrity`, tính SHA-256 trên `json.dumps(..., sort_keys=True, separators=(",", ":"), ensure_ascii=False)`.
3. Gán `integrity.content_sha256`.
4. `tempfile.mkstemp(prefix=".provenance-", suffix=".tmp", dir=run_dir)` — **cùng filesystem**.
5. `json.dump` → `flush()` → `os.fsync()` → `os.replace(temp, provenance.json)`.
6. Chỉ sau khi sidecar tồn tại hợp lệ mới thêm ref và ghi `report.json`.

- Sidecar write fail → `ProvenanceError(code="WRITE_FAILED")`, **không publish report**, temp file bị xoá (test 8).
- Report write fail sau sidecar → `RuntimeError` với chữ `"orphan sidecar"`; sidecar được giữ lại (test 9).
- **Không tuyên bố** hai file được transaction atomic cùng nhau — mỗi file atomic riêng, có cửa sổ sidecar mồ côi.

## 6. Missing / corrupt / hash mismatch

| Tình huống | Hành vi | Code |
|---|---|---|
| Không có `provenance_ref` | `read_provenance()` trả `None` (legacy) | — |
| Ref trỏ file thiếu | `ProvenanceError` | `MISSING` |
| Ref absolute / drive / `..` / ra ngoài run_dir | `ProvenanceError` | `INVALID_REF` |
| File không đọc được | `ProvenanceError` | `UNREADABLE` |
| JSON sai định dạng | `ProvenanceError` | `MALFORMED` |
| Schema không validate | `ProvenanceError` | `INVALID_SCHEMA` |
| Thiếu digest | `ProvenanceError` | `MISSING_DIGEST` |
| Digest không khớp | `ProvenanceError` | `DIGEST_MISMATCH` |

Không có đường nào tự động bỏ qua lỗi để trả về trạng thái "VERIFIED". Hash **chỉ** chứng minh byte-integrity so với digest được lưu; không dùng để khẳng định nguồn tri thức đáng tin, tài liệu đã xác minh, workflow an toàn hay checkpoint chính thống.

## 7. Test commands và kết quả

```powershell
& "C:\Program Files\Python313\python.exe" -m pytest -q tests/unit/test_provenance_sidecar.py
# 13 passed in 0.37s

& "C:\Program Files\Python313\python.exe" -m pytest -q
# 261 passed, 6 skipped in 18.28s

& "C:\Program Files\Python313\python.exe" -m ruff check src api scripts tests evaluation gui
# All checks passed!
```

Coverage theo 12 yêu cầu: sidecar written (1), ref hợp lệ (2), legacy (3), file thiếu (4), traversal (5 + param absolute), malformed (6), hash mismatch (7), sidecar write fail (8), report write fail (9), round-trip generation keys (10), không thêm field vào `EvidenceBundle`/`Workflow` (11), artifact legacy-shaped đọc được sau serialization (12). Đều đi qua `save_report()` / file JSON thật, không chỉ instantiate model. Smoke chạy pipeline thật cũng thành công (mục 3). Không chạy Docker.

## 8. Compatibility limitations

- Phase 5A đã chứng minh `generation.provenance_ref` được baseline strict reader chấp nhận; batch này **không chạy lại** baseline reader. Kết luận tương thích vẫn dựa trên bằng chứng của batch trước + test round-trip hiện tại.
- Chỉ thêm key vào `dict[str,Any]`; `EvidenceBundle`/`Workflow`/`PipelineResult` giữ nguyên field → strict consumer baseline vẫn parse được report có ref (theo Phase 5A).
- External strict consumer chưa inventory — NOT VERIFIED.
- `provenance_ref` không xuất hiện trong CLI stdout/API in-memory; chỉ trong `report.json` đã lưu. Consumer đọc qua `GET /results/{id}` sẽ thấy ref vì route trả raw JSON từ file.
- Sidecar mồ côi (report write fail) không bị dọn — thiết kế có chủ đích, đã ghi rõ trong error message.

## 9. Metadata vẫn NOT_AVAILABLE / null

- `retrieval.backend`, `retrieval.items[].document_kind/source_url/retrieval_score/context_backend`, `query_fingerprint` (không có nguồn trong payload).
- `generation.generator_version`, `prompt_version`, `generation_config(_hash)`, `model_identity`; `checkpoint_id=null` với rule_based. **Không tuyên bố T5 chạy với checkpoint fine-tuned** — `models.yaml:26` để trống, không đụng vào batch này.
- `execution.selected_action`, `argv`, `exit_code`, `stdout_ref`, `stderr_ref`, `lab_manifest_sha256`, `repository_commit`, `container_image_digest`.
- `environment.repository_commit`, `container_image_digest`.
- Các giá trị này được ghi rõ `NOT_AVAILABLE`/`null`, không tự suy diễn từ log hay config.

## Git status & diff summary (cuối batch)

```
 M src/vuln2action/domain/evidence.py
 M src/vuln2action/domain/workflow.py
 M src/vuln2action/evidence/collector.py
 M src/vuln2action/evidence/reporter.py
 M src/vuln2action/generation/t5.py
 M src/vuln2action/pipeline/run.py
 M tests/integration/test_docker_lab.py
 M tests/unit/test_executor.py
?? artifacts/
?? docs/evaluation/
?? docs/human-evaluation/
?? docs/paper-deviation-report-vi.md
?? reports/
?? tests/unit/test_evidence_provenance.py
?? tests/unit/test_provenance_sidecar.py
?? src/vuln2action/evidence/provenance.py
```

```
 src/vuln2action/domain/evidence.py    |   1 +
 src/vuln2action/domain/workflow.py    |   1 +
 src/vuln2action/evidence/collector.py |   3 +
 src/vuln2action/evidence/reporter.py  |  27 ++++++++++++++++++++++-
 src/vuln2action/generation/t5.py      |   3 +
 src/vuln2action/pipeline/run.py       |   1 +
 tests/integration/test_docker_lab.py  | 106 +++++++++++++++++++++++++++++++++-
 tests/unit/test_executor.py           |  27 +++++++++
 8 files changed, 166 insertions(+), 3 deletions(-)
```

`HEAD = 4283360`. File mới (`provenance.py`, `test_provenance_sidecar.py`, báo cáo này) nằm trong untracked paths ở trên; không commit/push.
