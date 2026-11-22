# PHASE 5A — Provenance Sidecar Compatibility Tests

- Repository: `Vuln2Action-Lab`, branch `dev`, HEAD `4283360`
- Batch: TEST-ONLY. Không implement, không sửa source/schema/test/config/README, không đụng artifact hiện có, không Docker/Kaggle, không commit/push.
- Artifact nguồn (chỉ đọc): `results/t5-demo-cve-001/report.json`
- Reader baseline: lấy trực tiếp từ `git show 4283360:...`, load bằng `importlib.util.spec_from_file_location` trong thư mục temp riêng.
- Reader current: `src/vuln2action/domain/{evidence,workflow}.py` trong working tree.
- Thư mục test: `C:\Users\HOANGM~1\AppData\Local\Temp\opencode\prov-compat-7abf2f18fca640d2ba06578b030f31cd` — **đã tạo và đã dọn** sau khi chạy (chỉ các file do batch này tạo).

## Setup & commands (chính xác)

```powershell
$repo = (Get-Location).Path
$tmp  = 'C:\Users\HOANGM~1\AppData\Local\Temp\opencode\prov-compat-7abf2f18fca640d2ba06578b030f31cd'
git -C $repo show 4283360:src/vuln2action/domain/evidence.py | Out-File -FilePath "$tmp\baseline\evidence.py" -Encoding ascii
git -C $repo show 4283360:src/vuln2action/domain/workflow.py | Out-File -FilePath "$tmp\baseline\workflow.py" -Encoding ascii
```

Lần chạy đầu (không set encoding) bị lỗi console giống demo trước:

```
UnicodeEncodeError: 'charmap' codec can't encode character '\u1ead' in position 300: character maps to <undefined>
```

Lần chạy hợp lệ (dùng Python có pydantic 2.14.1; graphify env không có pydantic nên không dùng):

```powershell
$env:PYTHONIOENCODING = 'utf-8'
& "C:\Program Files\Python313\python.exe" "$tmp\run_tests.py" "$tmp" "$repo"
```

Output header (để chứng minh reader nào được dùng):

```
BASELINE_EVIDENCE_EXTRA_FORBID forbid
CURRENT_EVIDENCE_EXTRA_FORBID forbid
BASELINE_GENERATION_FIELD_TYPE dict[str, typing.Any] | None
CURRENT_GENERATION_FIELD_TYPE dict[str, typing.Any] | None
```

**Hạn chế setup quan trọng**: "artifact được tạo từ baseline" trong test 1 là artifact hiện tại **đã xoá field `checkpoint_id`** khỏi `evidence` và `workflow` để khớp shape baseline — không phải artifact do chạy pipeline baseline tạo ra. Baseline reader cũng chỉ là `EvidenceBundle`/`Workflow`, không phải full `PipelineResult`.

## Test results

### Test 1 — Baseline reader đọc artifact baseline-shaped

- **Setup**: `EvidenceBundle`/`Workflow` từ `git show 4283360`; artifact = bản copy của report.json với `checkpoint_id` bị xoá khỏi `evidence` và `workflow`.
- **Command**: harness chung ở trên, case 1.
- **Expected**: ACCEPT.
- **Actual**: `baseline EvidenceBundle parsed (8 fields); baseline Workflow parsed (5 steps); checkpoint_id absent`.
- **Status**: **PASS**.

### Test 2 — Baseline reader đọc artifact có `checkpoint_id`

- **Setup**: baseline reader + report.json hiện tại (giữ `checkpoint_id`).
- **Command**: harness, case 2.
- **Expected**: REJECT với `ValidationError`.
- **Actual**:
  ```
  ValidationError: 1 validation error for EvidenceBundle | checkpoint_id |
    Extra inputs are not permitted [type=extra_forbidden, input_value=None, input_type=NoneType]
  ```
- **Status**: **PASS** (quan sát đúng rejection). Giá trị `null` vẫn bị reject vì **key hiện diện**, không phải vì giá trị.

### Test 3 — Current reader đọc artifact cũ (không `checkpoint_id`)

- **Setup**: current `EvidenceBundle`/`Workflow`; artifact đã xoá `checkpoint_id`.
- **Expected**: ACCEPT, `checkpoint_id=None`.
- **Actual**: `current EvidenceBundle parsed; checkpoint_id=None; Workflow.checkpoint_id=None`.
- **Status**: **PASS**.

### Test 4 — Current reader đọc artifact hiện tại

- **Setup**: current reader + report.json nguyên vẹn.
- **Expected**: ACCEPT.
- **Actual**: `current reader parsed; evidence.checkpoint_id=None; workflow.checkpoint_id=None`.
- **Status**: **PASS**.

### Test 5 — `generation` có nhận `provenance_ref`?

- **Setup**: copy report.json, thêm `evidence.generation.provenance_ref = "provenance.json"`, parse bằng current `EvidenceBundle`.
- **Expected**: ACCEPT vì `generation: dict[str, Any] | None`.
- **Actual**: `accepted; generation keys=['capec', 'capec_note', 'input', 'output', 'provenance_ref', 'provider']; provenance_ref='provenance.json'`.
- **Status**: **PASS**.

### Test 6 — Strict consumer baseline có reject `generation.provenance_ref`?

- **Setup**: baseline `EvidenceBundle`/`Workflow` (cả hai `extra="forbid"`), artifact ở dạng baseline (xoá `checkpoint_id`) + `generation.provenance_ref`.
- **Expected**: KHÔNG reject.
- **Actual**: `baseline strict reader ACCEPTED generation.provenance_ref; extra='forbid' present on EvidenceBundle; generation keys=['capec', 'capec_note', 'input', 'output', 'provenance_ref', 'provider']`.
- **Status**: **PASS**. Lý do: field `generation` là `dict[str,Any]` ngay từ baseline; `extra="forbid"` chỉ áp dụng cho **field của model**, không áp dụng cho key trong dict.

### Test 7 — Artifact không có provenance reference

- **Setup**: current reader + report.json hiện tại (không có `provenance_ref`).
- **Expected**: ACCEPT, ref absent.
- **Actual**: `current reader parsed; generation keys=['capec', 'capec_note', 'input', 'output', 'provider']; provenance_ref present=False`.
- **Status**: **PASS**.

### Test 8 — Artifact tham chiếu `provenance.json` bị thiếu

- **Setup**: thêm `generation.provenance_ref="provenance.json"`; parse bằng current model; sau đó thử mở `results/t5-demo-cve-001/provenance.json` bằng `open()`.
- **Expected**: model chấp nhận; `open()` ném `FileNotFoundError`; không có xử lý trong source.
- **Actual**:
  ```
  model accepted ref='provenance.json'; naive open() raised FileNotFoundError:
  [Errno 2] No such file or directory: '...\results\t5-demo-cve-001\provenance.json';
  no source code reads provenance_ref
  ```
- **Status**: **PASS** (hành vi quan sát đúng: **không có fallback/xử lý thiếu sidecar**). Kiểm chứng thêm: `grep -R "provenance_ref|provenance.json" src/**/*.py` → **0 match**, tức không có reader nào xử lý ref hiện nay.

### Test 9 — JSON serialization bảo toàn trường `generation`

- **Setup**: current `EvidenceBundle.model_validate` với `generation` gốc + `provenance_ref`; `model_dump(mode="json")`; so sánh dict.
- **Expected**: các key cũ (`provider`, `input`, `capec`, `capec_note`, `output`) và ref đều còn.
- **Actual**: `round-trip equal=True; existing fields preserved=True; keys=['capec', 'capec_note', 'input', 'output', 'provenance_ref', 'provider']`.
- **Status**: **PASS**.

## Compatibility matrix (cập nhật bằng thực nghiệm)

| Option | Kết quả thực nghiệm | Kết luận |
|---|---|---|
| **A. Thêm field vào `EvidenceBundle`** | Test 2: baseline reader **reject** `checkpoint_id` (`extra_forbidden`) | **KHÔNG an toàn** với reader baseline nếu deploy writer trước reader |
| **B. Envelope `schema_version` ở top-level** | Chưa test | **NOT TESTED** — chỉ có suy luận từ `PipelineResult extra="forbid"` |
| **C. Sidecar + reference trong `generation` dict** | Test 5/6/7/9: ref được baseline lẫn current reader chấp nhận, serialize round-trip đúng | **Phần reference: VERIFIED**. Phần ghi file/đọc file/atomicity: **NOT TESTED** (chưa có implementation) |
| **D. Legacy export** | Chưa test | **NOT TESTED** |

Bảng tổng hợp 9 test: **9 PASS / 0 FAIL / 0 NOT TESTED** (trong phạm vi setup nêu trên).

## Option C có an toàn để implement không?

**Có điều kiện, mới chỉ an toàn ở phần đã test**: đặt `provenance_ref` inside `evidence.generation` tương thích ngược với baseline strict reader và bảo toàn serialization (test 5,6,7,9). **Chưa đủ bằng chứng** để nói toàn bộ Option C an toàn, vì:

- chưa có writer `provenance.json` trong `reporter.py` (`reporter.py:28-52` chỉ ghi `report.json` + `report.md`);
- chưa có reader/resolver, và test 8 cho thấy ref trỏ tới file thiếu **không được xử lý**;
- atomicity giữa 2 file chưa được test;
- CLI (`cli.py:64-73`) và API (`api/routes/results.py:15-26`) chưa được chạy với artifact có sidecar;
- external strict consumer chưa được inventory.

Không implement trong batch này.

## Remaining blockers

1. Cần test writer/reader sidecar + atomicity + hash mismatch (mục 5 của design report) trước khi code.
2. Cần quyết định xử lý sidecar thiếu: `null`, bỏ qua, hay hard-fail — hiện **không có hành vi nào**.
3. Cần inventory strict external consumer; baseline reject ở test 2 chứng minh rủi ro có thật với consumer dùng model baseline.
4. Full `PipelineResult` baseline chưa được test (chỉ `EvidenceBundle`/`Workflow`).
5. Artifact "baseline" là dẫn xuất từ artifact hiện tại, không phải do chạy baseline pipeline — cần test lại nếu yêu cầu bằng chứng mạnh hơn.
6. T5/checkpoint provenance, commit/image digest không nằm trong phạm vi test này.

## Git status & diff summary (cuối batch)

```
 M src/vuln2action/domain/evidence.py
 M src/vuln2action/domain/workflow.py
 M src/vuln2action/evidence/collector.py
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
```

```
 src/vuln2action/domain/evidence.py    |   1 +
 src/vuln2action/domain/workflow.py    |   1 +
 src/vuln2action/evidence/collector.py |   3 +
 src/vuln2action/generation/t5.py      |   3 +
 src/vuln2action/pipeline/run.py       |   1 +
 tests/integration/test_docker_lab.py  | 106 +++++++++++++++++++++++++++++++++-
 tests/unit/test_executor.py           |  27 +++++++++
 7 files changed, 141 insertions(+), 1 deletion(-)
```

`HEAD = 4283360`. Temp dir của batch đã xoá (`EXISTS_AFTER=False`). Không file source/schema/test/config nào bị thay đổi bởi batch này.
