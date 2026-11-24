# Báo cáo sai lệch so với paper — DRAFT

Trạng thái: **DRAFT, chưa phải báo cáo cuối**. Ngày: 2026-11-22. HEAD: `4283360`.

Không được trình bày tài liệu này như kết quả tái tạo đầy đủ paper.

## 1. Mục tiêu và phạm vi

Vuln2Action-Lab là đồ án phòng thủ, lấy cảm hứng từ kiến trúc của Vuln2Action
(Kumari & Yadav, JISA 99 (2026) 104420). Mục tiêu là xây pipeline có bằng chứng
trong lab cô lập, không phải sao chép số liệu hay trọng số của paper.

## 2. Paper methodology (tóm tắt)

CVE/CWE/CAPEC/ExploitDB -> TF-IDF hoặc Word2Vec + cosine chọn CAPEC -> T5 sinh
execution flow Explore/Experiment/Exploit -> ánh xạ technique sang ExploitDB ->
truy xuất code bằng SBERT -> Flask GUI -> BLEU/ROUGE, CAPEC accuracy, so sánh
FLAN-T5, đo tài nguyên và human evaluation.

## 3. Kiến trúc repo

`connectors/` -> `domain/` -> `retrieval/` -> `generation/` ->
`reproduction/` -> `evidence/` -> `pipeline/`; API và GUI là lớp demo. Mọi
xuất phát đều opt-in, executor chỉ chạy argv từ manifest trên localhost.

## 4. Nguồn dữ liệu

| Thành phần | Nguồn | Nhóm tự gán? |
|---|---|---|
| CVE description | NVD 2.0 | Không |
| CVE->CWE | NVD | Không |
| CWE->CAPEC | MITRE `Related_Weakness` | Không |
| CAPEC flow | MITRE `Execution_Flow` | Không |
| CVE->CAPEC reference | Galeax/CVE2CAPEC | Không |
| Independent label | MITRE `Example_Instances` | Nhóm viết tiêu chí trích xuất, nhãn chép nguyên văn |
| Sample CVE | Nhóm tạo (fake) | Có |
| Validator XSS | Nhóm viết | Có |

Snapshot 114.560 CVE nằm ở dataset Kaggle riêng, **không có trong Git**.
Repo chỉ lưu script build.

## 5. Mapping CVE/CWE/CAPEC

- TF-IDF 86/100, Word2Vec 87/100; paper 89/100.
- Benchmark 120 CVE có circular label: Galeax sinh nhãn từ cùng quan hệ
  CWE->CAPEC dùng để tạo candidate. Không được dùng làm bằng chứng ranking.
- Independent set 21 case: TF-IDF Top-1 0,3333, Word2Vec 0,1905; coverage 12/21.
  Kết luận đảo ngược so với benchmark circular.

## 6. Retrieval

Benchmark 9 CVE tracked. README ghi semantic P@3 0,296; máy có raw MITRE XML
chạy ra 0,3333 do enricher đọc snapshot local (`retrieval/semantic.py:236-240`).
Đây là khác biệt môi trường, không phải lỗi code; phải ghi rõ khi trích số.

## 7. T5 generation

- Stage 1 sau resume trên kernel `alexdannguyen/v2a-stage1-resume-checkpoint-3465`:
  BLEU 0,4802 và ROUGE-L F1 0,5659 trên 11,089 validation rows; checkpoint
  `3465 → 4158`, epoch 6. Đây là observed validation result trên split có leakage
  11,083/11,089; không phải independent evaluation, generalization evidence hay
  paper-comparable result. Chi tiết: `docs/t5-stage1-final-vi.md`.
- Phân loại claim: observed validation result = có artifact; independent evaluation =
  chưa có; generalization evidence = không; paper-comparable result = không.
- Kết quả cũ đã có (không phải kết quả chạy hiện tại): CVE-only BLEU 0,1640
  (10 epoch) / 0,2567 (1 epoch), paper 0,7589; collapse về 25 prediction duy
  nhất trên 11.089 dòng; 11.083/11.089 validation target trùng train.
- CAPEC-conditioned 0,8594 và hybrid 0,7508 là protocol khác, **không so trực
  tiếp** với 0,7589 của paper.
- Validation hiện tại bị leakage nặng;BLEU không đại diện generalization.
  Cần holdout/group-split mới (`docs/evaluation/t5-group-split-plan.md`).

## 8. Reproduction lab

`cve-001`: vulnerable + patched, validator kiểm tra marker, allowlist action,
evidence có generation input/output, workflow, plan. Hai action cùng gọi một
validator marker cố định -> đây là provenance, chưa phải bằng chứng workflow
sinh đúng payload. `cve-002/003` là placeholder.

## 9. Evidence

`EvidenceBundle` lưu generation (CVE, contexts, CAPEC, output), workflow, plan,
log và validation result. Chưa lưu checkpoint/model id; chưa phân biệt
reference flow và generated flow. Xem `reports/t5-pipeline-evidence-audit.md`.

## 10. Benchmark methodology

Freeze independent set tại `docs/evaluation/capec-independent-freeze.md`
(SHA-256 `93128e50...49c8`). Protocol group-split cho T5 nằm ở
`docs/evaluation/t5-group-split-plan.md`. Không tune benchmark theo kết quả.

## 11. Kết quả đánh giá

| Hạng mục | Giá trị repo | Ghi chú |
|---|---|---|
| Retrieval P@3 (README) | 0,296 | local có raw XML: 0,3333 |
| CAPEC Top-1 (120, circular) | 87/100 | không dùng làm bằng chứng độc lập |
| CAPEC Top-1 (independent, TF-IDF) | 0,3333 all / 0,5833 reachable | 21 case, coverage 12/21 |
| Stage 1 BLEU/ROUGE | BLEU 0,4802; ROUGE-L F1 0,5659 | 11,089 validation rows, resume 3465→4158, epoch 6; observed validation, leakage 11,083/11,089, không generalization |
| SBERT retrieval | chưa tích hợp | chỉ có Word2Vec description mapping |
| Stage 2 CVE-only | chưa chạy | chờ checkpoint stage 1 |

## 12. Human evaluation

Dự kiến 20 CVE, **1 advisor reviewer**. Bộ tài liệu nằm ở
`docs/human-evaluation/`; chưa gửi được vì thiếu split cuối và output workflow.
Không gọi là 3 chuyên gia, không tái tạo Table 6 của paper.

## 13. Giới hạn

- Dataset nhỏ hơn paper về số CAPEC có flow (176 so với ~1.024).
- FP16 từng gây NaN; chuyển FP32 là lựa chọn triển khai, không đổi protocol.
- Chạy 6 epoch thực tế sau resume từ checkpoint epoch 5, không phải 50 epoch hoàn thành.
- T4 x2 thay A100 32GB.
- Local exploit code không được đưa vào Kaggle hay evidence công khai.
- CI chưa kiểm chứng Docker lab integration (2 test skip).

## 14. Bảng sai lệch bắt buộc

| Paper | Repo implementation | Deviation | Evidence |
|---|---|---|---|
| 114.560 CVE, A100 | 114.560 CVE, T4 x2 | Khác phần cứng | `docs/paper-reproduction.md`, Kaggle kernel |
| 50 epoch, lr 5e-5 | lịch 50, dừng sau 6 epoch (resume từ checkpoint epoch 5); FP32 | Khác số epoch thực chạy | `docs/t5-stage1-final-vi.md`, kernel log |
| BLEU 0,7589 | BLEU 0,4802 observed validation (cũ: 0,1640; ROUGE-L F1 0,5659) | Không paper-comparable; validation leakage 11,083/11,089 | `docs/t5-stage1-final-vi.md`, `data/external/resume_cp3465/` |
| 3 chuyên gia | 1 advisor reviewer | Khác số reviewer | `docs/human-evaluation/protocol.md` |
| CAPEC 89/100 | 87/100; independent TF-IDF 0,3333 | Thấp hơn và đảo chiều ranker | `docs/capec-selection-report-vi.md`, `docs/analysis.md` |
| SBERT + threshold | Word2Vec description mapping | SBERT chưa tích hợp | `src/vuln2action/mapping/exploit.py` |
| Flask GUI với generated flow | GUI chỉ hiện reference CAPEC flow | Thiếu luồng T5 | `gui/app.py:110-150` |
| Validation 80/20 theo CVE | target trùng train 11.083/11.089 | Leakage, cần group-split | `docs/t5-stage1-eval-vi.md` |

## 15. Future work

Nối checkpoint T5 vào GUI, validator theo action, holdout độc lập, human eval,
Stage 2 và SBERT nếu còn thời gian.

## Cấm khi hoàn thiện báo cáo

Không ghi 3 chuyên gia; không gộp CVE-only/gold-CAPEC/hybrid; không ghi 50 epoch
đã hoàn thành; không gọi BLEU leakage là generalization; không nói SBERT/Stage 2
đã xong; không nói nhóm tái tạo đầy đủ paper.
