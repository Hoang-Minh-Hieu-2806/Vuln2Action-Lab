# Anticipated defense questions — Vuln2Action-Lab

Câu trả lời ngắn, có dẫn chứng. Không phóng đại thành quả.

## Research

**1. Đồ án khác gì Vuln2Action paper?**  
Đồ án triển khai lại pipeline local: ingest → retrieval → generation → lab → evidence, nhưng không tái hiện toàn bộ paper: phần cứng T4 x2 thay A100, 6 epoch thay 50, human eval 1 advisor thay 3 chuyên gia, group-split chưa có. Xem `docs/paper-deviation-report-vi.md:120-129`, `docs/defense/limitations-slide.md:24-35`.

**2. Phần nào nhóm tự triển khai?**  
Package/CLI, retrieval TF-IDF/Word2Vec/semantic, CVE→CAPEC mapping, rule-based generation, T5 training/eval scripts, planner/executor/validator, evidence/provenance, GUI và evaluation harness. Xem `README.md:62-87`, `docs/roadmap.md`.

**3. Phần nào chưa tái hiện?**  
SBERT, Stage 2 chạy thật, `cve-002/003`, 3-expert human eval, 50 epoch A100, group-disjoint holdout, Docker CI xanh trên GitHub. Xem `docs/defense/limitations-slide.md:24-35`, `docs/paper-deviation-report-vi.md:100-129`.

**4. Tại sao chưa thể claim full paper reproduction?**  
Vì không có đủ artifact cho protocol paper: leakage 11,083/11,089, không independent test, không group-split, không human eval 3 chuyên gia. Xem `docs/defense/defense-claims-vi.md`, `docs/evaluation/t5-group-split-plan.md:3`.

## Dataset

**5. NVD là gì?**  
National Vulnerability Database; dự án có client NVD 2.0 opt-in để lấy mô tả CVE, CWE/CPE. Xem `docs/roadmap.md:7-9`, `README.md:72-73`.

**6. CWE và CAPEC khác nhau thế nào?**  
CWE là lớp yếu phần mềm; CAPEC là pattern/mô tả cách khai thác. Dự án mở rộng CWE→CAPEC rồi chọn CAPEC bằng TF-IDF/Word2Vec. Xem `docs/roadmap.md:16-22`.

**7. Dữ liệu ExploitDB có vai trò gì?**  
Cung cấp mô tả technique cho Stage 2 và technique→exploit map; trong demo chỉ là metadata/tham chiếu, không đưa exploit source vào evidence. Xem `README.md:81`, `docs/roadmap.md:16-22`.

**8. Dataset có giới hạn gì?**  
55,420 rows nhưng chỉ 176 CAPEC execution-flow targets; validation leakage 11,083/11,089; independent CAPEC set chỉ 21 case. Xem `docs/evaluation/t5-group-split-plan.md:7-14`, `docs/evaluation/capec-independent-freeze.md:14`.

## Retrieval

**9. TF-IDF hoạt động thế nào?**  
Trọng số từ theo tần suất và độ hiếm trong corpus; là baseline retrieval. Trên independent CAPEC set: Top-1 0,3333 (all) / 0,5833 (reachable). Xem `docs/evaluation/capec-independent-freeze.md:41-48`.

**10. Word2Vec hoạt động thế nào?**  
Biểu diễn từ/văn bản thành vector để so sánh tương đồng ngữ nghĩa. Trên independent set nó thua TF-IDF: Top-1 0,1905 (all) / 0,3333 (reachable); benchmark 120 CVE circular nên không dùng làm bằng chứng ranking. Xem `docs/evaluation/capec-independent-freeze.md:41-55`.

**11. Tại sao cần semantic retrieval?**  
Để enrich ngữ cảnh bằng MITRE/CWE/CAPEC thay vì chỉ khớp từ. README ghi P@3 0,296; máy có raw XML chạy 0,3333 — khác biệt môi trường, đã ghi rõ. Xem `docs/paper-deviation-report-vi.md:52-54`.

**12. Đánh giá retrieval bằng tiêu chí nào?**  
Generation/retrieval harness dùng P@k/R@k/F1@k/MRR; CAPEC independent freeze dùng Top-1, Recall@5, MRR với 21 case và phân biệt all/reachable. Xem `docs/roadmap.md:37-42`, `docs/evaluation/capec-independent-freeze.md:30-36`.

## T5

**13. T5 nhận input và sinh output ra sao?**  
Input là CVE description/context, `target_field=target`, max input/target 512/512; output là execution-flow text dạng Explore/Experiment/Exploit. Xem `docs/t5-stage1-final-vi.md:9-27`.

**14. BLEU đo điều gì?**  
Độ trùng n-gram giữa output và reference, có brevity penalty; implementation tương thích sacrebleu. Xem `evaluation/generation/metrics.py:1-12`.

**15. ROUGE-L F1 đo điều gì?**  
F1 dựa trên longest common subsequence giữa candidate và reference, đo trùng chuỗi từ. Xem `evaluation/generation/metrics.py:1-12`.

**16. Tại sao BLEU 0.4802 chưa chứng minh generalization?**  
Vì đây là observed validation result trên split có leakage 11,083/11,089; không có group-disjoint holdout. Xem `docs/defense/defense-claims-vi.md`, `docs/evaluation/t5-group-split-plan.md:11-14`.

**17. Leakage ảnh hưởng kết quả ra sao?**  
Nó khiến BLEU đo template recall trên flow đã thấy, không đo khả năng xử lý CVE chưa từng gặp. Xem `docs/evaluation/t5-group-split-plan.md:11-14`.

**18. Tại sao chưa có group-split evaluation?**  
Vì plan mới ở mức `PLAN ONLY`; dự án không đổi dataset/split, không retrain trong đợt này. Xem `docs/evaluation/t5-group-split-plan.md:3-33`.

## System

**19. Validator kiểm tra gì?**  
Validator đọc manifest lab, kiểm tra marker/counterfactual và in payload `V2A_VALIDATION_JSON:`. Trong demo freeze, verdict là `SIMULATED`, không phải Docker PASS. Xem `src/vuln2action/reproduction/executor.py:13,43-54`, demo `validator/validation.json`.

**20. Evidence bundle có vai trò gì?**  
Gộp generation input/output, workflow, plan, execution log và validation result thành một run artifact; `checkpoint_id=null` trong demo. Xem `artifacts/demo/final-cve001-20261123T065251Z/evidence/evidence.json`, `evidence/report.json`.

**21. Provenance giúp gì cho audit?**  
Ghi retrieval items, provider/checkpoint, execution mode và content hash để truy nguồn số liệu. Xem `artifacts/demo/final-cve001-20261123T065251Z/evidence/provenance.json`.

**22. Hệ thống hạn chế arbitrary execution thế nào?**  
Executor mặc định simulate; khi chạy thật chỉ dùng lệnh có trong manifest, target phải localhost/allowed host, không shell, và validator/allowlist vẫn áp dụng. Xem `src/vuln2action/reproduction/executor.py:21-40,57-90`.

**23. Reference flow khác generated flow ra sao?**  
Reference flow lấy từ CAPEC metadata; generated flow là output thật của generator. GUI hiện tách `reference_flow`, `generated_flow=null`, `generation_status=unavailable`. Xem `gui/app.py`, `tests/unit/test_gui.py`.

## Demo

**24. Tại sao demo là SIMULATED?**  
Vì pipeline chạy ở chế độ mô phỏng trong artifact freeze; provider là `rule_based`, execution mode `simulated`, validator status `SIMULATED`. Xem demo `consistency.json`, `evidence/provenance.json`, `validator/validation.json`.

**25. Docker validation đã hoàn thành chưa?**  
Chưa. Không có GitHub-run xanh cho Docker CI và đợt này không chạy Docker integration. Xem `docs/defense/limitations-slide.md:22,37-45`.

**26. T5 có trực tiếp sinh flow trong demo không?**  
Không. Flow hiển thị là reference/CAPEC; generated flow không có trong run demo này. Xem `docs/defense/demo-script-vi.md`, `gui/app.py`.

**27. Nếu GUI không chạy thì demo dự phòng thế nào?**  
Dùng CLI JSON, `report.json`, `report.md`, provenance và screenshot đã freeze trong artifact root; vẫn nói rõ SIMULATED/reference flow. Xem `artifacts/demo/final-cve001-20261123T065251Z/`, `scripts/verify_demo_freeze.py`.

## Future work

**28. T3 Human Evaluation cần những gì?**  
Cần `splits.json` chuẩn, 20 workflow output, 1 advisor reviewer, protocol/rubric/form; không tự tạo điểm. Xem `docs/human-evaluation/protocol.md:9-16,32-36,84-90`.

**29. T6 Docker CI cần những gì?**  
Cần job riêng với `V2A_DOCKER_TESTS=1`, một GitHub run xanh, cleanup luôn chạy; không `continue-on-error`. Xem `docs/defense/limitations-slide.md:37-45`, `reports/next-action-roadmap.md:155-156`.

**30. T8 Group Split sẽ cải thiện evaluation như thế nào?**  
Nó tạo manifest group-disjoint theo normalized target/near-duplicate, test cố định dùng một lần, kèm overlap report và hash; khi đó BLEU/ROUGE mới phản ánh unseen attack flow thay vì template recall. Xem `docs/evaluation/t5-group-split-plan.md:16-32,62-75`.
