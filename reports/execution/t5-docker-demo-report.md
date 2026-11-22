# T5 Docker demo report — Batch 2 + 3 (2026-11-22)

## 1. Conclusion

**PARTIALLY VERIFIED.** Validator trả `PASS` thật và `report.json`/`report.md` được
tạo bởi pipeline; tuy nhiên CLI thoát với **exit code 1** do `UnicodeEncodeError`
khi in đường dẫn chứa tiếng Việt **sau khi** report đã được ghi. Không chạy lại lệnh
theo yêu cầu. Screenshot không có công cụ chụp thực → `SCREENSHOT_NOT_CAPTURED`.

Không tuyên bố demo "VERIFIED trọn vẹn" vì exit code không phải 0 và thiếu ảnh chụp.

## 2. Commands actually run

| Step | Command | Exit |
|---|---|---:|
| Pre-flight | `git status --short --branch`, `git log -1 --oneline`, `git diff --stat`, `git diff` | 0 |
| Pre-flight | `docker info --format '{{.ServerVersion}}'` | 0 (29.8.2) |
| Pre-flight | `docker compose -f labs/cve-001/docker-compose.yml config` | 0 (host_ip `127.0.0.1`, published `18001`/`18011`) |
| Pre-flight | `Get-NetTCPConnection -LocalPort 18001,18011 -State Listen` | both FREE |
| Build | `docker compose -f labs/cve-001/docker-compose.yml build` | 0 |
| Demo | `vuln2action --sample CVE-2024-0001 --execute --save t5-demo-cve-001` | 1 (post-write print error) |
| Audit | parse `results/t5-demo-cve-001/report.json` | 0 |
| Audit | recompute SHA-256 for 15 artifacts vs manifest | PASS |

## 3. Docker build result

Images built/tagged: `vuln2action-cve-001-vulnerable:latest`,
`vuln2action-cve-001-patched:latest`. Build context `labs/cve-001/target`,
Dockerfile `labs/cve-001/target/Dockerfile`. Full output:
`artifacts/demo/cve-001/logs/docker-build.log`, exit 0.

Network `vuln2action-lab-net` existed before this session and was not created or
deleted by the demo. No volume was created or removed.

## 4. Docker execution result

CLI stdout log records:
- `[workflow] step lab-up selected allowlisted action validate`
- `[setup] ... labctl.py up`, `exit=0`
- `[validate] ... labctl.py validate`, `exit=0`
- `[teardown] ... labctl.py down`, `exit=0`

## 5. Validator result

From `report.json` → `result.status = PASS`, `result.evidence.validation`:

```json
{
  "status": "PASS",
  "lab_id": "cve-001",
  "vulnerability_id": "CVE-2024-0001",
  "checks": {
    "marker": "<b>v2a-probe</b>",
    "vulnerable_reflects_unescaped": true,
    "patched_reflects_escaped": true,
    "patched_reflects_unescaped": false,
    "health": {
      "vulnerable": {"status": "ok", "mode": "vulnerable"},
      "patched": {"status": "ok", "mode": "patched"}
    }
  }
}
```

Only the fixed marker was used; this proves the lab counterfactual, not that a
T5-generated payload reproduced the vulnerability.

## 6. Report paths

- `results/t5-demo-cve-001/report.json` (14,592 bytes, parsed successfully)
- `results/t5-demo-cve-001/report.md` (183 bytes)
- Packaged copies: `artifacts/demo/cve-001/evidence/report.json`, `report.md`

Report content verified: `cve_id=CVE-2024-0001`, `provider=rule_based`,
`result.status=PASS`, evidence keys
`checkpoint_id, collected_at, command_outputs, generation, http, logs, plan, validation_result, workflow`,
`checkpoint_id=null`.

## 7. Artifacts and SHA-256

Full list recorded in `artifacts/demo/cve-001/manifest.json`; 15 files, all hashes
recomputed and matched:

| File | SHA-256 |
|---|---|
| evidence/evidence.json | f66a1f8ecf014f83cd0e64aaab20403926e572ab3ae8ba67c3496b79509ffd1a |
| evidence/report.json | 53cc479c8007230209151dadcfb7b724d6202a0783c928ce1c26573ffbdce5e9 |
| evidence/report.md | c8cf6852c3a3ec0d51ec1b10c8c7d25417afe592c27b93f6385faf40d25f1bfa |
| execution/execution.json | 01a5cd8b0ac3e94876cb72d2c8f23e235c8698175d1daa7a41bbf13ad403ed21 |
| input/docker-compose.yml | 1ecaa5eaae67d90b6654ae6fe32a31b31d237a61188d1704aaa92767ad4db1e8 |
| input/lab.yaml | 0375c3e9484bc21a7a4541beeda722eb792eb32217423d4404d8233641b78cb1 |
| input/sample_cves.json | b90478e70717ddca681f5676a40c510ffd36ffbf0b95658e95df1fb8273ecf28 |
| logs/cli-exit.txt | f1b2f662800122bed0ff255693df89c4487fbdcf453d3524a42d4ec20c3d9c04 |
| logs/cli-stderr.log | 9246bc49eed5f9c68ad593e7419d1b322b86f9634e798425a557818d20716298 |
| logs/cli-stdout.log | eb862858aa9cd1159b2132802a6ddbc925614578324f19f6d89e97b2fe965582 |
| logs/docker-build.log | 879b15ce3393ba9eb0208f55a40fbe30f099bd967730b76b670f8a941dbe2bb5 |
| screenshots/SCREENSHOT_NOT_CAPTURED.txt | 5bc1df47e4ed9199ebb47d93d25cd7b05dde1c0e3a91fb9bbb560029b26a8245 |
| validator/validation.json | bf5f53dc9051a64af09d89e1bb291964a4df8a1ab6460947be154654371d4332 |
| workflow/plan.json | ab252ba4e70549fb17898a4b6379eac479aec17097d829e884fda142988f3eca |
| workflow/workflow.json | 1b95c7601590a9517ab1852bac6dd30a865e993b64ba004fe66b6d5d7214b646 |

Hashes confirm artifact integrity at creation time only, not absolute provenance.

## 8. Screenshot status

`SCREENSHOT_NOT_CAPTURED` — no real screenshot tool was used. No illustrative or
synthetic image was created. Manual capture instructions: run the CLI command in a
terminal and capture the window showing the validator JSON and final verdict.

## 9. Docker cleanup status

No container with name `vuln2action-cve-001-*` remains (`docker ps -a` filter empty).
Ports 18001 and 18011 are FREE after the run. No volume or image was deleted.
The CLI `teardown` log shows `labctl.py down`, exit 0.

## 10. Git status before and after

Before: branch `dev`, HEAD `4283360`, 7 modified tracked files (prior batch) plus
untracked `docs/evaluation/`, `docs/human-evaluation/`, `docs/paper-deviation-report-vi.md`,
`reports/`, `tests/unit/test_evidence_provenance.py`.

After: identical, plus untracked `artifacts/` and new `reports/execution/*.md`.
`git diff --stat` unchanged (7 files, 141 insertions, 1 deletion). **No source file
was modified by Batch 2/3.** No commit/push.

## 11. Unverified steps

- Screenshot (not captured).
- CLI exit 0 (not achieved; encoding failure after report write).
- Kaggle stage-1 metrics/checkpoint (external, unchanged).
- Docker CI on GitHub (job not enabled).
- External strict schema compatibility.

## 12. Blockers and next actions

- User decision needed to fix the console encoding problem: either set
  `PYTHONIOENCODING=utf-8` for a future run or accept the current artifact with
  documented exit code 1. Fixing source in `cli.py` is **out of scope** without
  approval.
- If a fresh exit-0 run is required, it must be a new session directory (never
  overwrite `artifacts/demo/cve-001/`).
- Next recommended batch: T2 claims lock, using this report as the verified demo
  evidence and labelling T5 as rule-based, not generated.
