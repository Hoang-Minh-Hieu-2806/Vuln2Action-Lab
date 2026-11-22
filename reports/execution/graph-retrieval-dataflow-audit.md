# Graph Architecture Audit — Retrieval Data Flow (`KnowledgeDocument`, `RetrievedContext`)

- Ngày: 2026-11-22 · Baseline `4283360`
- Phạm vi: READ-ONLY. Không sửa source/graph, không refactor, không Docker/Kaggle/training, không commit/push, không chạy test.
- Nguồn: `graphify-out/graph.json` (2.078 nodes / 4.658 edges, `directed: false`, build tại commit `4283360`), `GRAPH_REPORT.md`, và source tree.

## 1. Executive summary

Hai domain model đều nằm trong cùng file `src/vuln2action/domain/knowledge.py`:

| Model | Định nghĩa | Graph degree | Community |
|---|---|---:|---|
| `KnowledgeDocument` | `:109-125` | 33 | 18 `"KnowledgeDocument"` |
| `RetrievedContext` | `:101-106` | 31 | 20 `"RetrievedContext"` |

Kiến trúc retrieval là **3 backend lexical cùng chia sẻ một interface** (`RetrievalBackend.search` tại `retrieval/base.py:10-22`), trả về `RetrievedContext`, rồi `retrieval/ranker.py:20-66` gộp thêm context tổng hợp từ CVE field. `KnowledgeDocument` là đơn vị corpus; `RetrievedContext` là đơn vị kết quả. Không có embedding backend thật (`base.py:39-43` là stub).

Điểm đáng chú ý nhất **không nằm ở graph**: toàn bộ `score`, `backend`, `source` của `RetrievedContext` bị **ép thành chuỗi** tại `generation/prompts.py:6-7` trước khi vào `Workflow.context_summary` (`generation/rule_based.py:24`, `generation/t5.py:194`). Graph không thấy được conversion này.

Graph phản ánh tốt import/annotation (29/33 và 26/31 cạnh EXTRACTED), nhưng 6 cạnh INFERRED đều là constructor call trong test — không phải runtime dependency.

## 2. `KnowledgeDocument` trace

### 2.1 Definition (VERIFIED BY SOURCE)
`src/vuln2action/domain/knowledge.py:109-125`: Pydantic `BaseModel`, `extra="forbid"`, fields:
`doc_id: str`, `text: str`, `kind: str = "cwe"`, `name: str = ""`, `source: str = ""`; validator `must_not_be_blank` áp cho `doc_id`, `text` (`:119-125`). Docstring `:110`: "A retrievable document (CWE, CAPEC, or reference metadata)."

### 2.2 Constructors / factories (VERIFIED BY SOURCE)
| Factory | File : line | Transformation |
|---|---|---|
| `cwe_document(CweRecord)` | `retrieval/corpus.py:39-46` | `cwe_id → doc_id`, `name`, `text=f"{id} {name}: {description}"`, `source=_definition_url("cwe", id)` (`:34-36`) |
| `capec_document(CapecRecord)` | `retrieval/corpus.py:49-56` | tương tự với `capec_id`, `kind="capec"` |
| `CorpusFile.model_validate(raw)` | `retrieval/corpus.py:26-31, 59-63` | JSON object → `list[KnowledgeDocument]` (`min_length=1`) |
| `load_corpus_file` list-branch | `retrieval/corpus.py:66-76` | CWE/CAPEC record JSON → `CweRecord`/`CapecRecord` → factory; unknown shape → `TypeError` |
| `load_seed_corpus` / `load_processed_corpus` / `build_corpus` / `default_corpus` | `retrieval/corpus.py:79-118` | chọn nguồn + cache `lru_cache(maxsize=1)` |

**Không tìm thấy factory nào tạo `KnowledgeDocument` cho "reference metadata"** dù docstring có nhắc — xem mục False positives.

### 2.3 Import sites (VERIFIED BY SOURCE / graph)
Production: `domain/__init__.py:6` (re-export), `retrieval/{base,corpus,keyword,ranker,semantic,text,tfidf}.py`, `evaluation/retrieval/harness.py:15`.
Test-only import: `tests/unit/test_evaluation_retrieval.py:9`, `tests/unit/test_retrieval_backends.py:7`.
Graph ghi 8 cạnh `imports` EXTRACTED — khớp nhóm production (7 retrieval + 1 domain facade; evaluation dùng reference annotation, không có cạnh import riêng trong graph).

### 2.4 Production call sites (VERIFIED BY SOURCE)
- `retrieval/corpus.py:40` `KnowledgeDocument(...)` trong `cwe_document()` — graph `calls` EXTRACTED tại `L40`.
- `retrieval/corpus.py:50` `KnowledgeDocument(...)` trong `capec_document()` — graph `calls` EXTRACTED tại `L50`.
- `retrieval/corpus.py:63` `CorpusFile.model_validate(raw)` — deserialization, graph chỉ ghi `references`.
- Các hàm consumption: `build_contexts_for_cve` (`ranker.py:27`), `KeywordBackend.search` (`keyword.py:36`), `TfidfBackend.search` (`tfidf.py:48`), `SemanticBackend.search` (`semantic.py:336-354`), `SemanticEnricher.enrich` (`semantic.py:191-208`), `document_text` (`text.py:170-182`), `harness.evaluate_backend` (`evaluation/retrieval/harness.py:45-62`).

### 2.5 Test-only references (VERIFIED BY SOURCE)
`tests/unit/test_evaluation_retrieval.py:13-15,75`; `tests/unit/test_retrieval_backends.py:25,29,33,57,62,149`. Graph có **3 cạnh `calls` INFERRED** cho `KnowledgeDocument` — đã đọc hết:

| Graph source | Evidence | Kết luận |
|---|---|---|
| `test_harness_mrr_uses_full_ranking` (`test_evaluation_retrieval.py:75`) | list comprehension `KnowledgeDocument(doc_id=..., text=...)` | CONFIRMED — fixture test |
| `test_document_text_repeats_name_for_field_boost` (`test_retrieval_backends.py:149`) | `document = KnowledgeDocument(...)` | CONFIRMED — fixture test |
| `test_semantic_backend_uses_mitre_metadata` (`test_retrieval_backends.py:57`) | `KnowledgeDocument(...)` trong `documents = [...]` | CONFIRMED — fixture test |

### 2.6 Serialization / deserialization
- **Deserialize có**: `CorpusFile.model_validate` (`corpus.py:63`) từ `data/samples/knowledge_corpus.json` (tồn tại, cấu trúc `{version, description, source, documents:[...]}`).
- **Deserialize gián tiếp**: `load_corpus_file` list-branch (`corpus.py:70-73`) validate `CweRecord`/`CapecRecord` rồi mới tạo document.
- **Serialize trực tiếp `KnowledgeDocument`: KHÔNG TÌM THẤY** trong source. Script `scripts/build_dataset.py:86,91` ghi `CweRecord`/`CapecRecord` (dạng raw), không ghi document; `scripts/build_retrieval_context.py:80` ghi `SemanticContextFile` (metadata khác). Đây là NOT VERIFIED chứ không phải khẳng định không tồn tại ở ngoài repo.

### 2.7 Schema transformations
`CweRecord`/`CapecRecord` (id, name, description) → `KnowledgeDocument` (doc_id, name, text ghép, source URL) → văn bản index (3 biến thể, xem 3.3) → `RetrievedContext` → chuỗi `context_summary`.

## 3. `RetrievedContext` trace

### 3.1 Definition (VERIFIED BY SOURCE)
`domain/knowledge.py:101-106`: `extra="forbid"`, `source: str`, `text: str`, `score: float = 0.0 (ge=0)`, `backend: str = "keyword"`.

### 3.2 Backend nào tạo `RetrievedContext`? (VERIFIED BY SOURCE)
| Producer | File : line | `source` | `text` | `score` | `backend` |
|---|---|---|---|---|---|
| `KeywordBackend.search` | `retrieval/keyword.py:38-46` | `documents[index].doc_id` | `documents[index].text` | similarity Dice | `self.name = "keyword"` |
| `TfidfBackend.search` | `retrieval/tfidf.py:50-58` | `doc_id` | `document.text` | cosine TF-IDF | `"tfidf"` |
| `SemanticBackend.search` | `retrieval/semantic.py:347-354` | `doc_id` | `document.text` | word/char TF-IDF blend | `"semantic"` |
| `build_contexts_for_cve` (tổng hợp, không phải backend) | `retrieval/ranker.py:35-41, 45-52, 58-65` | `document.doc_id` / `record.cwe_id` / `reference:<url>` | text document / CWE lookup / `Reference metadata: <url>` | `1.0`, `1.0`, `0.5` | `"record-cwe"`, `"cwe-lookup"`, `"reference-metadata"` |

Graph ghi đúng 1 cạnh `calls` EXTRACTED cho `RetrievedContext` — `ranker.py:35` — nhưng **không ghi 3 backend constructors** (chỉ để lại `references` tại `keyword.py:30`, `tfidf.py:42`, `semantic.py:333`). Đây là graph under-report, không phải source thiếu.

### 3.3 Field điền từ đâu / indexing (VERIFIED BY SOURCE)
Ba backend **không dùng chung một hàm dựng text index**:
- keyword: `texts = [document.text ...]` (`keyword.py:36`) — không boost name, không enrich.
- tfidf: `document_text(document, name_weight=2)` (`tfidf.py:48`; `text.py:170-182`) — lặp `name` 2 lần + text.
- semantic: `split_camel_case(_index_text(document, enricher, name_weight))` (`semantic.py:267-270`; `_index_text` `:211-220`; `enrich` `:191-208`) — name boost + alternate terms + related CAPEC names + parent weaknesses.

`text` trả về trong `RetrievedContext` **luôn là `document.text` gốc**, không phải text đã enrich/boost. Chỉ `score` phản ánh indexing variant.

### 3.4 Có bao nhiêu retrieval backend? (VERIFIED BY SOURCE)
`RetrievalBackend` (ABC, `base.py:10`) + **3 concrete**: `KeywordBackend`, `TfidfBackend`, `SemanticBackend`, đăng ký qua `get_backend` (`base.py:25-44`, alias `kw`, `tf-idf`, `enriched`). `embedding`/`embeddings` → `NotImplementedError` (`base.py:39-43`). `config/settings.yaml:8-12` liệt kê đúng 3 và `default_backend: "semantic"`. `retrieval/capec.py` là mapping CAPEC (`map_cve_to_capec` → `CapecMapping`), **không phải backend tạo `RetrievedContext`**.

### 3.5 Analysis / generation tiêu thụ thế nào (VERIFIED BY SOURCE)
- `pipeline/analyze.py:64` `contexts = build_contexts_for_cve(...)`; `:65` `generator.generate(cve, contexts)`; `:68` đưa vào `AnalysisOutcome.contexts`.
- `generation/base.py:14`, `llm.py:10`, `rule_based.py:11`, `t5.py:300` — cùng signature `generate(cve, contexts)`.
- `rule_based.py:24` và `t5.py:194` → `build_context_summary(contexts)` (`prompts.py:6-7`) → `Workflow.context_summary: str`.
- `t5.build_model_input` (`t5.py:55-67`) chỉ dùng `context.source` lọc `CAPEC-*` để tạo prompt; bỏ qua `score`, `backend`, `text`.
- `generation/llm.py:10-12` — stub, `NotImplementedError`.
- `run.py:76` ghi `[context.source for context in outcome.contexts]` vào evidence.

### 3.6 Fallback / default context (VERIFIED BY SOURCE)
| Tình huống | Hành vi | Evidence |
|---|---|---|
| `get_backend("")` hoặc `None` | mặc định `keyword` | `base.py:26` |
| backend lạ / `embedding` | `ValueError` / `NotImplementedError` | `base.py:39-44` |
| processed corpus rỗng | fallback seed corpus | `corpus.py:109-113` |
| path corpus chỉ định rỗng | `FileNotFoundError` | `corpus.py:104-108` |
| thiếu `sklearn` (tfidf) | fallback `keyword_search` | `tfidf.py:11-17` |
| thiếu `sklearn` (semantic) | fallback keyword trên text đã enrich | `semantic.py:272-278` |
| metadata MITRE lỗi XML | bỏ qua, giữ context đã có | `semantic.py:238-243` |
| `doc_id` không có metadata | `enrich()` trả `document.text` | `semantic.py:192-194` |
| query không token / top_k<=0 | `[]` | `semantic.py:256-264` |

**Không có default `RetrievedContext` object nào.** Dữ liệu hiện tại: `data/processed/cwe.json` và `capec.json` **KHÔNG TỒN TẠI** → runtime dùng seed corpus `data/samples/knowledge_corpus.json`; `data/samples/cwe_semantic_context.json` tồn tại.

### 3.7 Context rỗng / thiếu metadata (VERIFIED BY SOURCE)
- `ranker.py:27-66`: nếu `cve.cwe` rỗng, `documents` rỗng và `cve.references` rỗng → `contexts=[]`; `rank_contexts([])` → `[]`. Không có placeholder, không có exception.
- `build_context_summary([])` → `""` (`prompts.py:7`) → `Workflow.context_summary=""`.
- `RetrievedContext.backend` mặc định `"keyword"` (`knowledge.py:106`) — fixture test `test_retrieval.py:40-41` tạo context không truyền backend nên mang nhãn mặc định dù không phải keyword backend.
- `KnowledgeDocument.name`/`source` mặc định `""` (`knowledge.py:116-117`); fixture test thường bỏ qua → `document_text` trả nguyên `document.text` (`text.py:180-181`).

## 4. End-to-end retrieval data flow

| # | Bước | File / function | Input → Output | Transformation | Dependency / fallback |
|---:|---|---|---|---|---|
| 1 | Dataset build | `scripts/build_dataset.py:76-92` → `connectors/dataset.py:83-88 write_cwe_dataset/write_capec_dataset` | NVD/CWE/CAPEC XML → `data/processed/{cves,cwe,capec}.json` | `CweRecord`/`CapecRecord` → `model_dump(json)` | opt-in; hiện processed **missing** |
| 2 | Corpus load | `retrieval/corpus.py:98-118 build_corpus/default_corpus` | files → `tuple[KnowledgeDocument]` | `load_processed_corpus` → nếu rỗng `load_seed_corpus` | `lru_cache(maxsize=1)` |
| 3 | Document factory | `corpus.py:39-56 cwe_document/capec_document` | `CweRecord`/`CapecRecord` → `KnowledgeDocument` | flatten + `_definition_url` | graph `calls` EXTRACTED |
| 4 | Metadata enrich (chỉ semantic) | `semantic.py:91-174 build_semantic_contexts`, `:185-208 SemanticEnricher`, `:223-244 default_semantic_enricher` | XML/JSON → `SemanticContext` → text mở rộng | alternate terms / CAPEC / parents | tracked JSON + raw snapshot; parse error swallowed |
| 5 | Indexing | `keyword.py:36`, `tfidf.py:48`, `semantic.py:267-270` | `KnowledgeDocument` → `list[str]` | 3 biến thể | TF-IDF fit **mỗi lần search**, không persist |
| 6 | Retrieval | `base.py:25-44 get_backend` → `*.search` | query + docs + top_k → `list[RetrievedContext]` | score + gán `source`/`text`/`backend` | sklearn fallback keyword |
| 7 | Rank / gộp | `ranker.py:11-17 rank_contexts`, `:20-66 build_contexts_for_cve` | contexts + CVE fields → contexts đã dedupe | dedupe theo `source`, giữ max score; thêm CWE/reference context | `lookup_cwe` (`connectors/catalog.py:24`) |
| 8 | Analysis | `pipeline/analyze.py:56-74 analyze_cve` | `CveRecord` → `AnalysisOutcome` | contexts + workflow + capec | generator via `generation/__init__.py` |
| 9 | Generation | `rule_based.py:11-49`, `t5.py:55-67,276-309` | `contexts` → prompt/string → `Workflow` | **metadata `score`/`backend` bị bỏ** | LLM generator stub |
| 10 | Evidence | `pipeline/run.py:70-82`, `evidence/reporter.py:28-52` | generation input → `report.json` | chỉ lưu `context.source` list | output dir `results/` |

## 5. Dependency matrix

| Từ → tới | Loại | Evidence | Graph có thấy? |
|---|---|---|---|
| `domain` → `pydantic` | inherits | `knowledge.py:101,109` | Có (`inherits BaseModel`, external node) |
| `retrieval/*` → `domain` | imports + annotations | 8 cạnh import | Có |
| `retrieval/corpus` → `connectors/dataset` | import (layer ngang) | `corpus.py:17` | Không phải cạnh với 2 node này |
| `retrieval/ranker` → `connectors/catalog` | runtime call `lookup_cwe` | `ranker.py:5,43` | Không |
| `pipeline/analyze` → `retrieval`, `generation` | runtime call | `analyze.py:6-8,63-65` | Một phần (imports/refs) |
| `generation/*` → `domain` | imports + annotations | `prompts.py:3`, `base.py:7`, `t5.py:26` | Có |
| `evaluation` → `retrieval`, `domain` | import + call | `harness.py:15-16,52,62` | Có (refs) |
| tests → `domain` | fixture constructors | 6 cạnh INFERRED | Có (INFERRED) |

Không có dependency ngược: AST SCC trên 60 module local = `[]`; `vuln2action.domain` không import module local nào (kiểm tra ở Phase 1).

## 6. Confirmed risks

1. **Mất metadata tại ranh giới generation** — `prompts.py:6-7` render `[source] text`, bỏ `score`, `backend`; `rule_based.py:24`, `t5.py:194`, `run.py:76` đều tiêu thụ chuỗi này. Không thể truy vết backend/điểm số từ `Workflow`/report.
2. **Ba cách dựng index text khác nhau** — `keyword.py:36` vs `tfidf.py:48` vs `semantic.py:211-220`: cùng corpus nhưng khác tín hiệu; so sánh benchmark giữa backend không còn thuần "thuật toán".
3. **Không có index persistent** — `tfidf.py:26`, `semantic.py:291-292` fit vectorizer trên mọi `search`; chỉ corpus được cache (`corpus.py:116`).
4. **Degradation im lặng** — thiếu sklearn (`tfidf.py:14-17`, `semantic.py:275-278`) và XML lỗi (`semantic.py:239-243`) đều fallback không báo cho caller; `RetrievedContext.backend` vẫn ghi `"tfidf"`/`"semantic"` dù thực tế chạy keyword.
5. **Docstring/schema lệch** — `KnowledgeDocument` nhận "reference metadata" (`knowledge.py:110`) nhưng reference context được tạo trực tiếp thành `RetrievedContext` ở `ranker.py:57-65`; không có factory document tương ứng.
6. **Default không đồng nhất** — `config/settings.yaml:9` default `semantic`, nhưng `get_backend("")` → `keyword` (`base.py:26`) và `RetrievedContext.backend` default `"keyword"` (`knowledge.py:106`).

## 7. False positives / graph limitations

- Graph **undirected** (`directed: false`) → không đọc hướng `retrieval → domain` từ mũi tên HTML.
- 6 cạnh INFERRED (`calls`) đều là constructor call trong fixture/fake test (bảng mục 2.5 và 3.2 ở trên) — **không** chứng minh runtime dependency giữa test function và implementation function.
- Community 18/20 đặt tên theo chính node (`"KnowledgeDocument"`, `"RetrievedContext"`) → vô nghĩa về kiến trúc; community 37 `"cve2capec.py"` thực chất chứa cạnh `contains`/`inherits` của `knowledge.py` và node `BaseModel` không có `source_file` → nhiễu.
- Graph không ghi 3 constructor backend tạo `RetrievedContext` (chỉ có `ranker.py:35` là `calls` EXTRACTED) → **under-report runtime**, không phải source thiếu.
- Health check: 0 dangling, 0 collapsed, **1 self-loop** trong toàn graph (`cpe_criteria_walk`, không liên quan 2 node này); 12 producer suppression site trong `graphify/extract.py` → không coi graph là đầy đủ tuyệt đối.

## 8. Refactoring recommendations (có điều kiện, không dựa trên graph degree)

1. Nếu so sánh backend tiếp tục được dùng cho báo cáo: đưa `document_text` / `_index_text` về **một helper dùng chung** để tránh 3 biến thể (`keyword.py:36`, `tfidf.py:48`, `semantic.py:211-220`). Đây là trùng lặp source có thật, không phải suy luận từ graph.
2. Nếu cần truy vết provenance trong evidence: truyền `list[RetrievedContext]` (hoặc tối thiểu `source`+`backend`+`score`) vào `EvidenceBundle` thay vì chuỗi `Workflow.context_summary` (`prompts.py:6-7`). Hiện chưa có requirement nào xác nhận cần thiết.
3. Sửa docstring `KnowledgeDocument` (`knowledge.py:110`) cho khớp thực tế, hoặc thêm factory reference-document nếu thiết kế muốn quản lý thống nhất — chỉ khi có nhu cầu.
4. **Không** đổi domain model chỉ vì degree 33/31.

## 9. Unknown / unverified items

- Có consumer bên ngoài repo đọc `RetrievedContext.backend`/`score` từ `report.json` hay không — không kiểm chứng được.
- Không tìm thấy writer serialize `KnowledgeDocument`; không khẳng định tuyệt đối rằng không có ngoài repo.
- 33 file không đại diện trong graph (23 `.ipynb`, 8 không rõ đuôi, 1 `.example`) — có thể chứa luồng retrieval khác.
- 12 suppression site ở khâu extract: tổn thất node/edge gốc không đo được từ `graph.json`.
- Không chạy test theo yêu cầu; mọi "CONFIRMED" ở trên là xác minh bằng đọc source, không phải bằng thực thi.

## 10. Kết luận

- **VERIFIED BY SOURCE**: definition, factory, 3 backend + alias registry, field provenance, 4 fallback cơ bản, empty-context behavior, và 6 cạnh INFERRED (đều là fixture constructor trong test). Luồng dataset → document → index → retrieval → ranker → analysis → generation → evidence tồn tại đúng như mục 4, với indexing in-memory.
- **INFERRED BY GRAPH**: community map, import/annotation edges, phân loại 33/31 cạnh, và việc graph không ghi 3 backend constructor. Graph dùng để điều hướng, không dùng làm bằng chứng runtime.
- **NOT VERIFIED**: serialize `KnowledgeDocument`, consumer bên ngoài của context metadata, nội dung 33 file ngoài graph, và tổn thất extract do 12 suppression site.

Graphify ở mức **khá tốt** cho câu hỏi "ai import/annotate kiểu nào", nhưng **không trung thực** với câu hỏi "ai tạo object khi chạy" (thiếu 3 backend constructor, thừa 6 fixture test) và hoàn toàn không thấy được việc ép metadata thành chuỗi ở `prompts.py:6-7`. Những edge cần verify thủ công: 6 cạnh INFERRED, cạnh `inherits BaseModel` (external node), và mọi suy luận dựa trên community name.
