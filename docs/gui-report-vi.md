# B?o c?o Flask GUI

Ng?y ch?y: 2026-11-05  
Nh?nh: `codex/paper-reproduction`  
App: `gui/app.py`  
Dataset: `data/processed/reproduction/`

## 1. Ch?y local

```bash
pip install -e ".[gui]"
python gui/app.py
```

M? `http://127.0.0.1:5000`. App ch? bind localhost, kh?ng g?i m?ng ngo?i.

## 2. Ch?c n?ng

- Nh?p CVE id c? trong 55k dataset, ho?c d?n m? t? l? h?ng.
- V?i CVE ?? c? prediction: d?ng CAPEC ?? ch?n b?i Word2Vec (precomputed).
- V?i m? t? t? do: d?ng TF-IDF tr?n to?n b? CAPEC.
- Hi?n th? 3 pha Explore / Experiment / Exploit, t?ng step v? technique.
- Hi?n th? technique ? ExploitDB description n?u c? mapping stage 2.
- Hi?n th? candidate CAPEC v? ?i?m cosine.
- API JSON: `GET /api/analyze?cve_id=...`; health: `GET /health`.

## 3. Ki?m tra v?i dataset th?t

```text
/health:
  cves=55.000
  capecs=615
  predictions=39.181
  technique_mappings=665

/api/analyze?cve_id=CVE-2010-20125:
  selected_capec=CAPEC-193
  method=precomputed Word2Vec
  phases=3
```

Unit tests:

```bash
pytest -q tests/unit/test_gui.py
```

## 4. An to?n

- Read-only: kh?ng c? endpoint ch?y l?nh, kh?ng t?i exploit code.
- Ch? ??c file local trong dataset.
- Bind `127.0.0.1`, kh?ng public ra m?ng.
- Kh?ng hi?n th? hay th?c thi exploit source code; ch? description/metadata.

## 5. Gi?i h?n

GUI hi?n hi?n th? **CAPEC flow tham chi?u** v? mapping ExploitDB description,
ch?a g?i checkpoint T5 ?? sinh flow. Khi c? checkpoint stage 1/2, c? th? th?m
ch? ?? "generated flow" b?ng `T5Generator` ho?c m?t endpoint ri?ng; c?n gi?
nguy?n t?c kh?ng t? ??ng ch?y exploit.

Kh?ng ???c m? t? GUI l? "t? ??ng khai th?c". ??y l? c?ng c? tra c?u/tr?nh b?y
flow v? metadata trong lab local.
