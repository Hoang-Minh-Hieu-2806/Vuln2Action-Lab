# Problem statement

Security analysts and students face a flood of published CVEs, but a CVE
description alone rarely tells you **whether and how a vulnerability is
reproducible**:

- CVE text is short, inconsistent, and often lacks reproduction steps.
- Relevant context is scattered across CWE (weakness type), CPE (affected
  products), CAPEC (attack patterns), and external references.
- Reproduction environments drift: library versions, configs, and setups that
  worked once are hard to recreate and share.
- Validation is ad hoc: "it looked vulnerable" is not a repeatable PASS/FAIL.

**Vuln2Action-Lab** addresses this by building a small, extensible pipeline:

1. **Ingest** CVE/CWE/CPE/CAPEC/reference records into uniform schemas.
2. **Retrieve** the most relevant vulnerability knowledge for a given CVE.
3. **Generate** a structured, human-readable *reproduction workflow*
   (rule-based baseline first, LLM/T5 later).
4. **Execute + validate** that workflow against an **isolated Docker lab**
   only, producing a PASS/FAIL verdict plus collected evidence.
5. **Report** the evidence so a third party can re-run and confirm.

The project prioritises *reproducibility and safety* over exploit sophistication.
