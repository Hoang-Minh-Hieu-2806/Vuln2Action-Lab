# Labs

Each `labs/<id>/` is an **isolated, team-owned vulnerable lab** for one sample
CVE. Labs run on localhost via their own `docker-compose.yml` and are never
pointed at real-world systems.

Layout per lab:

```
labs/cve-001/
  docker-compose.yml   # builds/serves the vulnerable target on 127.0.0.1 only
  README.md            # what the lab demonstrates + how to validate
  target/              # minimal demo app (fake vulnerability, Phase 5)
  validation/          # validation script producing PASS/FAIL (Phase 5/6)
```

Current labs (all Phase-1 placeholders, no live services yet):

- `cve-001` <-> `CVE-2024-0001` (fake XSS-style demo)
- `cve-002` <-> `CVE-2024-0002` (fake SQLi-style demo)
- `cve-003` <-> `CVE-2024-0003` (fake path-traversal demo)
