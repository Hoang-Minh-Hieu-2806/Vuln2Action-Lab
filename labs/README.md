# Labs

Each `labs/<id>/` is an **isolated, team-owned vulnerable lab** for one sample
CVE. Labs run on localhost via their own `docker-compose.yml` and are never
pointed at real-world systems.

Layout per lab:

```
labs/cve-001/
  docker-compose.yml   # builds/serves the vulnerable target on 127.0.0.1 only
  lab.yaml             # manifest: status, allowed hosts, setup/validate/teardown commands
  README.md            # what the lab demonstrates + how to validate
  target/              # minimal demo app (Dockerfile + app)
  validation/          # validator producing PASS/FAIL
```

Current labs:

- `cve-001` <-> `CVE-2024-0001` — **live** demo (output-encoding / XSS-style)
  with vulnerable + patched services and a real PASS/FAIL validator.
- `cve-002` <-> `CVE-2024-0002` — placeholder (SQLi-style demo).
- `cve-003` <-> `CVE-2024-0003` — placeholder (path-traversal demo).

Only labs with `status: ready` and a `has_patched_counterfactual: true`
manifest may produce a real `PASS`.
