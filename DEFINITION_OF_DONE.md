# Definition of Done — ThreatWatch v1.1.0

A) CLI stable
- `--json` prints valid JSON to stdout (no human text mixed)

B) E2E test (real)
- Runs CLI against `sample_data/auth.log`
- Asserts exit code 0
- Parses stdout as JSON and validates minimal required keys

C) Tests and CI
- `pytest` passes locally
- GitHub Actions passes on main

D) Repo structure docs
- ROLE.md (what it is / what it is not)
- ARCHITECTURE.md (ingest → parse → detect → output)
- DEFINITION_OF_DONE.md (this checklist)

E) Demo reproducible
- README: Quickstart (5–8 lines)
- Example JSON output stored in `reports/sample_output.json` (or a short snippet)

F) Release
- Git tag `v1.1.0`
- Short release notes: what it does, how to run, evidence (tests/CI)
