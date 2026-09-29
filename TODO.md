# TODO

Items requiring further work. Completed items are kept below for context.

## Open

### Reproducibility
- [ ] Generate a lockfile for the dev environment (`uv lock` or `pip-compile`).
      Currently `pyproject.toml` declares pinned direct deps but transitives
      are resolved at install time.

### Polish
- [ ] Add a coverage badge to README (`pytest-cov` is already configured).
- [ ] Add ADRs under `docs/adr/` for two load-bearing decisions:
  - AST call-graph reachability vs. runtime tracing
  - Sandboxed TDD verification vs. trusting a second LLM review
- [ ] Consolidate the three "## Dashboard"-adjacent headings in README
      (`## Dashboard Preview` image + `## Dashboard` section) into one.

### Benchmark expansion
- [ ] Run the reachability benchmark against at least one more fixture to
      strengthen the "one fixture" limitation noted in `benchmarks/README.md`.
- [ ] Consider an alias-table audit pass: pull the top 500 PyPI packages by
      download count, flag any whose import name differs from their package
      name, and add missing entries to `PYPI_TO_IMPORT_NAME`.

## Completed

Tracked here for context — see git history for details.

### Correctness / credibility
- [x] Mocked-response tests for `scanners/prioritization.py` (11 tests).
- [x] `SECURITY.md` now documents the actual isolation model (temp dir,
      network on, no resource limits, secrets inherited).
- [x] Every dependency in `pyproject.toml` pinned to match `requirements*.txt`.

### Reproducibility
- [x] Retry cap configurable via `MAX_REPAIR_ATTEMPTS` env var (default 3).
- [x] Structured `run_report.json` written per pipeline run.

### Evidence
- [x] `benchmarks/` folder with ground truth, scan input, scored output,
      and a scoring script. Results: 100% precision / 100% recall / 100%
      accuracy under strict scoring; 100% / 83% / 89% under loose scoring.
- [x] README "Limitations" section documents known scope boundaries.
- [x] README "Dashboard" section documents stack, launch command, inputs.

### Polish
- [x] Conventional commits used throughout.
- [x] Real bug fixed: `yaml.load` -> `yaml.safe_load` in `sample_repo/app.py`.
- [x] Reachability aliases added: pyOpenSSL, pysaml2, python-jwt.
