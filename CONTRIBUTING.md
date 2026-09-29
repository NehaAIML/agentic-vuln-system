# Contributing

1. Fork and branch from `main`.
2. `python -m venv .venv && source .venv/bin/activate`
3. `pip install -e .[dev]`
4. `pre-commit install`
5. `pytest`  — all tests must pass; new logic needs tests.
6. Open a PR with a conventional-commit title, e.g. `fix(scanners): ...`.

## Commit style
`type(scope): short subject` — types: feat, fix, docs, test, chore, ci, refactor.
