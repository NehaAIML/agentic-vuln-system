#!/usr/bin/env python3
"""
harden_05_fix_create_pr_again.py

Final mypy cleanup:
  1. create_pr.py  : replace buggy `repo_path: Path = Path(repo_path)` with
                     a fresh `repo_root = Path(repo_path)` and rename all
                     subsequent uses of `repo_path / ...` to `repo_root / ...`
  2. .pre-commit-config.yaml : add types-PyYAML to mypy hook dependencies

DRY_RUN preview. ast.parse() validation. .bak backups. Refuses if anchors missing.
"""

from __future__ import annotations

import ast
import re
import shutil
import sys
from pathlib import Path

DRY_RUN = False

REPO_ROOT = Path.cwd()
TARGET_PY = REPO_ROOT / "create_pr.py"
TARGET_YAML = REPO_ROOT / ".pre-commit-config.yaml"


def fix_create_pr(text: str) -> tuple[str, list[str]]:
    notes: list[str] = []

    # 1) Remove the buggy re-annotation line and introduce repo_root
    bad = "    repo_path: Path = Path(repo_path)\n"
    good = "    repo_root = Path(repo_path)\n"
    if bad in text:
        text = text.replace(bad, good, 1)
        notes.append("replaced `repo_path: Path = Path(...)` with `repo_root = Path(...)`")
    elif good in text:
        notes.append("repo_root already present (skipped)")
    else:
        raise RuntimeError("anchor `repo_path: Path = Path(repo_path)` not found")

    # 2) Rename uses inside the function body: `repo_path /` -> `repo_root /`
    #    and `cwd=repo_path` -> `cwd=repo_root`
    body_start = text.find("def create_pr")
    head, body = text[:body_start], text[body_start:]

    n_slash = len(re.findall(r"\brepo_path\s*/", body))
    body = re.sub(r"\brepo_path\s*/", "repo_root /", body)
    if n_slash:
        notes.append(f"renamed {n_slash} use(s) of `repo_path /` -> `repo_root /`")

    n_cwd = len(re.findall(r"cwd=repo_path\b", body))
    body = re.sub(r"\bcwd=repo_path\b", "cwd=repo_root", body)
    if n_cwd:
        notes.append(f"renamed {n_cwd} use(s) of `cwd=repo_path` -> `cwd=repo_root`")

    # 3) Remove now-unused `from typing import Optional`? No — still needed for vuln_id.
    return head + body, notes


def fix_pre_commit_yaml(text: str) -> tuple[str, list[str]]:
    notes: list[str] = []
    if "types-PyYAML" in text:
        notes.append("types-PyYAML already in .pre-commit-config.yaml (skipped)")
        return text, notes

    old = "additional_dependencies: [types-requests]"
    new = "additional_dependencies: [types-requests, types-PyYAML]"
    if old in text:
        text = text.replace(old, new, 1)
        notes.append("added types-PyYAML to mypy hook additional_dependencies")
    else:
        notes.append("ANCHOR NOT FOUND: `additional_dependencies: [types-requests]`")
    return text, notes


def show_region(text: str, needle: str, before: int = 2, after: int = 5) -> str:
    lines = text.splitlines()
    for i, ln in enumerate(lines):
        if needle in ln:
            lo = max(0, i - before)
            hi = min(len(lines), i + after + 1)
            return "\n".join(f"  {j+1:4d} | {lines[j]}" for j in range(lo, hi))
    return "  (needle not found)"


def main() -> int:
    print(f"Repo root : {REPO_ROOT}")
    print(f"DRY_RUN   : {DRY_RUN}")
    print("=" * 60)

    if not TARGET_PY.exists():
        print(f"ERROR: {TARGET_PY} not found.")
        return 1

    original = TARGET_PY.read_text(encoding="utf-8")
    try:
        patched, notes = fix_create_pr(original)
    except RuntimeError as e:
        print(f"ABORT: {e}")
        return 2

    print("\ncreate_pr.py")
    for n in notes:
        print(f"  + {n}")

    try:
        ast.parse(patched)
        print("  ast.parse(): OK")
    except SyntaxError as e:
        print(f"  ABORT: would not parse: {e}")
        return 3

    print("\n--- region: function head ---")
    print(show_region(patched, "def create_pr", before=0, after=6))

    print("\n--- region: first `repo_root /` use ---")
    print(show_region(patched, "repo_root /", before=2, after=3))

    yaml_text = None
    yaml_notes: list[str] = []
    if TARGET_YAML.exists():
        yaml_text_orig = TARGET_YAML.read_text(encoding="utf-8")
        yaml_text, yaml_notes = fix_pre_commit_yaml(yaml_text_orig)
        print("\n.pre-commit-config.yaml")
        for n in yaml_notes:
            print(f"  + {n}")
        print("\n--- region: mypy hook ---")
        print(show_region(yaml_text, "mypy", before=1, after=4))

    if DRY_RUN:
        print("\nDRY_RUN is ON - nothing was written.")
        print("Set DRY_RUN = False and run again to apply.")
        return 0

    bak_py = TARGET_PY.with_suffix(".py.bak")
    shutil.copy2(TARGET_PY, bak_py)
    TARGET_PY.write_text(patched, encoding="utf-8")
    print(f"WROTE  : {TARGET_PY}")
    print(f"BACKUP : {bak_py}")

    if yaml_text is not None and yaml_text != yaml_text_orig:
        bak_y = TARGET_YAML.with_suffix(".yaml.bak")
        shutil.copy2(TARGET_YAML, bak_y)
        TARGET_YAML.write_text(yaml_text, encoding="utf-8")
        print(f"WROTE  : {TARGET_YAML}")
        print(f"BACKUP : {bak_y}")

    print("\nNext:")
    print("  pre-commit run --all-files     # expect all green")
    print(
        '  git add -A && git commit -m "fix(types): correct repo_path->repo_root in create_pr; add types-PyYAML to pre-commit mypy"'
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
