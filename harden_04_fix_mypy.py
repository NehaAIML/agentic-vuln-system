#!/usr/bin/env python3
"""
harden_04_fix_mypy.py

Clears the final 8 mypy/ruff findings so `pre-commit run --all-files` is green.

Fixes:
  tests/test_patch_generator.py   E741  l -> line
  scanners/reachability.py:130    narrow `root` type before ast.Name check
  create_pr.py:8                  vuln_id: str = None -> Optional[str] = None
  create_pr.py:9                  convert repo_path to Path before annotations bind
  create_pr.py:95                 narrow vuln_id after result lookup
  pyproject.toml                  add types-PyYAML to dev extras

DRY_RUN preview. .bak backup. ast.parse() validation. Refuses if anchors missing.
"""

from __future__ import annotations

import ast
import re
import shutil
import sys
from pathlib import Path

DRY_RUN = False

REPO_ROOT = Path.cwd()


def show_region(text: str, needle: str, before: int = 2, after: int = 4) -> str:
    lines = text.splitlines()
    for i, ln in enumerate(lines):
        if needle in ln:
            lo = max(0, i - before)
            hi = min(len(lines), i + after + 1)
            return "\n".join(f"  {j+1:4d} | {lines[j]}" for j in range(lo, hi))
    return "  (needle not found)"


# ---------------------------------------------------------------------------
# Individual fixers
# ---------------------------------------------------------------------------


def fix_test_rename(text: str) -> tuple[str, str]:
    # E741: `[l for l in ...]` -> `[line for line in ...]`
    pat = re.compile(r"\[l\s+for\s+l\s+in\s+")
    if pat.search(text):
        text = pat.sub("[line for line in ", text)
        text = text.replace("len(hunk_body)", "len(hunk_body)")  # no-op, idempotent marker
        # also rename the inner reference in the assert message if present
        text = text.replace("got {len(hunk_body)}", "got {len(hunk_body)}")
        return text, "E741: renamed `l` -> `line` in hunk_body comprehension"
    return text, "E741: no change needed (skipped)"


def fix_reachability(text: str) -> tuple[str, str]:
    """
    The error at line 130 is:
        root = node                       # node: ast.Attribute
        while isinstance(root, ast.Attribute):
            root = root.value             # root.value: ast.expr  -> mismatch

    mypy's issue is that `root` is inferred as ast.Attribute on first bind,
    then reassigned to ast.expr. Fix by annotating `root: ast.expr = node`
    before the loop.
    """
    old_block = (
        "        def visit_Attribute(self, node: ast.Attribute):\n"
        "            root = node\n"
        "            while isinstance(root, ast.Attribute):\n"
        "                root = root.value\n"
    )
    new_block = (
        "        def visit_Attribute(self, node: ast.Attribute):\n"
        "            root: ast.expr = node\n"
        "            while isinstance(root, ast.Attribute):\n"
        "                root = root.value\n"
    )
    if old_block in text:
        return text.replace(old_block, new_block, 1), "reachability: annotated `root: ast.expr`"
    if "root: ast.expr = node" in text:
        return text, "reachability: already annotated (skipped)"
    return text, "reachability: ANCHOR NOT FOUND (manual review)"


def fix_create_pr(text: str) -> tuple[str, str]:
    notes = []

    # 1. signature: vuln_id: str = None -> Optional[str] = None
    if "def create_pr(repo_path: str, results_json: str, vuln_id: str = None):" in text:
        text = text.replace(
            "def create_pr(repo_path: str, results_json: str, vuln_id: str = None):",
            "def create_pr(repo_path: str, results_json: str, vuln_id: Optional[str] = None):",
            1,
        )
        notes.append("signature: vuln_id -> Optional[str]")
    elif "Optional[str] = None" in text:
        notes.append("signature: already Optional (skipped)")
    else:
        notes.append("signature: ANCHOR NOT FOUND")

    # 2. import Optional
    if "from typing import Optional" not in text:
        text = text.replace(
            "from pathlib import Path\n",
            "from pathlib import Path\nfrom typing import Optional\n",
            1,
        )
        notes.append("added `from typing import Optional`")

    # 3. body: repo_path = Path(repo_path) -> repo_path_obj = Path(repo_path) then use obj
    old = "    repo_path = Path(repo_path)\n"
    new = "    repo_path: Path = Path(repo_path)\n"
    if old in text:
        text = text.replace(old, new, 1)
        notes.append("body: annotated repo_path: Path after conversion")

    # 4. vuln_id reassign at line ~95: after we know result["vuln_id"] is str
    old_assign = '    vuln_id = result["vuln_id"]\n'
    new_assign = '    vuln_id = str(result["vuln_id"])\n'
    if old_assign in text:
        text = text.replace(old_assign, new_assign, 1)
        notes.append("body: vuln_id <- str(result['vuln_id']) to narrow Optional[str]")

    return text, "create_pr.py: " + "; ".join(notes)


def fix_pyproject(text: str) -> tuple[str, str]:
    if "types-PyYAML" in text:
        return text, "pyproject: types-PyYAML already present (skipped)"
    anchor = '    "pre-commit",\n'
    if anchor not in text:
        return text, "pyproject: dev extras anchor NOT FOUND (manual review)"
    text = text.replace(anchor, anchor + '    "types-PyYAML",\n', 1)
    return text, "pyproject: added types-PyYAML to dev extras"


# ---------------------------------------------------------------------------

TARGETS = {
    "tests/test_patch_generator.py": fix_test_rename,
    "scanners/reachability.py": fix_reachability,
    "create_pr.py": fix_create_pr,
}


def main() -> int:
    print(f"Repo root : {REPO_ROOT}")
    print(f"DRY_RUN   : {DRY_RUN}")
    print("=" * 60)

    staged: list[tuple[Path, str, str]] = []  # (path, new_text, summary)

    for rel, fixer in TARGETS.items():
        p = REPO_ROOT / rel
        if not p.exists():
            print(f"\n[skip] {rel} not found")
            continue
        original = p.read_text(encoding="utf-8")
        patched, summary = fixer(original)
        print(f"\n{rel}")
        print(f"  {summary}")
        if patched != original:
            try:
                ast.parse(patched)
                print("  ast.parse(): OK")
            except SyntaxError as e:
                print(f"  ABORT: {rel} would not parse: {e}")
                return 3
            staged.append((p, patched, summary))
        else:
            print("  (no changes)")

    # pyproject
    pp = REPO_ROOT / "pyproject.toml"
    if pp.exists():
        original = pp.read_text(encoding="utf-8")
        patched, summary = fix_pyproject(original)
        print("\npyproject.toml")
        print(f"  {summary}")
        if patched != original:
            staged.append((pp, patched, summary))

    # preview regions
    print("\n" + "=" * 60)
    print("Preview regions")
    print("=" * 60)
    for p, patched, _ in staged:
        print(f"\n--- {p.relative_to(REPO_ROOT)} ---")
        needle = {
            "tests/test_patch_generator.py": "hunk_body",
            "scanners/reachability.py": "root: ast.expr",
            "create_pr.py": "def create_pr",
        }.get(str(p.relative_to(REPO_ROOT)), "types-PyYAML")
        print(show_region(patched, needle, before=1, after=3))

    if DRY_RUN:
        print("\nDRY_RUN is ON - nothing was written.")
        print("Set DRY_RUN = False and run again to apply.")
        return 0

    for p, patched, _ in staged:
        bak = p.with_suffix(p.suffix + ".bak")
        shutil.copy2(p, bak)
        p.write_text(patched, encoding="utf-8")
        print(f"WROTE  : {p}")
        print(f"BACKUP : {bak}")

    print(
        "\nNext:"
        '\n  pip install -e ".[dev]"        # picks up types-PyYAML'
        "\n  pre-commit run --all-files     # should be fully green"
        '\n  git add -A && git commit -m "fix(types): clear mypy/ruff findings; add types-PyYAML"'
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
