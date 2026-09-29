#!/usr/bin/env python3
"""harden_02_pin_deps.py (mypy-clean) - pins requirements*.txt to PyPI latest."""

from __future__ import annotations

import json
import re
import shutil
import sys
import urllib.request
from pathlib import Path

DRY_RUN = False  # already applied once; safe to leave False

REPO_ROOT = Path.cwd()
REQ_FILES = ["requirements.txt", "requirements-dashboard.txt"]
PYPROJECT = "pyproject.toml"
DEV_ONLY = {"pytest", "pytest-cov", "responses", "ruff", "black", "mypy", "pre-commit"}

REQ_LINE = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9_.\-]+)" r"(?P<extras>\[[^\]]+\])?" r"\s*(?P<spec>[<>=!~].*)?$"
)

Row = tuple[str, "str | None", "str | None"]


def latest_version(pkg: str) -> "str | None":
    url = f"https://pypi.org/pypi/{pkg}/json"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            data = json.load(resp)
        return data["info"]["version"]
    except Exception as e:
        print(f"    !! PyPI lookup failed for {pkg}: {e}")
        return None


def parse_requirements(path: Path) -> list[Row]:
    out: list[Row] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            out.append((raw, None, None))
            continue
        m = REQ_LINE.match(stripped)
        if not m:
            print(f"    [warn] unparsed line in {path.name}: {raw!r}")
            out.append((raw, None, None))
            continue
        name = m.group("name")
        spec = m.group("spec") or ""
        if spec.startswith("=="):
            out.append((raw, name, raw))
        else:
            out.append((raw, name, None))
    return out


def pin_file(path: Path, dry: bool) -> dict[str, str]:
    if not path.exists():
        print(f"  [skip] {path.name} does not exist")
        return {}
    print(f"\n  {path.name}:")
    parsed = parse_requirements(path)
    pinned: dict[str, str] = {}
    new_lines: list[str] = []
    for raw, name, already in parsed:
        if name is None:
            new_lines.append(raw)
            continue
        if already is not None:
            ver_match = re.search(r"==\s*([^\s;#]+)", already)
            ver = ver_match.group(1) if ver_match else "?"
            print(f"    [keep]   {raw.strip()}")
            pinned[name] = ver
            new_lines.append(raw)
            continue
        ver = latest_version(name)
        if ver is None:
            new_lines.append(raw)
            continue
        new_line = f"{name}=={ver}"
        print(f"    [pin]    {raw.strip()}  ->  {new_line}")
        pinned[name] = ver
        new_lines.append(new_line)
    if dry:
        return pinned
    bak = path.with_suffix(path.suffix + ".bak")
    shutil.copy2(path, bak)
    path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
    print(f"    backup : {bak.name}")
    return pinned


def sync_pyproject(pins: dict[str, str], dry: bool) -> None:
    pp = REPO_ROOT / PYPROJECT
    if not pp.exists():
        print(f"\n  [skip] {PYPROJECT} not found")
        return
    text = pp.read_text(encoding="utf-8")
    runtime = {n: v for n, v in pins.items() if n.lower() not in DEV_ONLY}
    if not runtime:
        print(f"\n  [skip] no runtime deps to sync into {PYPROJECT}")
        return
    dep_lines = ",\n".join(f'    "{n}=={v}"' for n, v in sorted(runtime.items()))
    new_block = f"dependencies = [\n{dep_lines},\n]"
    pattern = re.compile(r"dependencies\s*=\s*\[[^\]]*\]", re.DOTALL)
    if not pattern.search(text):
        print(f"\n  [warn] no dependencies block found in {PYPROJECT}")
        return
    updated = pattern.sub(new_block, text, count=1)
    print(f"\n  {PYPROJECT} dependencies block:")
    print("    --- proposed ---")
    for ln in new_block.splitlines():
        print(f"    {ln}")
    if dry:
        return
    shutil.copy2(pp, pp.with_suffix(".toml.bak"))
    pp.write_text(updated, encoding="utf-8")
    print(f"    backup : {PYPROJECT}.bak")


def main() -> int:
    print(f"Repo root : {REPO_ROOT}")
    print(f"DRY_RUN   : {DRY_RUN}")
    print("=" * 60)
    all_pins: dict[str, str] = {}
    for fname in REQ_FILES:
        pins = pin_file(REPO_ROOT / fname, DRY_RUN)
        all_pins.update(pins)
    rt = REPO_ROOT / "requirements.txt"
    if rt.exists():
        rt_pins: dict[str, str] = {}
        for raw, name, already in parse_requirements(rt):
            if name is None:
                continue
            if already:
                m = re.search(r"==\s*([^\s;#]+)", already)
                if m:
                    rt_pins[name] = m.group(1)
            elif name in all_pins:
                rt_pins[name] = all_pins[name]
        sync_pyproject(rt_pins, DRY_RUN)
    print("\n" + "=" * 60)
    if DRY_RUN:
        print("DRY_RUN is ON - nothing was written.")
    else:
        print("Done. Review with:  git diff")
    return 0


if __name__ == "__main__":
    sys.exit(main())
