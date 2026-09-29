#!/usr/bin/env python3
"""
harden_09_security_md.py

Replaces the SECURITY.md placeholder block with the honest isolation model
that matches what sandbox_runner.py actually does.

DRY_RUN preview. .bak backup. Refuses if the placeholder anchor is missing.
"""

from __future__ import annotations
import shutil
import sys
from pathlib import Path

DRY_RUN = False
TARGET = Path.cwd() / "SECURITY.md"

OLD = """## Threat Model of This Tool

This project scans *other* repositories and executes AI-generated patches.
It is therefore itself a security-sensitive component.

>>> EDIT THIS SECTION — do not ship as-is <<<

- Sandbox mechanism: [ ] temp dir only  [ ] Docker  [ ] nsjail/firejail  [ ] VM
- Network access inside sandbox: [ ] enabled  [ ] disabled
- Resource limits (CPU/mem/disk): [ ] none  [ ] specified below
- Secrets exposed to generated code: [ ] possible  [ ] prevented

Until the above is filled in and verified, do not run this pipeline
against untrusted repositories or with production credentials present.
"""

NEW = """## Threat Model of This Tool

This project scans *other* repositories and executes AI-generated patches.
It is therefore itself a security-sensitive component.

### Current Isolation Model

**Not hardened for untrusted input.** Treat this tool as a development
aid, not a production sandbox.

- **Sandbox mechanism:** plain `tempfile.mkdtemp()` — filesystem-level
  copy of the target repo. No container, no VM, no OS-level isolation.
- **Network access:** enabled. Generated patches and test commands run
  with the host's network stack available.
- **Resource limits:** none. No CPU, memory, disk, or wall-clock caps
  beyond per-command `timeout=` arguments.
- **Secrets:** inherited from the parent environment. Do **not** run
  this pipeline with production credentials present (AWS keys, GitHub
  tokens, etc.) in the environment.

### Recommendations Before Running

- Run against test/fork repositories only.
- Unset sensitive environment variables first:
  `env -i PATH="$PATH" python run_pipeline.py ...`
- For untrusted input, wrap the process in a container yourself
  (Docker, `nsjail`, `firejail`, or a VM). This is on the roadmap.
"""


def main() -> int:
    print(f"Target  : {TARGET}")
    print(f"DRY_RUN : {DRY_RUN}")
    print("=" * 60)

    if not TARGET.exists():
        print("ERROR: SECURITY.md not found.")
        return 1

    text = TARGET.read_text(encoding="utf-8")

    if "Current Isolation Model" in text:
        print("  [skip] isolation model already documented")
        return 0

    if OLD not in text:
        print("  [ABORT] placeholder anchor not found")
        print("          SECURITY.md may have been edited. Manual review needed.")
        return 2

    text = text.replace(OLD, NEW, 1)
    print("  [ok] replaced placeholder with honest isolation model")
    print(f"       old block: {len(OLD)} chars")
    print(f"       new block: {len(NEW)} chars")

    if DRY_RUN:
        print("\nDRY_RUN is ON - nothing was written.")
        return 0

    bak = TARGET.with_suffix(".md.bak")
    shutil.copy2(TARGET, bak)
    TARGET.write_text(text, encoding="utf-8")
    print(f"\nWROTE  : {TARGET}")
    print(f"BACKUP : {bak}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
