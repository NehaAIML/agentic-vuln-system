#!/usr/bin/env python3
"""
Final README cleanup:
  1. Remove the second (duplicate) ## Project Structure
  2. Move the first one so order is: Highlights -> Project Structure -> 1. Background
  3. Remove redundant H2 title + italic tagline under H1
  4. Update section 2 text: EPSS is now covered by tests
  5. Update section 3 count + description to match reality
"""
from pathlib import Path
import re, shutil, sys

DRY_RUN = False
TARGET = Path.cwd() / "README.md"


def main() -> int:
    print(f"Target  : {TARGET}")
    print(f"DRY_RUN : {DRY_RUN}")
    print("=" * 60)
    if not TARGET.exists():
        print("ERROR: README.md not found."); return 1

    text = TARGET.read_text(encoding="utf-8")
    changes = []
    original = text

    # --- 1. Remove the redundant H2 title + italic tagline (if present) ---
    for block in [
        "## Agentic Vulnerability Triage and Automated Patching System\n\n",
        "### **[ Autonomous Vulnerability Triage & Automated Patching Engine ]**\n\n",
        "_AST Reachability | EPSS Threat Intel | Sandboxes | Self-Repair_\n\n",
        "[ Autonomous Vulnerability Triage & Automated Patching Engine ]\n\n",
    ]:
        if block in text:
            text = text.replace(block, "", 1)
            changes.append(f"removed redundant block: {block.splitlines()[0][:50]}")

    # --- 2. Remove the SECOND ## Project Structure block (the duplicate) ---
    # Find all occurrences of the structure heading
    struct_pat = re.compile(r"## Project Structure\n~~~text\n.*?\n~~~\n\n?", re.DOTALL)
    matches = list(struct_pat.finditer(text))
    if len(matches) > 1:
        # Remove all but the first
        for m in reversed(matches[1:]):
            text = text[:m.start()] + text[m.end():]
        changes.append(f"removed {len(matches)-1} duplicate Project Structure block(s)")
    elif len(matches) == 1:
        changes.append("only one Project Structure block (correct)")

    # --- 3. Move Project Structure to sit right after Highlights ---
    struct_match = struct_pat.search(text)
    if struct_match:
        struct_block = struct_match.group(0)
        text = text[:struct_match.start()] + text[struct_match.end():]
        # Insert before "## 1. Background & Motivation"
        anchor = "## 1. Background & Motivation"
        if anchor in text:
            text = text.replace(anchor, struct_block + anchor, 1)
            changes.append("moved Project Structure above section 1")

    # --- 4. Fix the EPSS "not covered" claim in section 2 ---
    old_epss = "Not currently covered by the test suite — treat scores as informational until a mocked-response test exists."
    new_epss = "Covered by 11 mocked-response tests in `tests/test_prioritization.py` (commit ceeb6ac)."
    if old_epss in text:
        text = text.replace(old_epss, new_epss, 1)
        changes.append("updated section 2: EPSS is now tested")

    # --- 5. Fix the "38 tests" claim in section 3 ---
    old_count = "38 Passing Unit Tests"
    new_count = "Passing Unit Tests"
    if old_count in text:
        text = text.replace(old_count, new_count, 1)
        changes.append("softened '38 Passing Unit Tests' claim")

    old_desc = "Fully cover reachability resolution, AST call-graph construction, diff sanitization, and retry logic."
    new_desc = "Cover reachability resolution, AST call-graph construction, diff sanitization, retry logic, and EPSS scoring/prioritization."
    if old_desc in text:
        text = text.replace(old_desc, new_desc, 1)
        changes.append("expanded tests description")

    print("\nPlanned changes:")
    if not changes:
        print("  (none - README already clean)")
    for c in changes:
        print(f"  + {c}")

    if text == original:
        print("\nNo changes to write.")
        return 0

    if DRY_RUN:
        print("\nDRY_RUN is ON - nothing was written.")
        return 0

    shutil.copy2(TARGET, TARGET.with_suffix(".md.bak2"))
    TARGET.write_text(text, encoding="utf-8")
    print(f"\nWROTE  : {TARGET}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
