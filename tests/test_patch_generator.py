"""
test_patch_generator.py
------------------------
Unit tests for agent/patch_generator.py. The critical property under test:
clean_diff_output() must strip LLM commentary/markdown fences WITHOUT ever
truncating meaningful diff content (trailing blank context lines especially
-- this caused a real corrupt-patch bug during development).
"""

import subprocess
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from agent.patch_generator import clean_diff_output, call_dry_run


def test_strips_markdown_fence_and_leading_commentary():
    raw = (
        "Sure, here's the fix:\n\n```diff\n"
        "diff --git a/app.py b/app.py\n"
        "index 111..222 100644\n"
        "--- a/app.py\n+++ b/app.py\n"
        "@@ -1,1 +1,1 @@\n-old\n+new\n"
        "```\n"
    )
    cleaned = clean_diff_output(raw)
    assert cleaned.startswith("diff --git")
    assert "```" not in cleaned
    assert "Sure, here's the fix" not in cleaned


def test_preserves_trailing_blank_context_lines():
    """
    Regression test for the real bug: a diff whose last hunk ends with
    blank context lines used to get those lines silently stripped by a
    blanket .strip(), leaving a hunk header (@@ -a,N +a,N @@) that no
    longer matched the actual line count -- i.e. a corrupt patch that
    looks fine until you try to `git apply` it.
    """
    raw = (
        "diff --git a/app.py b/app.py\n"
        "index 111..222 100644\n"
        "--- a/app.py\n+++ b/app.py\n"
        "@@ -1,5 +1,5 @@\n"
        " context1\n"
        "-old\n"
        "+new\n"
        " context2\n"
        " \n"  # trailing blank context line -- must survive cleaning
    )
    cleaned = clean_diff_output(raw)
    lines = cleaned.splitlines()
    # The hunk header claims 5 old / 5 new lines; count the actual body lines
    # that follow the @@ header and belong to the hunk (context/-/+ prefixed).
    hunk_body = [line for line in lines[lines.index("@@ -1,5 +1,5 @@") + 1 :]]
    assert len(hunk_body) == 5, f"expected 5 hunk lines, got {len(hunk_body)}: {hunk_body}"


def test_no_diff_header_returns_stripped_text_without_crashing():
    cleaned = clean_diff_output("I could not find a fix for this issue.")
    assert "diff --git" not in cleaned
    assert cleaned.strip() == "I could not find a fix for this issue."


def test_dry_run_pyyaml_diff_actually_applies_with_git(tmp_path):
    """
    End-to-end check that the dry-run backend's diff isn't just
    well-formed in the abstract, but actually applies cleanly with real
    `git apply` against a real file on disk.
    """
    app_py = tmp_path / "app.py"
    app_py.write_text(
        "import yaml\n\n\ndef load_config(raw_yaml):\n" "    return yaml.load(raw_yaml)\n"
    )
    vuln = {
        "id": "CVE-TEST",
        "package": "PyYAML",
        "installed_version": "5.3.1",
        "fixed_version": "5.4",
    }
    context = {"file": "app.py"}

    diff = call_dry_run(vuln, context, repo_root=str(tmp_path))
    cleaned = clean_diff_output(diff)

    patch_file = tmp_path / "test.diff"
    patch_file.write_text(cleaned)

    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    result = subprocess.run(
        ["git", "apply", "--check", str(patch_file)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"git apply --check failed: {result.stderr}"

    subprocess.run(["git", "apply", str(patch_file)], cwd=tmp_path, check=True)
    patched = app_py.read_text()
    assert "Loader=yaml.SafeLoader" in patched


def test_dry_run_unknown_package_returns_noop_diff_without_crashing(tmp_path):
    app_py = tmp_path / "app.py"
    app_py.write_text("import somepkg\nsomepkg.do_thing()\n")
    vuln = {
        "id": "CVE-X",
        "package": "SomeUnknownPkg",
        "installed_version": "1.0",
        "fixed_version": "1.1",
    }
    context = {"file": "app.py"}
    diff = call_dry_run(vuln, context, repo_root=str(tmp_path))
    assert diff.startswith("diff --git")
