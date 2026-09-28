"""
test_reachability.py
---------------------
Unit tests for scanners/reachability.py. This module is the highest-stakes
piece of correctness in the whole pipeline: a false "unreachable" verdict
means a real vulnerability gets silently deprioritized, and a false
"reachable" verdict wastes an LLM call + sandbox run on dead code.
"""
import json
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from scanners.reachability import (
    find_reachable_packages, filter_vulnerabilities, resolve_import_name
)


@pytest.fixture
def tmp_repo():
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)


def write(repo: Path, relpath: str, content: str):
    p = repo / relpath
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    return p


def test_direct_call_is_reachable(tmp_repo):
    write(tmp_repo, "app.py", "import yaml\nyaml.load('x')\n")
    results = find_reachable_packages(str(tmp_repo), ["yaml"])
    assert results[0].reachable is True
    assert results[0].usages[0].line == 2


def test_unused_import_is_unreachable(tmp_repo):
    write(tmp_repo, "app.py", "import yaml\n# never used\n")
    results = find_reachable_packages(str(tmp_repo), ["yaml"])
    assert results[0].reachable is False
    assert results[0].usages == []


def test_aliased_import_is_still_resolved(tmp_repo):
    write(tmp_repo, "app.py", "import yaml as y\ny.load('x')\n")
    results = find_reachable_packages(str(tmp_repo), ["yaml"])
    assert results[0].reachable is True


def test_from_import_is_resolved(tmp_repo):
    write(tmp_repo, "app.py", "from yaml import load\nload('x')\n")
    results = find_reachable_packages(str(tmp_repo), ["yaml"])
    assert results[0].reachable is True


def test_usage_in_nested_function_records_correct_function_name(tmp_repo):
    write(tmp_repo, "app.py", "import yaml\n\ndef outer():\n    def inner():\n        yaml.load('x')\n    inner()\n")
    results = find_reachable_packages(str(tmp_repo), ["yaml"])
    assert results[0].reachable is True
    assert results[0].usages[0].function == "inner"


def test_usage_across_multiple_files_all_found(tmp_repo):
    write(tmp_repo, "a.py", "import yaml\nyaml.load('x')\n")
    write(tmp_repo, "sub/b.py", "import yaml\nyaml.load('y')\n")
    results = find_reachable_packages(str(tmp_repo), ["yaml"])
    assert results[0].reachable is True
    assert len(results[0].usages) == 2
    files_found = {u.file for u in results[0].usages}
    assert any("a.py" in f for f in files_found)
    assert any("b.py" in f for f in files_found)


def test_no_duplicate_usage_for_single_attribute_call(tmp_repo):
    """
    Regression test: `pkg.func(...)` used to trigger both visit_Attribute
    and visit_Name on the same node, double-counting the usage.
    """
    write(tmp_repo, "app.py", "import yaml\nyaml.load('x')\n")
    results = find_reachable_packages(str(tmp_repo), ["yaml"])
    assert len(results[0].usages) == 1


def test_syntax_error_file_does_not_crash_scan(tmp_repo, capsys):
    write(tmp_repo, "broken.py", "def f(:\n    pass\n")
    write(tmp_repo, "app.py", "import yaml\nyaml.load('x')\n")
    results = find_reachable_packages(str(tmp_repo), ["yaml"])
    assert results[0].reachable is True  # app.py still gets scanned


def test_site_packages_and_venv_are_skipped(tmp_repo):
    write(tmp_repo, "venv/lib/site-packages/yaml/__init__.py", "def load(x): pass\n")
    write(tmp_repo, "app.py", "print('no import here')\n")
    results = find_reachable_packages(str(tmp_repo), ["yaml"])
    assert results[0].reachable is False


@pytest.mark.parametrize("pypi_name,expected_import", [
    ("PyYAML", "yaml"),
    ("Jinja2", "jinja2"),
    ("Pillow", "PIL"),
    ("beautifulsoup4", "bs4"),
    ("requests", "requests"),  # no mismatch: falls through to lowercase
    ("SomeRandomPackage", "somerandompackage"),  # unknown: lowercased fallback
])
def test_resolve_import_name_mapping(pypi_name, expected_import):
    assert resolve_import_name(pypi_name) == expected_import


def test_filter_vulnerabilities_end_to_end_separates_reachable_and_filtered(tmp_repo):
    write(tmp_repo, "app.py", "import yaml\nyaml.load('x')\n")
    # jinja2 imported nowhere -> should be filtered
    vulns = [
        {"id": "CVE-1", "package": "PyYAML", "ecosystem": "PyPI",
         "installed_version": "5.3.1", "fixed_version": "5.4"},
        {"id": "CVE-2", "package": "Jinja2", "ecosystem": "PyPI",
         "installed_version": "2.10.1", "fixed_version": "2.10.3"},
    ]
    result = filter_vulnerabilities(vulns, str(tmp_repo))
    assert [v["id"] for v in result["reachable"]] == ["CVE-1"]
    assert [v["id"] for v in result["filtered"]] == ["CVE-2"]
    assert "_reachability" in result["reachable"][0]


def test_non_pypi_ecosystem_always_passes_through_unfiltered(tmp_repo):
    """npm/maven packages aren't analyzed by this (Python-only) AST walker
    and must never be silently dropped -- they should always be treated as
    reachable/actionable so a downstream (future) JS/Java analyzer can
    handle them, rather than this module wrongly filtering them out."""
    vulns = [{"id": "CVE-JS", "package": "lodash", "ecosystem": "npm",
              "installed_version": "4.17.15", "fixed_version": "4.17.21"}]
    result = filter_vulnerabilities(vulns, str(tmp_repo))
    assert [v["id"] for v in result["reachable"]] == ["CVE-JS"]
