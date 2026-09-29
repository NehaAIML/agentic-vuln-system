"""
test_code_graph.py
-------------------
Unit tests for scanners/code_graph.py: function-boundary detection, call
graph edges, and blast-radius computation.
"""

import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from scanners.code_graph import FileGraph, get_context_for_usage


@pytest.fixture
def tmp_repo():
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)


def write(repo: Path, relpath: str, content: str):
    p = repo / relpath
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    return p


SAMPLE = """import yaml

def helper():
    return load_it("x")

def load_it(raw):
    return yaml.load(raw)

def unrelated():
    return 42
"""


def test_function_containing_line_finds_correct_function(tmp_repo):
    path = write(tmp_repo, "app.py", SAMPLE)
    graph = FileGraph(path)
    # line 7 is `return yaml.load(raw)` inside load_it
    assert graph.function_containing_line(7) == "load_it"


def test_call_graph_edge_detected(tmp_repo):
    path = write(tmp_repo, "app.py", SAMPLE)
    graph = FileGraph(path)
    assert "load_it" in graph.functions["helper"].calls
    assert "helper" in graph.functions["load_it"].called_by


def test_blast_radius_counts_upstream_callers(tmp_repo):
    path = write(tmp_repo, "app.py", SAMPLE)
    graph = FileGraph(path)
    # load_it is called by helper (1 upstream caller); unrelated calls nothing
    assert graph.blast_radius("load_it") == 1
    assert graph.blast_radius("unrelated") == 0


def test_transitive_blast_radius(tmp_repo):
    code = """import yaml

def top():
    return middle()

def middle():
    return bottom()

def bottom():
    return yaml.load("x")
"""
    path = write(tmp_repo, "app.py", code)
    graph = FileGraph(path)
    # bottom <- middle <- top: 2 transitive upstream callers
    assert graph.blast_radius("bottom") == 2


def test_module_level_usage_falls_back_to_line_window(tmp_repo):
    code = "import yaml\nCONFIG = yaml.load('x: 1')\n"
    write(tmp_repo, "app.py", code)
    ctx = get_context_for_usage(str(tmp_repo), str(tmp_repo / "app.py"), "yaml", 2)
    assert ctx.target_function is None
    assert ctx.fallback_snippet is not None
    assert "CONFIG" in ctx.fallback_snippet


def test_context_file_path_is_relative_to_repo_root(tmp_repo):
    """
    Regression test: patch/sandbox steps require the stored `file` path to
    be relative to repo_root (since sandboxes copy repo_root's *contents*
    to their own root) -- an absolute or CWD-relative path here would make
    every generated diff fail to apply in the sandbox.
    """
    write(tmp_repo, "sub/app.py", SAMPLE)
    ctx = get_context_for_usage(str(tmp_repo), str(tmp_repo / "sub" / "app.py"), "yaml", 7)
    assert ctx.file == "sub/app.py"
    assert not Path(ctx.file).is_absolute()
