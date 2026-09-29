"""
code_graph.py
-------------
Step 2: Context-Aware Code Retrieval & AST Mapping.

Given a reachability "usage" (file, line, function), this builds a small,
precise context bundle for the LLM:
  - the enclosing function's full source (not the whole file)
  - a fallback +/- N line window if the usage isn't inside a function
    (e.g. module-level code)
  - the file's import block (so the LLM knows exactly how the package is
    aliased/imported)
  - a lightweight call graph edge: which functions call which other
    functions in the same file, so the agent knows if the vulnerable call
    is behind a widely-used helper (higher blast radius) or an isolated
    one-off.

This deliberately avoids dumping whole files into the LLM context window.
"""

import ast
import json
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import List, Dict, Optional


@dataclass
class FunctionContext:
    name: str
    start_line: int
    end_line: int
    source: str
    calls: List[str] = field(default_factory=list)  # names of functions this one calls
    called_by: List[str] = field(default_factory=list)  # functions in this file that call this one


@dataclass
class CodeContext:
    file: str
    package: str
    usage_line: int
    imports: List[str]
    target_function: Optional[FunctionContext]
    fallback_snippet: Optional[str]
    blast_radius: int  # number of distinct functions (transitively) that reach the target


class FileGraph:
    """Parses one file into a map of function-name -> FunctionContext, plus import lines."""

    def __init__(self, path: Path):
        self.path = path
        self.source = path.read_text(encoding="utf-8")
        self.lines = self.source.splitlines(keepends=True)
        self.tree = ast.parse(self.source, filename=str(path))
        self.functions: Dict[str, FunctionContext] = {}
        self.imports: List[str] = []
        self._build()

    def _build(self):
        # Collect import lines verbatim (source-accurate, handles multi-import lines)
        for node in ast.walk(self.tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                start = node.lineno - 1
                end = getattr(node, "end_lineno", node.lineno)
                self.imports.append("".join(self.lines[start:end]).rstrip("\n"))

        # Collect top-level and nested function defs with line ranges
        for node in ast.walk(self.tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                start = node.lineno
                end = getattr(node, "end_lineno", node.lineno)
                src = "".join(self.lines[start - 1 : end])
                self.functions[node.name] = FunctionContext(
                    name=node.name, start_line=start, end_line=end, source=src
                )

        # Build call edges: for each function, walk its body for Call nodes
        # whose func resolves to another known function name in this file.
        for fname, fctx in self.functions.items():
            func_node = self._find_function_node(fname)
            if func_node is None:
                continue
            for node in ast.walk(func_node):
                if isinstance(node, ast.Call):
                    called_name = self._resolve_call_name(node)
                    if called_name and called_name in self.functions and called_name != fname:
                        fctx.calls.append(called_name)

        # Reverse edges for called_by
        for fname, fctx in self.functions.items():
            for called in fctx.calls:
                self.functions[called].called_by.append(fname)

    def _find_function_node(self, name: str):
        for node in ast.walk(self.tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
                return node
        return None

    @staticmethod
    def _resolve_call_name(call_node: ast.Call) -> Optional[str]:
        f = call_node.func
        if isinstance(f, ast.Name):
            return f.id
        if isinstance(f, ast.Attribute):
            return f.attr
        return None

    def function_containing_line(self, line: int) -> Optional[str]:
        best = None
        for fname, fctx in self.functions.items():
            if fctx.start_line <= line <= fctx.end_line:
                if best is None or (fctx.end_line - fctx.start_line) < (
                    self.functions[best].end_line - self.functions[best].start_line
                ):
                    best = fname  # prefer the innermost/smallest enclosing function
        return best

    def blast_radius(self, fname: str) -> int:
        """Count distinct functions that transitively call `fname` (upstream callers)."""
        seen = set()
        stack = [fname]
        while stack:
            cur = stack.pop()
            for caller in self.functions.get(cur, FunctionContext("", 0, 0, "")).called_by:
                if caller not in seen:
                    seen.add(caller)
                    stack.append(caller)
        return len(seen)


def fallback_snippet(path: Path, line: int, context: int = 20) -> str:
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    start = max(0, line - 1 - context)
    end = min(len(lines), line + context)
    return "".join(lines[start:end])


def get_context_for_usage(repo_root: str, file: str, package: str, usage_line: int) -> CodeContext:
    # `file` as recorded by the reachability step is usually already a valid
    # relative/absolute path (it came from Path.rglob()). Fall back to
    # joining with repo_root by filename only if the stored path doesn't
    # resolve directly (e.g. contexts are rebuilt from a different CWD).
    path = Path(file)
    if not path.exists():
        path = Path(repo_root) / Path(file).name

    # Normalize to a path relative to repo_root: downstream steps (patch
    # generation, sandboxing) copy repo_root's *contents* into a sandbox
    # directory, so diffs must reference paths relative to repo_root, not
    # relative to whatever CWD the scan was originally run from.
    try:
        rel_path = path.resolve().relative_to(Path(repo_root).resolve())
    except ValueError:
        rel_path = Path(path.name)

    graph = FileGraph(path)
    fname = graph.function_containing_line(usage_line)

    if fname:
        fctx = graph.functions[fname]
        radius = graph.blast_radius(fname)
        return CodeContext(
            file=str(rel_path),
            package=package,
            usage_line=usage_line,
            imports=graph.imports,
            target_function=fctx,
            fallback_snippet=None,
            blast_radius=radius,
        )
    else:
        return CodeContext(
            file=str(rel_path),
            package=package,
            usage_line=usage_line,
            imports=graph.imports,
            target_function=None,
            fallback_snippet=fallback_snippet(path, usage_line),
            blast_radius=0,
        )


def build_contexts_for_reachable_vulns(repo_root: str, reachability_json: str) -> List[Dict]:
    with open(reachability_json) as f:
        data = json.load(f)

    contexts = []
    for vuln in data["reachable"]:
        usages = vuln.get("_reachability", {}).get("usages", [])
        if not usages:
            continue
        # Take the first usage site as the primary patch target; the rest
        # are reported so the LLM/patch step can address multi-site fixes.
        primary = usages[0]
        ctx = get_context_for_usage(repo_root, primary["file"], vuln["package"], primary["line"])
        contexts.append(
            {
                "vuln": vuln,
                "context": asdict(ctx),
                "all_usage_sites": usages,
            }
        )
    return contexts


def main():
    if len(sys.argv) < 3:
        print("Usage: code_graph.py <repo_root> <reachability_results.json>")
        sys.exit(1)
    repo_root, reach_json = sys.argv[1], sys.argv[2]

    contexts = build_contexts_for_reachable_vulns(repo_root, reach_json)

    for c in contexts:
        vuln = c["vuln"]
        ctx = c["context"]
        print(f"=== {vuln['id']} ({vuln['package']}) ===")
        print(f"File: {ctx['file']}:{ctx['usage_line']}")
        if ctx["target_function"]:
            tf = ctx["target_function"]
            print(f"Enclosing function: {tf['name']} (lines {tf['start_line']}-{tf['end_line']})")
            print(f"Blast radius (upstream callers): {ctx['blast_radius']}")
        else:
            print("No enclosing function found; using +/-20 line window.")
        print()

    out_path = Path(repo_root) / "code_contexts.json"
    with open(out_path, "w") as f:
        json.dump(contexts, f, indent=2)
    print(f"Written {len(contexts)} context bundle(s) to {out_path}")


if __name__ == "__main__":
    main()
