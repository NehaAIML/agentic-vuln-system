"""
reachability.py
----------------
Determines whether a vulnerable package is *actually used* (imported and
called) anywhere in the codebase, as opposed to merely being listed in a
manifest file. This is the key noise-reduction step: most dependency
scanners report every transitive CVE regardless of whether the vulnerable
code path is ever executed.

Approach:
1. Walk all .py files, build an import map (module alias -> real module).
2. Walk all Call / Attribute nodes, resolve them back through the alias map.
3. A package is "reachable" if any resolved call touches a name that starts
   with the package's top-level module name.

This is a heuristic, not a full call-graph/taint analysis -- it deliberately
errs toward "reachable" (false negatives on filtering) rather than silently
hiding a real vuln. It's a fast triage pass, not a formal proof.
"""

import ast
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Set


@dataclass
class Usage:
    file: str
    line: int
    function: str
    code_snippet: str = ""


@dataclass
class ReachabilityResult:
    package: str
    reachable: bool
    usages: List[Usage] = field(default_factory=list)


def _extract_snippet(source_lines: List[str], lineno: int, context: int = 20) -> str:
    start = max(0, lineno - 1 - context)
    end = min(len(source_lines), lineno + context)
    return "".join(source_lines[start:end])


def find_reachable_packages(repo_path: str, package_names: List[str]) -> List[ReachabilityResult]:
    """
    Walk all .py files under repo_path and determine, for each package name,
    whether it is imported AND actually referenced (called or attribute-accessed).
    """
    repo = Path(repo_path)
    target_packages = set(package_names)
    all_usages: Dict[str, List[Usage]] = {pkg: [] for pkg in target_packages}

    for py_file in repo.rglob("*.py"):
        if "/.venv/" in str(py_file) or "/venv/" in str(py_file) or "site-packages" in str(py_file):
            continue
        per_file = analyze_file(py_file, target_packages)
        for pkg, usages in per_file.items():
            all_usages[pkg].extend(usages)

    results = []
    for pkg in package_names:
        usages = all_usages.get(pkg, [])
        results.append(
            ReachabilityResult(
                package=pkg,
                reachable=len(usages) > 0,
                usages=usages,
            )
        )
    return results


def analyze_file(path: Path, target_packages: Set[str]) -> Dict[str, List[Usage]]:
    """
    Parse a single .py file and, for each target package, collect every
    Name/Attribute usage that resolves back to an import of that package
    (via the file's own import statements/aliases), tagged with line number,
    enclosing function, and a surrounding code snippet.
    """
    findings: Dict[str, List[Usage]] = {pkg: [] for pkg in target_packages}
    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
    except (SyntaxError, UnicodeDecodeError) as e:
        print(f"[warn] could not parse {path}: {e}", file=sys.stderr)
        return findings

    import_map: Dict[str, str] = {}
    usages_with_module: List[tuple] = []
    func_stack = ["<module>"]

    class Visitor(ast.NodeVisitor):
        def visit_Import(self, node: ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                local = alias.asname or alias.name.split(".")[0]
                import_map[local] = top
            self.generic_visit(node)

        def visit_ImportFrom(self, node: ast.ImportFrom):
            if node.module:
                top = node.module.split(".")[0]
                for alias in node.names:
                    local = alias.asname or alias.name
                    import_map[local] = top
            self.generic_visit(node)

        def visit_FunctionDef(self, node):
            func_stack.append(node.name)
            self.generic_visit(node)
            func_stack.pop()

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_Name(self, node: ast.Name):
            top = import_map.get(node.id)
            if top in target_packages:
                usages_with_module.append((top, node.lineno, func_stack[-1]))
            self.generic_visit(node)

        def visit_Attribute(self, node: ast.Attribute):
            root: ast.expr = node
            while isinstance(root, ast.Attribute):
                root = root.value
            if isinstance(root, ast.Name):
                top = import_map.get(root.id)
                if top in target_packages:
                    usages_with_module.append((top, node.lineno, func_stack[-1]))
            self.generic_visit(node)

    Visitor().visit(tree)

    # De-duplicate: `pkg.func(...)` triggers both visit_Attribute (for the
    # Attribute node) and visit_Name (for its child Name node), producing
    # two entries at the same line/function. One usage per (module, line,
    # function) is all we need for triage purposes.
    seen = set()
    deduped = []
    for entry in usages_with_module:
        if entry not in seen:
            seen.add(entry)
            deduped.append(entry)
    usages_with_module = deduped

    source_lines = source.splitlines(keepends=True)
    for top, lineno, func_name in usages_with_module:
        findings[top].append(
            Usage(
                file=str(path),
                line=lineno,
                function=func_name,
                code_snippet=_extract_snippet(source_lines, lineno),
            )
        )
    return findings


# PyPI package (distribution) names frequently differ from the Python
# import/module name. This table covers common mismatches; anything not
# listed falls back to a lowercased version of the package name, which
# covers the vast majority of real-world packages.
PYPI_TO_IMPORT_NAME = {
    "pyyaml": "yaml",
    "jinja2": "jinja2",
    "pillow": "PIL",
    "beautifulsoup4": "bs4",
    "python-dateutil": "dateutil",
    "scikit-learn": "sklearn",
    "protobuf": "google",
    "opencv-python": "cv2",
    "pyjwt": "jwt",
    "python-jose": "jose",
    "mysqlclient": "MySQLdb",
    "psycopg2-binary": "psycopg2",
    "pyopenssl": "OpenSSL",
    "pysaml2": "saml2",
    "python-jwt": "python_jwt",
}


def resolve_import_name(pypi_package_name: str) -> str:
    key = pypi_package_name.lower()
    return PYPI_TO_IMPORT_NAME.get(key, key)


def filter_vulnerabilities(vulns: List[Dict], repo_path: str) -> Dict[str, List[Dict]]:
    """
    Given normalized vuln records (from run_scan.py) split them into
    'reachable' (real, actionable) and 'filtered' (dead-code, safe to ignore).
    """
    # Map: import_name -> original pypi package name(s), since scan results
    # report the PyPI name but the AST walk needs the import name.
    pypi_names = {v["package"] for v in vulns if v.get("ecosystem") == "PyPI"}
    import_to_pypi: Dict[str, str] = {resolve_import_name(p): p for p in pypi_names}

    reach_results_by_import = {
        r.package: r for r in find_reachable_packages(repo_path, list(import_to_pypi.keys()))
    }
    # Re-key by original PyPI name for lookup below
    reach_results = {
        import_to_pypi[import_name]: result
        for import_name, result in reach_results_by_import.items()
    }

    reachable, filtered = [], []
    for v in vulns:
        if v.get("ecosystem") != "PyPI":
            # Non-Python ecosystems: skip reachability (handled by other analyzers)
            reachable.append(v)
            continue
        result = reach_results.get(v["package"])
        if result and result.reachable:
            v["_reachability"] = {
                "usages": [u.__dict__ for u in result.usages[:5]]  # cap for brevity
            }
            reachable.append(v)
        else:
            filtered.append(v)
    return {"reachable": reachable, "filtered": filtered}


def main():
    if len(sys.argv) < 3:
        print("Usage: reachability.py <repo_path> <scan_results.json>")
        sys.exit(1)
    repo_path, scan_results_path = sys.argv[1], sys.argv[2]

    with open(scan_results_path) as f:
        vulns = json.load(f)

    result = filter_vulnerabilities(vulns, repo_path)

    print(f"Reachable (actionable): {len(result['reachable'])}")
    for v in result["reachable"]:
        usages = v.get("_reachability", {}).get("usages", [])
        loc = usages[0] if usages else {}
        print(
            f"  - {v['id']} ({v['package']}) used at "
            f"{loc.get('file', '?')}:{loc.get('line', '?')} in {loc.get('function', '?')}()"
        )

    print(f"\nFiltered (dead code, safe to deprioritize): {len(result['filtered'])}")
    for v in result["filtered"]:
        print(f"  - {v['id']} ({v['package']}) — never imported/called")

    out_path = Path(repo_path) / "reachability_results.json"
    with open(out_path, "w") as f:
        json.dump(result, f, indent=2)
    print(f"\nWritten to {out_path}")


if __name__ == "__main__":
    main()
