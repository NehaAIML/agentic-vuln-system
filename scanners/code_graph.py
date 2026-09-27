import ast
from pathlib import Path

def build_ast_graph(repo_path: str) -> dict:
    """Builds an AST call graph to locate dependency usage across Python files."""
    graph = {}
    path = Path(repo_path)
    for py_file in path.glob("**/*.py"):
        if ".venv" in py_file.parts:
            continue
        try:
            tree = ast.parse(py_file.read_text(encoding="utf-8"))
            calls = [node.func.id for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)]
            graph[str(py_file)] = calls
        except Exception:
            pass
    return graph
