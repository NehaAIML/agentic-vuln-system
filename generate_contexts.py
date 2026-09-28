import sys
import json
import pathlib
import ast

def extract_imports(file_path: str) -> list:
    """Extract top-level imports from a Python file."""
    try:
        with open(file_path, 'r') as f:
            tree = ast.parse(f.read())
        imports = []
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append(f"import {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                names = ", ".join(alias.name for alias in node.names)
                imports.append(f"from {node.module} import {names}")
        return imports
    except Exception:
        return []

def main():
    if len(sys.argv) < 2:
        print("Usage: generate_contexts.py <repo_path>")
        sys.exit(1)
    
    repo_path = pathlib.Path(sys.argv[1])
    reach_results_path = repo_path / "reachability_results.json"
    
    if not reach_results_path.exists():
        print(f"Error: {reach_results_path} not found. Run scanners/reachability.py first.")
        sys.exit(1)

    with open(reach_results_path) as f:
        data = json.load(f)

    contexts = []
    for vuln in data.get("reachable", []):
        usages = vuln.get("_reachability", {}).get("usages", [])
        if not usages:
            continue
            
        usage = usages[0]
        file_path = usage["file"]
        line = usage["line"]
        code_snippet = usage["code_snippet"]
        
        imports = extract_imports(file_path)
        
        context_entry = {
            "vuln": {
                "id": vuln["id"],
                "package": vuln["package"],
                "installed_version": vuln.get("installed_version", "unknown"),
                "fixed_version": vuln.get("fixed_version", "unknown"),
                "severity": vuln.get("severity", "unknown"),
                "summary": vuln.get("summary", ""),
                "advisory_url": vuln.get("advisory_url", "")
            },
            "context": {
                "file": file_path,
                "usage_line": line,
                "imports": imports,
                "fallback_snippet": code_snippet
            }
        }
        contexts.append(context_entry)

    out_path = repo_path / "contexts.json"
    with open(out_path, "w") as f:
        json.dump(contexts, f, indent=2)
    
    print(f"✅ Generated {len(contexts)} contexts for reachable vulnerabilities.")
    print(f"Written to {out_path}")

if __name__ == "__main__":
    main()
