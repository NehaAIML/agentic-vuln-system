from scanners.code_graph import build_ast_graph
from agent.patch_generator import generate_patch
from agent.pr_creator import create_pull_request

def main():
    print("🔬 Running Full Package Simulation...")
    graph = build_ast_graph(".")
    print(f"[CodeGraph] Indexed {len(graph)} files.")
    
    patch = generate_patch({"cve": "CVE-2026-9999"}, "sample context")
    success = create_pull_request("fix/cve-2026-9999", patch, "All tests passed successfully.")
    print(f"[Simulation] Complete. PR Created: {success}")

if __name__ == "__main__":
    main()
