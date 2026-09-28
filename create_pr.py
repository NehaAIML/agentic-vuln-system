import sys
import json
import subprocess
from pathlib import Path
from datetime import datetime

def create_pr(repo_path: str, results_json: str, vuln_id: str = None):
    repo_path = Path(repo_path)
    
    with open(results_json) as f:
        results = json.load(f)
    
    if vuln_id:
        result = next((r for r in results if r["vuln_id"] == vuln_id), None)
        if not result:
            print(f"❌ Vulnerability {vuln_id} not found in results")
            return False
    else:
        result = next((r for r in results if r["success"]), None)
        if not result:
            print("❌ No successful remediations found")
            return False
    
    if not result["success"]:
        print(f"❌ Remediation for {result['vuln_id']} was not successful")
        return False
    
    final_diff = result["final_diff"]
    vuln_id = result["vuln_id"]
    package = result["package"]
    
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    branch_name = f"fix/{vuln_id}-{timestamp}"
    
    print(f"📝 Creating branch: {branch_name}")
    
    if not (repo_path / ".git").exists():
        print(f"❌ {repo_path} is not a git repository")
        return False
    
    subprocess.run(["git", "checkout", "-b", branch_name], cwd=repo_path, check=True)
    
    patch_file = repo_path / "_pr_patch.diff"
    patch_file.write_text(final_diff)
    
    try:
        result_apply = subprocess.run(
            ["git", "apply", str(patch_file.name)],
            cwd=repo_path,
            capture_output=True,
            text=True,
        )
        
        if result_apply.returncode != 0:
            with open(patch_file) as f:
                subprocess.run(["patch", "-p1"], cwd=repo_path, stdin=f, check=True)
        
        print(f"✅ Patch applied successfully")
        subprocess.run(["git", "add", "-A"], cwd=repo_path, check=True)
        
        commit_msg = f"fix: remediate {vuln_id} in {package}\n\nAutomated vulnerability remediation using agentic self-repair loop.\nCVE: {vuln_id}\nPackage: {package}"
        subprocess.run(["git", "commit", "-m", commit_msg], cwd=repo_path, check=True)
        print(f"✅ Committed changes")
        
        subprocess.run(["git", "push", "-u", "origin", branch_name], cwd=repo_path, check=True)
        print(f"✅ Pushed branch to remote")
        
        pr_title = f"Fix {vuln_id}: Automated remediation for {package}"
        pr_body = f"## Automated Vulnerability Remediation\n\n**CVE:** {vuln_id}\n**Package:** {package}\n\nThis PR contains an automated patch generated and verified by the agentic self-repair loop."
        
        subprocess.run(["gh", "pr", "create", "--title", pr_title, "--body", pr_body], cwd=repo_path, check=True)
        print(f"\n🎉 Pull Request created successfully!")
        
        patch_file.unlink()
        return True
        
    except Exception as e:
        print(f"❌ Error creating PR: {e}")
        patch_file.unlink(missing_ok=True)
        subprocess.run(["git", "checkout", "-"], cwd=repo_path)
        subprocess.run(["git", "branch", "-D", branch_name], cwd=repo_path)
        return False

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: create_pr.py <repo_path> <remediation_results.json> [vuln_id]")
        sys.exit(1)
    
    success = create_pr(sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None)
    sys.exit(0 if success else 1)
