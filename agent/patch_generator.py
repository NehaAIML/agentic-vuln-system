import json

def generate_patch(vuln_info: dict, code_context: str) -> str:
    """Generates a minimal git unified diff patch for the vulnerability."""
    print(f"[PatchGenerator] Drafting patch for {vuln_info.get('cve')}...")
    # Returns a simulated clean unified diff format
    return """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -10,3 +10,3 @@
- insecure_call()
+ secure_call()
"""
