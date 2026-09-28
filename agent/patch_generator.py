import re

def sanitize_patch(raw_output: str) -> str:
    # Remove markdown code blocks if present
    cleaned = re.sub(r"^```(?:diff)?\s*\n", "", raw_output, flags=re.MULTILINE)
    cleaned = re.sub(r"\n\s*```\s*$", "", cleaned)
    # Strip trailing whitespace on each line which causes git apply to fail
    lines = [line.rstrip() for line in cleaned.splitlines()]
    return "\n".join(lines) + "\n"


"""
patch_generator.py
-------------------
Step 3: Local LLM Patch Generation.

Feeds the vulnerability advisory + the precise code context (from
code_graph.py) into a local or free-tier LLM and asks for ONLY a unified
git diff back. Supports:
  - Ollama (local, free, e.g. `ollama run deepseek-coder-v2`)
  - Groq free-tier API (OpenAI-compatible endpoint)
  - Gemini Flash free-tier API
  - A `--dry-run` mode with a canned response, so the rest of the pipeline
    (Step 4 sandboxed testing) can be developed/tested without any live
    model or network call.

The prompt enforces strict output constraints and the response is
sanitized to strip markdown fences / commentary the model may add despite
instructions.
"""
import difflib
import json
import sys
import urllib.request
import urllib.error
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Dict, Any


SYSTEM_PROMPT = """You are a security patch generation agent. You will be given:
1. A CVE advisory (id, summary, affected package, fixed version)
2. The exact code location and enclosing function where the vulnerable
   package is used
3. The file's import statements

Your job: produce a MINIMAL, SAFE fix as a standard unified git diff.

STRICT OUTPUT RULES:
- Output ONLY a valid unified diff starting with "diff --git"
- Do NOT include any explanation, markdown fences, or commentary
- The diff must apply cleanly with `git apply` or `patch -p1`
- Prefer the smallest change that remediates the vulnerability (e.g.
  adding a safe loader argument, bumping a pinned version in a manifest,
  adding an explicit timeout/parameter) over large rewrites
- Never change unrelated code, formatting, or imports beyond what the fix
  requires
- If the fix requires a version bump in a manifest file (e.g.
  requirements.txt), include that hunk too, in the same diff
"""


def build_user_prompt(vuln: Dict[str, Any], context: Dict[str, Any]) -> str:
    tf = context.get("target_function")
    if tf:
        code_block = tf["source"]
        location_desc = f"function `{tf['name']}` (lines {tf['start_line']}-{tf['end_line']})"
    else:
        code_block = context.get("fallback_snippet", "")
        location_desc = f"line {context['usage_line']} (module-level code)"

    imports_block = "\n".join(context.get("imports", []))

    return f"""## Vulnerability
ID: {vuln['id']}
Package: {vuln['package']} (installed: {vuln['installed_version']}, fixed: {vuln.get('fixed_version', 'unknown')})
Severity: {vuln.get('severity', 'unknown')}
Summary: {vuln.get('summary', '')}
Advisory: {vuln.get('advisory_url', '')}

## Location
File: {context['file']}
{location_desc}

## Imports in this file
{imports_block}

## Code
```python
{code_block}
```

Produce the unified diff fixing this vulnerability in the file `{context['file']}`.
"""


def clean_diff_output(raw: str) -> str:
    """
    Strip markdown fences and leading commentary an LLM may add despite
    instructions, WITHOUT touching the diff body itself. Trailing blank
    lines inside a diff can be meaningful context lines (part of a hunk),
    so this must never blanket-strip() the whole text -- that silently
    truncates hunk content while leaving stale line-count headers behind,
    producing a corrupt patch that still looks plausible at a glance.
    """
    text = raw

    # Cut anything before the first real diff header (leading commentary,
    # a "Here's the fix:" preamble, etc.)
    idx = text.find("diff --git")
    if idx == -1:
        # No diff header found at all -- nothing safe to salvage.
        return text.strip() + "\n"
    text = text[idx:]

    # Drop a trailing markdown fence line (```), if the model added one,
    # without touching any blank lines that came before it.
    lines = text.splitlines(keepends=True)
    while lines and lines[-1].strip() in ("```", "```diff", "```patch"):
        lines.pop()
    text = "".join(lines)

    if not text.endswith("\n"):
        text += "\n"
    return text


@dataclass
class PatchResult:
    diff: str
    raw_response: str
    model: str


def call_ollama(system_prompt: str, user_prompt: str, model: str = "deepseek-coder-v2",
                 host: str = "http://localhost:11434") -> str:
    payload = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "stream": False,
    }).encode("utf-8")

    req = urllib.request.Request(
        f"{host}/api/chat", data=payload, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.loads(resp.read())
            return data["message"]["content"]
    except urllib.error.URLError as e:
        raise ConnectionError(
            f"Could not reach Ollama at {host}. Is it running? (`ollama serve`) Error: {e}"
        )


def call_groq(system_prompt: str, user_prompt: str, api_key: str,
              model: str = "llama-3.1-70b-versatile") -> str:
    payload = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.1,
    }).encode("utf-8")

    req = urllib.request.Request(
        "https://api.groq.com/openai/v1/chat/completions",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = json.loads(resp.read())
        return data["choices"][0]["message"]["content"]


def call_dry_run(vuln: Dict[str, Any], context: Dict[str, Any], repo_root: Optional[str] = None) -> str:
    """
    Deterministic patch logic for offline development/testing of the
    pipeline (Step 4 onward) without needing a live model. Rather than
    hand-writing hunk headers (error-prone), this reads the real file,
    applies a known-good textual fix, and lets difflib compute a correct
    unified diff -- so the sandbox/apply step is exercised faithfully.
    """
    rel_file = context["file"]
    abs_file = Path(repo_root) / rel_file if repo_root else Path(rel_file)
    original_lines = abs_file.read_text(encoding="utf-8").splitlines(keepends=True)

    pkg = vuln["package"].lower()
    new_lines = list(original_lines)  # copy

    if pkg == "pyyaml":
        for i, line in enumerate(new_lines):
            if "yaml.load(" in line and "Loader=" not in line:
                new_lines[i] = line.replace(
                    "yaml.load(raw_yaml)", "yaml.load(raw_yaml, Loader=yaml.SafeLoader)"
                )
    elif pkg == "requests":
        for i, line in enumerate(new_lines):
            if "requests.get(" in line and "allow_redirects=" not in line:
                new_lines[i] = line.replace(
                    "requests.get(url, timeout=5)",
                    "requests.get(url, timeout=5, allow_redirects=False)",
                )
    else:
        # No fix template for this package in dry-run mode; return a no-op
        # diff so the pipeline still runs end-to-end for unknown packages.
        return (
            f"diff --git a/{rel_file} b/{rel_file}\n"
            f"index 0000000..0000000 100644\n"
        )

    diff_lines = list(difflib.unified_diff(
        original_lines, new_lines,
        fromfile=f"a/{rel_file}", tofile=f"b/{rel_file}",
    ))
    if not diff_lines:
        return (
            f"diff --git a/{rel_file} b/{rel_file}\n"
            f"index 0000000..0000000 100644\n"
        )

    header = f"diff --git a/{rel_file} b/{rel_file}\nindex 0000000..1111111 100644\n"
    # original_lines/new_lines were read with keepends=True, so each content
    # line already carries its own trailing "\n"; difflib appends "\n" to
    # the header lines (---/+++/@@) automatically with the default
    # lineterm. Join with "" -- joining with "\n" here would double every
    # newline and produce a corrupt patch.
    body = "".join(diff_lines)
    if not body.endswith("\n"):
        body += "\n"
    return header + body


def generate_patch(vuln: Dict[str, Any], context: Dict[str, Any],
                    backend: str = "dry-run", model: Optional[str] = None,
                    api_key: Optional[str] = None,
                    prior_error: Optional[str] = None,
                    prior_diff: Optional[str] = None,
                    repo_root: Optional[str] = None) -> PatchResult:
    """
    Generate a patch. If prior_error/prior_diff are given, this is a
    self-repair iteration (Step 4 feeds failures back in here).
    """
    user_prompt = build_user_prompt(vuln, context)
    if prior_error and prior_diff:
        user_prompt += f"""

## Previous attempt failed
Your previous diff was:
```diff
{prior_diff}
```

It failed with this error when applied/tested:
```
{prior_error}
```

Fix the diff so it applies cleanly and the tests pass. Output ONLY the
corrected unified diff.
"""

    if backend == "dry-run":
        raw = call_dry_run(vuln, context, repo_root=repo_root)
        model_name = "dry-run"
    elif backend == "ollama":
        model_name = model or "deepseek-coder-v2"
        raw = call_ollama(SYSTEM_PROMPT, user_prompt, model=model_name)
    elif backend == "groq":
        if not api_key:
            raise ValueError("Groq backend requires --api-key")
        model_name = model or "llama-3.1-70b-versatile"
        raw = call_groq(SYSTEM_PROMPT, user_prompt, api_key, model=model_name)
    else:
        raise ValueError(f"Unknown backend: {backend}")

    diff = clean_diff_output(raw)
    return PatchResult(diff=diff, raw_response=raw, model=model_name)


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("code_contexts_json")
    parser.add_argument("--repo-root", default=".",
                         help="Repo root, needed for dry-run to read real file contents")
    parser.add_argument("--backend", default="dry-run", choices=["dry-run", "ollama", "groq"])
    parser.add_argument("--model", default=None)
    parser.add_argument("--api-key", default=None)
    parser.add_argument("--index", type=int, default=None,
                         help="Only patch the Nth context (0-indexed); default: all")
    args = parser.parse_args()

    with open(args.code_contexts_json) as f:
        contexts = json.load(f)

    if args.index is not None:
        contexts = [contexts[args.index]]

    results = []
    for c in contexts:
        vuln, ctx = c["vuln"], c["context"]
        print(f"Generating patch for {vuln['id']} ({vuln['package']}) using backend={args.backend}...")
        result = generate_patch(vuln, ctx, backend=args.backend, model=args.model,
                                 api_key=args.api_key, repo_root=args.repo_root)
        print(result.diff)
        print("-" * 60)
        results.append({"vuln_id": vuln["id"], "package": vuln["package"], "diff": result.diff})

    out_path = Path(args.code_contexts_json).parent / "generated_patches.json"
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"Written {len(results)} patch(es) to {out_path}")


if __name__ == "__main__":
    main()
