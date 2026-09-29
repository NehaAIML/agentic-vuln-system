# Security Policy

## Reporting a Vulnerability

Please open a private GitHub security advisory, or email the maintainer.
Do not open public issues for exploitable findings.

## Threat Model of This Tool

This project scans *other* repositories and executes AI-generated patches.
It is therefore itself a security-sensitive component.

### Current Isolation Model

**Not hardened for untrusted input.** Treat this tool as a development
aid, not a production sandbox.

- **Sandbox mechanism:** plain `tempfile.mkdtemp()` — filesystem-level
  copy of the target repo. No container, no VM, no OS-level isolation.
- **Network access:** enabled. Generated patches and test commands run
  with the host's network stack available.
- **Resource limits:** none. No CPU, memory, disk, or wall-clock caps
  beyond per-command `timeout=` arguments.
- **Secrets:** inherited from the parent environment. Do **not** run
  this pipeline with production credentials present (AWS keys, GitHub
  tokens, etc.) in the environment.

### Recommendations Before Running

- Run against test/fork repositories only.
- Unset sensitive environment variables first:
  `env -i PATH="$PATH" python run_pipeline.py ...`
- For untrusted input, wrap the process in a container yourself
  (Docker, `nsjail`, `firejail`, or a VM). This is on the roadmap.

## Supported Versions

| Version | Supported |
|---------|-----------|
| main    | yes       |
