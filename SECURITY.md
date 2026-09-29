# Security Policy

## Reporting a Vulnerability

Please open a private GitHub security advisory, or email the maintainer.
Do not open public issues for exploitable findings.

## Threat Model of This Tool

This project scans *other* repositories and executes AI-generated patches.
It is therefore itself a security-sensitive component.

>>> EDIT THIS SECTION — do not ship as-is <<<

- Sandbox mechanism: [ ] temp dir only  [ ] Docker  [ ] nsjail/firejail  [ ] VM
- Network access inside sandbox: [ ] enabled  [ ] disabled
- Resource limits (CPU/mem/disk): [ ] none  [ ] specified below
- Secrets exposed to generated code: [ ] possible  [ ] prevented

Until the above is filled in and verified, do not run this pipeline
against untrusted repositories or with production credentials present.

## Supported Versions

| Version | Supported |
|---------|-----------|
| main    | yes       |
