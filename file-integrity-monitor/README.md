# file-integrity-monitor

A minimal **host-based tripwire**. It records a cryptographic (SHA-256) baseline of a directory tree, then later tells you exactly which files were **created, modified, or deleted**. Standard library only.

## Threat model

File integrity monitoring is a foundational control (it's in PCI-DSS, CIS, and most compliance baselines). It defends against:

- an attacker dropping a new file (web shell, backdoor, cron job),
- tampering with an existing binary or config,
- quietly deleting logs or security tooling.

Because detection is based on the file's **hash**, not its size or modification time, it still works when an attacker forges those metadata fields to hide the change. It assumes the baseline itself is stored somewhere the attacker can't reach (append-only storage, a separate host) — otherwise they could simply re-baseline.

## Usage

```bash
# 1. Take a baseline of a tree you currently trust
python cli.py baseline ./my-webroot --out webroot.baseline.json

# 2. Later — from cron, CI, or by hand — check for tampering
python cli.py check ./my-webroot --baseline webroot.baseline.json
```

`check` prints a clear diff and exits **1** if anything changed, **0** if clean — so it slots straight into a scheduled job or pipeline:

```
CHANGES DETECTED against webroot.baseline.json:

  + created  uploads/shell.php
  ~ modified index.php
  - deleted  .htaccess

1 created, 1 modified, 1 deleted.
```

## Design notes

- Hashes are computed in 64 KB chunks, so arbitrarily large files use flat memory.
- Baselines store paths **relative** to the root with forward slashes, so a baseline is portable across machines.
- An `ignore` list (default: `*.pyc`, `__pycache__`, `.git`, baseline files) keeps noise out.
- Unreadable files are recorded as a sentinel rather than skipped, so their later disappearance is still flagged.

## Run the tests

```bash
pytest tests/
```

Tests run against pytest's `tmp_path`, so they exercise the real filesystem without touching anything outside a temporary directory.
