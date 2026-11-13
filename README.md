# security-toolkit

A small collection of **defensive** security tools, written in Python. Each tool is self-contained, tested, and built around a clear threat model. The emphasis throughout is *blue team*: detecting, auditing, and monitoring — not attacking.

| Tool | What it does | Key concepts |
|------|--------------|--------------|
| [`password-auditor`](./password-auditor) | Audits password strength: entropy, common patterns, and whether the password has appeared in a known breach — checked **without ever sending the password** over the network. | Shannon entropy, k-anonymity, HaveIBeenPwned API, SHA-1 |
| [`log-anomaly-detector`](./log-anomaly-detector) | Parses authentication logs (SSH / web) and flags brute-force bursts and "impossible travel" logins. | Log parsing, sliding-window detection, geovelocity heuristics |
| [`file-integrity-monitor`](./file-integrity-monitor) | A mini host-based tripwire. Records a hashed baseline of a directory tree and reports any created, modified, or deleted file. | Cryptographic hashing, baseline/diff, HIDS fundamentals |

## Why these tools

These are the kinds of checks a security engineer or SOC analyst runs every day. They are deliberately small enough to read in one sitting, but each one is a real, working tool with:

- a documented **threat model** (what it protects against, and what it does *not*),
- **unit tests** (`pytest`),
- a command-line interface,
- no external services holding your secrets.

## Requirements

- Python 3.9+
- See each tool's `requirements.txt` (only `password-auditor` needs a network library; the rest use the standard library only).

## Running the tests

```bash
# from the repo root
pip install -r password-auditor/requirements.txt
pip install pytest
pytest
```

## Disclaimer

These tools are for auditing and protecting systems **you own or are authorised to test**. They are educational and defensive by design.

## Licence

MIT — see [LICENSE](./LICENSE).
