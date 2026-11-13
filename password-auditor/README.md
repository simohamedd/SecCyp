# password-auditor

A command-line tool that audits password strength and — optionally — tells you whether a password has turned up in a known data breach, **without ever sending the password anywhere**.

## Threat model

This tool helps defend against three real-world attacks:

1. **Low-entropy passwords** — guessable by brute force. Caught by the entropy estimate.
2. **Predictable passwords** — short, common, sequential, or repetitive. Caught by the pattern checks, which matter because a high entropy score alone can be misleading (`abcdefghijkl` scores well on length but is trivial to guess).
3. **Reused / already-breached passwords** — the single biggest real-world risk. Caught by the breach check.

It does **not** store passwords, transmit them, or rate the *person* — only the string.

## How the breach check stays private (k-anonymity)

The password is hashed locally with SHA-1. Only the **first 5 characters** of that hash are sent to the [HaveIBeenPwned](https://haveibeenpwned.com/API/v3#PwnedPasswords) range API. The API returns every breached hash sharing that prefix, and the tool matches the rest **locally**. The full hash — and therefore the password — never leaves your machine. An `Add-Padding` header is sent so the response size can't leak information either.

## Install

```bash
pip install -r requirements.txt   # only needed for --check-breaches
```

## Usage

```bash
# Prompt for a password (hidden input — stays out of shell history)
python cli.py

# Inline, with a breach check
python cli.py --password "correct horse battery staple" --check-breaches

# Audit a whole file, one password per line
python cli.py --file passwords.txt --check-breaches
```

Example output:

```
[password]
  verdict      : STRONG  (score 88/100)
  length       : 23
  entropy      : 108.2 bits (charset 95)
  breaches     : not found in known breach data
```

## Run the tests

```bash
pytest tests/
```

The breach logic is tested through its parser with synthetic data, so the test suite is fully offline.
