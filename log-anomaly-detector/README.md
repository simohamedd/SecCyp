# log-anomaly-detector

Parses authentication logs and flags two of the most common signs of account attack: **brute-force bursts** and **impossible-travel logins**. Standard library only — no dependencies.

## Threat model

| Signal | What it catches | Detector |
|--------|-----------------|----------|
| Many failed logins from one IP in a short window | Automated password guessing / credential stuffing | sliding-window counter per source IP |
| One account logging in successfully from two distant places too quickly | A stolen credential being used from a second location | geovelocity (haversine distance ÷ time) |

It is a **detection** aid, not prevention — it tells an analyst where to look. It assumes the logs themselves are trustworthy (an attacker with root could forge them).

## Design

Parsing and detection are deliberately separate:

- `parse_ssh_line` / `parse_log` turn raw OpenSSH `auth.log` lines into normalised `AuthEvent` records. Supporting a new log format means writing one parser — the detectors don't change.
- `detect_brute_force` and `detect_impossible_travel` work purely on `AuthEvent` objects, which makes them easy to unit test with synthetic data.

## Usage

```bash
# Brute-force scan
python cli.py --file samples/auth.log

# Add impossible-travel detection (needs an IP -> [lat, lon] map)
python cli.py --file samples/auth.log --geo samples/geo.json

# Machine-readable output
python cli.py --file samples/auth.log --geo samples/geo.json --json
```

Against the bundled sample you'll see a brute-force finding (six failures from `203.0.113.7` in seconds) and an impossible-travel finding (user `alice` in London then Sydney 30 minutes later).

> **Note on geolocation:** the tool takes the IP→location map as input rather than calling a geo-IP service, so it stays offline and dependency-free. Wire in MaxMind GeoLite2 or similar to build the map in production.

## Run the tests

```bash
pytest tests/
```
