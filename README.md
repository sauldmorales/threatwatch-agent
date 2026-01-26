# ThreatWatch Agent v1.1.0

Small local threat scanner for Linux `auth.log`.  
Parses authentication logs, counts failed logins, and flags brute-force style patterns (multiple failed attempts within a short window). Supports human output and JSON.

## Features

- `auth.log` parsing:
  - Timestamp normalization (reconstructs year when missing)
  - Host, process, PID, raw message
  - Extracts user and IP when applicable (e.g., `Failed password for ... from ...`)
- Brute-force detection:
  - Groups failed attempts by IP (and/or user depending on log line)
  - Sliding time window (default: 5 minutes)
  - Threshold-based detection (default: 5 attempts)
- CLI installed as `threatwatch`
- Output formats:
  - Human-readable summary
  - JSON for integrations
- Basic tests with `pytest`
- Standard Python package layout (`src/` + `pyproject.toml`)

## Requirements

- Python 3.10+ (tested on 3.12)
- Linux (designed for `/var/log/auth.log`-style logs)

## Install (dev)

```bash
git clone https://github.com/sauldmorales/threatwatch-agent.git
cd threatwatch-agent

python -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
python -m pip install -e .
python -m pip install -r requirements-dev.txt
```

## Usage

```bash
threatwatch --auth-log-path sample_data/auth.log
threatwatch --auth-log-path sample_data/auth.log --json
```

## Project Structure

```bash
threatwatch-agent/
├─ .github/
│  └─ workflows/
│     └─ tests.yml
├─ sample_data/
│  └─ auth.log
├─ src/
│  └─ threatwatch/
│     ├─ __init__.py
│     ├─ auth_log_analyzer.py
│     └─ cli.py
├─ tests/
│  ├─ test_smoke.py
│  ├─ test_e2e_cli_json.py
│  ├─ integration/
│  │  └─ test_cli_json_output.py
│  └─ unit/
│     └─ test_parser_smoke.py
├─ LICENSE
├─ pyproject.toml
├─ requirements.txt
├─ requirements-dev.txt
└─ README.md
```
## Test

```bash
pytest -q
```
## Security Checks (Local)

```bash

# Static analysis ( common python security issues )
bandit -r src -ll

# Dependency CVE audit
pip-audit
```

## Formatting

```bash
ruff check src tests
black src tests
```

## JSON Output

Fields in JSON mode:

- `total_lines`: total de lineas analizadas.
- `failed_login_lines`: total de lineas con fallos de autenticacion detectados.
- `bruteforce_sources`: mapa de fuente sospechosa a detalle.
  - `count`: total de eventos fallidos para esa fuente.
  - `first`: timestamp del primer evento visto.
  - `last`: timestamp del ultimo evento visto.

## Parser Notes

Se detectan variantes comunes:

- `Failed password for <user> from <ip>`
- `Failed password for invalid user <user> from <ip>`
- `Invalid user <user> from <ip>`

## Notes

```bash
This project is for defensive log analysis. Use only on systems and logs you are authorized to access.
```
