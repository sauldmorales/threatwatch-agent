# ThreatWatch — Role

## What it is
- A small, production-like CLI tool that analyzes SSH auth logs (e.g., `/var/log/auth.log`) and produces:
  - human-readable summary (default mode)
  - machine-readable JSON report (`--json`)
- Focus: parsing + basic detection (e.g., failed logins, brute-force sources) with tests and CI.

## What it is NOT
- Not a replacement for Fail2ban / not an automatic blocker.
- Not a long-running daemon/service by default.
- Not a multi-host SIEM collector.
- Not a complete log-rotation/inotify solution.
- Not a “supports every distro/log format” project.

## Design constraints (v1.1.0)
- With `--json`, stdout is JSON only (no human text mixed).
- Minimal scope: reliable demo + tests + docs + reproducible output.
