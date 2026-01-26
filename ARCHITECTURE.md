# ThreatWatch — Architecture

## Data flow (batch)
1) Ingest
   - Read log lines from a file path (e.g., `sample_data/auth.log` or `/var/log/auth.log`)
2) Parse
   - Convert raw syslog-style lines into structured events (timestamp, user, IP, message, etc.)
   - If a line is malformed: skip or warn (no crash)
3) Detect
   - Run brute-force detection on parsed events (window/threshold)
4) Output
   - Default: human summary to stdout
   - `--json`: JSON report only to stdout (human/logging goes to stderr if needed)

## Key modules (high-level)
- `threatwatch/cli.py`: argument parsing + orchestration
- `threatwatch/auth_log_analyzer.py`: parsing + analysis pipeline
- `threatwatch/auth_log_analyzer.py`: parsing and detection logic
