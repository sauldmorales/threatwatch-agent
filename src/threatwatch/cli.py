import argparse
import json
from typing import List

from threatwatch.auth_log_analyzer import LogParser, LogEntry, detect_bruteforce


def _collect_lines(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8") as f:
        return [line.rstrip("\n") for line in f]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ThreatWatch v0.1 – simple local threat scanner"
    )

    parser.add_argument(
        "--auth-log-path",
        default="sample_data/auth.log",
        help="Ruta al archivo auth.log (por defecto: sample_data/auth.log)",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Imprimir el reporte en formato JSON",
    )

    args = parser.parse_args()

    # 1) Leer líneas crudas del log
    lines = _collect_lines(args.auth_log_path)

    # 2) Parsear líneas a LogEntry
    parser_obj = LogParser()
    entries: List[LogEntry] = []
    for line in lines:
        entry = parser_obj.parse_line(line)
        if entry is not None:
            entries.append(entry)

    # 3) Detectar brute force (además de contar fallos)
    report = detect_bruteforce(entries)

    if args.json:
        # json.dumps no sabe manejar datetime, usamos default=str
        print(json.dumps(report, default=str, indent=2))
    else:
        print("=== ThreatWatch v0.1 ===")
        print(f"File analyzed: {args.auth_log_path}")
        print(f"Total lines: {report['total_lines']}")
        print(f"Failed login lines: {report['failed_login_lines']}")

        offenders = report["bruteforce_sources"]
        print(f"Brute force sources: {len(offenders)}")
        for key, info in offenders.items():
            first = info["first"]
            last = info["last"]
            count = info["count"]
            print(
                f" - {key}: {count} failed logins "
                f"between {first} and {last}"
            )


if __name__ == "__main__":
    main()
