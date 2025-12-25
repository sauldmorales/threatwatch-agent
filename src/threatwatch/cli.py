import argparse
from threatwatch.log_collector import collect_logs
from threatwatch.detectors.failed_logins import detect_failed_logins

def main() -> None:
    parser = argparse.ArgumentParser(
        description="ThreatWatch v0.1 - simple local threat scanner"
    )

    parser.add_argument(
        "--auth-log-path",
        default="sample_data/auth.log",
        help="Ruta al archivo auth.log (por defecto: sample_data/auth.log)",
    )

    args = parser.parse_args()

    lines = collect_logs(args.auth_log_path)
    report = detect_failed_logins(lines)

    print("=== ThreatWatch v0.1 ===")
    print(f"File analyzed: {args.auth_log_path}")
    print(f"Total lines: {report['total_lines']}")
    print(f"Failed login lines: {report['failed_login_lines']}")

if __name__ == "__main__":
    main()
