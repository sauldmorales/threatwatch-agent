import json
import shutil
import subprocess
import sys
from pathlib import Path

def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]

def _auth_log_path() -> Path:
    p = _repo_root() / "sample_data" / "auth.log"
    assert p.exists(), f"Missing sample log at: {p}"
    return p

def _cli_cmd(auth_log: Path) -> list[str]:
    exe = shutil.which("threatwatch")
    if exe:
        return [exe, "--auth-log-path", str(auth_log), "--json"]
    return [sys.executable, "-m", "threatwatch.cli", "--auth-log-path", str(auth_log), "--json"]

def test_cli_e2e_json_stdout_only():
    auth_log = _auth_log_path()
    cmd = _cli_cmd(auth_log)

    proc = subprocess.run(cmd, text=True, capture_output=True)

    assert proc.returncode == 0, (
        "CLI must exit 0.\n"
        f"CMD: {cmd}\n"
        f"STDOUT:\n{proc.stdout}\n"
        f"STDERR:\n{proc.stderr}\n"
    )

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        raise AssertionError(
            "With --json, stdout must be ONLY valid JSON (no human text mixed).\n"
            f"CMD: {cmd}\n"
            f"JSON error: {e}\n"
            f"RAW STDOUT:\n{proc.stdout}\n"
            f"STDERR:\n{proc.stderr}\n"
        )

    assert isinstance(data, dict), f"Expected top-level JSON object (dict), got: {type(data)}"

    # Ajustado a tu output actual (lo vimos en tu captura)
    required = {"total_lines", "failed_login_lines", "bruteforce_sources"}
    missing = required - set(data.keys())
    assert not missing, f"Missing required keys: {sorted(missing)}. Actual keys: {sorted(list(data.keys()))}"
