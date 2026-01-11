import json
import shutil
import subprocess


def test_cli_json_output_is_valid_json():
    exe = shutil.which("threatwatch")
    assert exe is not None, "No encuentro el ejecutable 'threatwatch' en PATH (¿instalaste con pip -e .?)"

    result = subprocess.run(
        [exe, "--auth-log-path", "sample_data/auth.log", "--json"],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, f"STDERR:\n{result.stderr}"
    data = json.loads(result.stdout)
    assert isinstance(data, dict)
