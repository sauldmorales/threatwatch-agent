from typing import List, Dict

def detect_failed_logins(lines: List[str]) -> Dict[str, int]:
    failed = [line for line in lines if "Failed password" in line]
    return {
        "total_lines": len(lines),
        "failed_login_lines": len(failed),
    }
