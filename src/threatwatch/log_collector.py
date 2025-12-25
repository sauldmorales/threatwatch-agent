from typing import List

def collect_logs(path: str) -> List[str]:
    try:
        with open(path, "r") as file:
            return file.readlines()
    except FileNotFoundError:
        print(f"[ERROR] El archivo no existe: {path}")
        return []
