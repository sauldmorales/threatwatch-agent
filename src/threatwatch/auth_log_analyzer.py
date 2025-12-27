from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, List, Dict, Any
from datetime import datetime
from collections import defaultdict
import re


# Patrón base para líneas de auth.log estilo syslog
_BASE_PATTERN = re.compile(
    r"""
    ^(?P<month>\w{3})          # Mes abreviado, ej: Dec
    \s+
    (?P<day>\d{1,2})           # Día
    \s+
    (?P<time>\d{2}:\d{2}:\d{2})# Hora HH:MM:SS
    \s+
    (?P<hostname>\S+)          # Hostname
    \s+
    (?P<process>\w+)           # Proceso (ej: sshd)
    \[
    (?P<pid>\d+)
    \]:
    \s+
    (?P<message>.*)            # Mensaje completo
    $
    """,
    re.VERBOSE,
)

# Detecta "Failed password for X from IP"
_FAILED_LOGIN_PATTERN = re.compile(
    r"Failed password for (?P<username>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)


@dataclass
class LogEntry:
    timestamp: datetime
    hostname: str
    process: str
    pid: int
    message: str
    raw_line: str
    username: Optional[str] = None
    ip_address: Optional[str] = None


class LogParser:
    def __init__(self) -> None:
        self._base_pattern = _BASE_PATTERN
        self._failed_login_pattern = _FAILED_LOGIN_PATTERN

    def parse_line(self, line: str) -> Optional[LogEntry]:
        line = line.strip()
        if not line:
            return None

        match = self._base_pattern.match(line)
        if not match:
            return None

        data = match.groupdict()

        # --- Intentar extraer usuario/IP solo si aplica ---
        username = None
        ip_address = None

        failed_match = self._failed_login_pattern.search(data["message"])
        if failed_match:
            username = failed_match.group("username")
            ip_address = failed_match.group("ip")

        # --- Manejar fecha (año fantasma: usamos año actual) ---
        current_year = datetime.now().year
        date_str = f"{current_year} {data['month']} {data['day']} {data['time']}"
        timestamp = datetime.strptime(date_str, "%Y %b %d %H:%M:%S")

        # --- Retornar estructura completa ---
        return LogEntry(
            timestamp=timestamp,
            hostname=data["hostname"],
            process=data["process"],
            pid=int(data["pid"]),
            message=data["message"],
            raw_line=line,
            username=username,
            ip_address=ip_address,
        )


def detect_bruteforce(
    entries: List[LogEntry],
    window_minutes: int = 5,
    threshold: int = 5,
) -> Dict[str, Any]:
    """
    Detecta posibles ataques de fuerza bruta agrupando intentos fallidos
    por IP (o usuario) en ventanas de tiempo deslizantes.

    Devuelve un diccionario con:
      - total_lines
      - failed_login_lines
      - bruteforce_sources: {clave -> {count, first, last}}
    """
    if not entries:
        return {
            "total_lines": 0,
            "failed_login_lines": 0,
            "bruteforce_sources": {},
        }

    window_seconds = window_minutes * 60

    # Solo entradas con intento fallido (donde logramos extraer user/IP)
    failed = [e for e in entries if e.username is not None or e.ip_address is not None]

    total_lines = len(entries)
    failed_count = len(failed)

    # Agrupar por IP si existe, si no por username, si no "unknown"
    grouped: Dict[str, List[LogEntry]] = defaultdict(list)
    for e in failed:
        key = e.ip_address or e.username or "unknown"
        grouped[key].append(e)

    offenders: Dict[str, Dict[str, Any]] = {}

    for key, events in grouped.items():
        if len(events) < threshold:
            continue

        events.sort(key=lambda e: e.timestamp)

        i = 0
        for j in range(len(events)):
            # deslizar la ventana
            while (
                events[j].timestamp.timestamp()
                - events[i].timestamp.timestamp()
                > window_seconds
            ):
                i += 1

            window_size = j - i + 1
            if window_size >= threshold:
                offenders[key] = {
                    "count": len(events),
                    "first": events[0].timestamp,
                    "last": events[-1].timestamp,
                }
                break

    return {
        "total_lines": total_lines,
        "failed_login_lines": failed_count,
        "bruteforce_sources": offenders,
    }
