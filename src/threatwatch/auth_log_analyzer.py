from dataclasses import dataclass
from datetime import datetime
import re
from typing import Optional

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
    def __init__(self):
        self._base_pattern = re.compile(
            r'(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
            r'(?P<hostname>\S+)\s+'
            r'(?P<process>\w+)(?:\[(?P<pid>\d+)\])?:\s+'
            r'(?P<message>.*)'
        )

        # detecta "Failed password for X from IP"
        self._failed_login_pattern = re.compile(
            r"Failed password for (?P<username>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
        )

    def parse_line(self, line: str) -> Optional[LogEntry]:
        line = line.strip()
        if not line:
            return None

        match = self._base_pattern.match(line)
        if not match:
            return None

        data = match.groupdict()

        # --- INTENTAR extraer usuario/IP solo si aplica ---
        username = None
        ip_address = None

        failed_match = self._failed_login_pattern.search(data["message"])
        if failed_match:
            username = failed_match.group("username")
            ip_address = failed_match.group("ip")

        # --- manejar fecha (Año fantasma: MVP) ---
        current_year = datetime.now().year
        date_str = f"{current_year} {data['month']} {data['day']} {data['time']}"
        timestamp = datetime.strptime(date_str, "%Y %b %d %H:%M:%S")

        # --- retornar estructura completa ---
        return LogEntry(
            timestamp=timestamp,
            hostname=data['hostname'],
            process=data['process'],
            pid=int(data['pid']) if data['pid'] else 0,
            message=data['message'],
            raw_line=line,
            username=username,
            ip_address=ip_address
        )


if __name__ == "__main__":
    sample = "Dec 25 14:02:05 PREDATORF4 sshd[9999]: Failed password for root from 192.168.1.5 port 22 ssh2"
    parser = LogParser()
    entry = parser.parse_line(sample)
    print(entry)
