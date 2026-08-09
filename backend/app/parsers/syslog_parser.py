"""Syslog parser — parse standard and structured syslog messages."""
import re
from typing import List, Dict, Any, Optional
from pathlib import Path


# Standard syslog regex (RFC 3164)
# <priority>timestamp hostname process[pid]: message
SYSLOG_PATTERN = re.compile(
    r"<(?P<priority>\d+)>"
    r"(?P<timestamp>\w{3}\s+\d+\s+\d+:\d+:\d+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<message>.*)"
)

# Structured syslog regex (RFC 5424)
STRUCTURED_SYSLOG_PATTERN = re.compile(
    r"<(?P<priority>\d+)>"
    r"(?P<version>\d+)\s+"
    r"(?P<timestamp>\S+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<appname>\S+)\s+"
    r"(?P<procid>\S+)\s+"
    r"(?P<msgid>\S+)\s+"
    r"(?P<structured_data>\S+)\s*"
    r"(?P<message>.*)?"
)

# Common IOC patterns
IP_PATTERN = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")
DOMAIN_PATTERN = re.compile(r"(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}")
HASH_PATTERN = re.compile(r"[0-9a-fA-F]{64}|[0-9a-fA-F]{32}|[0-9a-fA-F]{40}")

# Syslog severity from priority (priority = facility * 8 + severity)
SYSLOG_SEVERITY_MAP = {
    0: "critical",  # Emergency
    1: "critical",  # Alert
    2: "critical",  # Critical
    3: "high",      # Error
    4: "medium",    # Warning
    5: "medium",    # Notice
    6: "low",       # Informational
    7: "low",       # Debug
}


def parse_syslog_line(line: str) -> Optional[dict]:
    """Parse a single syslog line into a normalized alert dict.

    Supports both RFC 3164 (traditional) and RFC 5424 (structured) formats.
    """
    line = line.strip()
    if not line:
        return None

    # Try structured syslog first (RFC 5424)
    match = STRUCTURED_SYSLOG_PATTERN.match(line)
    if match:
        return _normalize_structured_syslog(match)

    # Try traditional syslog (RFC 3164)
    match = SYSLOG_PATTERN.match(line)
    if match:
        return _normalize_traditional_syslog(match)

    # Fallback: treat as raw message
    return _normalize_raw_message(line)


def parse_syslog_file(file_path: str, source: str = "syslog") -> List[dict]:
    """Parse a syslog file into normalized alert dicts."""
    alerts = []
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Syslog file not found: {file_path}")

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            alert = parse_syslog_line(line)
            if alert:
                alert["source"] = source
                alerts.append(alert)

    return alerts


def parse_syslog_stream(text: str, source: str = "syslog") -> List[dict]:
    """Parse syslog text stream into normalized alert dicts."""
    alerts = []
    for line in text.splitlines():
        alert = parse_syslog_line(line)
        if alert:
            alert["source"] = source
            alerts.append(alert)
    return alerts


def _priority_to_severity(priority: int) -> str:
    """Extract severity from syslog priority value."""
    severity_code = priority % 8
    return SYSLOG_SEVERITY_MAP.get(severity_code, "medium")


def _extract_iocs(text: str) -> Dict[str, Optional[str]]:
    """Extract IOC indicators from text."""
    ip_match = IP_PATTERN.search(text)
    domain_matches = DOMAIN_PATTERN.findall(text)
    hash_match = HASH_PATTERN.search(text)

    # Filter out obviously non-domain matches (too short, all-numeric)
    ioc_domain = None
    for d in domain_matches:
        parts = d.split(".")
        if len(parts) >= 2 and not all(p.isdigit() for p in parts):
            ioc_domain = d
            break

    return {
        "ioc_ip": ip_match.group(0) if ip_match else None,
        "ioc_domain": ioc_domain,
        "ioc_hash": hash_match.group(0) if hash_match else None,
    }


def _classify_alert_type(process: str, message: str) -> str:
    """Heuristic alert type classification from process name and message."""
    msg_lower = message.lower()
    proc_lower = process.lower() if process else ""

    keywords = {
        "brute_force": ["brute", "failed login", "authentication failure", "invalid password"],
        "lateral_movement": ["lateral", "smb", "rdp", "psexec", "wmi"],
        "malware_beacon": ["beacon", "c2", "callback", "malware", "trojan"],
        "privilege_escalation": ["privilege", "sudo", "su ", "escalat", "root"],
        "phishing": ["phish", "spam", "suspicious email"],
        "dns_tunneling": ["dns tunnel", "dns exfil", "anomalous dns"],
        "port_scan": ["scan", "nmap", "masscan", "port sweep"],
        "sql_injection": ["sql injection", "sqli", "union select"],
        "data_exfiltration": ["exfil", "data leak", "unauthorized transfer"],
        "credential_dumping": ["mimikatz", "lsass", "credential dump", "sam"],
        "intrusion_detection": ["ids", "ips", "intrusion", "alert", "attack"],
    }

    for alert_type, kws in keywords.items():
        for kw in kws:
            if kw in msg_lower or kw in proc_lower:
                return alert_type

    return "syslog_event"


def _normalize_traditional_syslog(match: re.Match) -> dict:
    """Normalize a traditional syslog match."""
    priority = int(match.group("priority"))
    timestamp = match.group("timestamp")
    hostname = match.group("hostname")
    process = match.group("process")
    pid = match.group("pid")
    message = match.group("message")

    iocs = _extract_iocs(message)
    alert_type = _classify_alert_type(process, message)
    severity = _priority_to_severity(priority)

    return {
        "source": "syslog",
        "alert_type": alert_type,
        "severity": severity,
        "ioc_ip": iocs["ioc_ip"],
        "ioc_domain": iocs["ioc_domain"],
        "ioc_hash": iocs["ioc_hash"],
        "raw_alert": {
            "priority": priority,
            "timestamp": timestamp,
            "hostname": hostname,
            "process": process,
            "pid": pid,
            "message": message[:4096],
        },
        "timestamp": timestamp,
    }


def _normalize_structured_syslog(match: re.Match) -> dict:
    """Normalize a structured syslog match (RFC 5424)."""
    priority = int(match.group("priority"))
    timestamp = match.group("timestamp")
    hostname = match.group("hostname")
    appname = match.group("appname")
    msgid = match.group("msgid")
    structured_data = match.group("structured_data")
    message = match.group("message") or ""

    iocs = _extract_iocs(message)
    alert_type = _classify_alert_type(appname, message)
    severity = _priority_to_severity(priority)

    return {
        "source": "syslog",
        "alert_type": alert_type,
        "severity": severity,
        "ioc_ip": iocs["ioc_ip"],
        "ioc_domain": iocs["ioc_domain"],
        "ioc_hash": iocs["ioc_hash"],
        "raw_alert": {
            "priority": priority,
            "timestamp": timestamp,
            "hostname": hostname,
            "appname": appname,
            "msgid": msgid,
            "structured_data": structured_data,
            "message": message[:4096],
        },
        "timestamp": timestamp,
    }


def _normalize_raw_message(line: str) -> dict:
    """Fallback: normalize an unstructured line as a raw alert."""
    iocs = _extract_iocs(line)
    return {
        "source": "syslog",
        "alert_type": "raw_event",
        "severity": "low",
        "ioc_ip": iocs["ioc_ip"],
        "ioc_domain": iocs["ioc_domain"],
        "ioc_hash": iocs["ioc_hash"],
        "raw_alert": {"message": line[:4096]},
        "timestamp": None,
    }
