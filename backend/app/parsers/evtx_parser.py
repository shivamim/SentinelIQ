"""Windows EVTX log parser — convert Windows Event Log files to normalized alerts."""
import json
from typing import List, Dict, Any, Optional
from pathlib import Path


def parse_evtx(file_path: str) -> List[dict]:
    """Parse Windows EVTX files into normalized alert dicts.

    Requires python-evtx package: pip install python-evtx

    Returns list of dicts with keys:
        source, alert_type, severity, ioc_ip, ioc_domain, ioc_hash,
        raw_alert (original XML), timestamp
    """
    try:
        import Evtx.Evtx as evtx
    except ImportError:
        raise ImportError(
            "python-evtx is required for EVTX parsing. "
            "Install with: pip install python-evtx"
        )

    alerts = []
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"EVTX file not found: {file_path}")

    with evtx.Evtx(str(path)) as log:
        for record in log.records():
            try:
                xml_content = record.xml()
                alert = _normalize_evtx_record(xml_content, path.name)
                alerts.append(alert)
            except Exception:
                # Skip malformed records
                continue

    return alerts


def parse_evtx_bytes(data: bytes) -> List[dict]:
    """Parse EVTX from raw bytes (for uploaded files)."""
    import tempfile
    import os

    with tempfile.NamedTemporaryFile(suffix=".evtx", delete=False) as f:
        f.write(data)
        temp_path = f.name

    try:
        return parse_evtx(temp_path)
    finally:
        os.unlink(temp_path)


def _normalize_evtx_record(xml_content: str, source_file: str) -> dict:
    """Normalize an EVTX XML record into a SentinelIQ alert dict."""
    import re

    # Extract EventID
    event_id_match = re.search(r"<EventID[^>]*>(\d+)</EventID>", xml_content)
    event_id = event_id_match.group(1) if event_id_match else "unknown"

    # Extract timestamp
    time_match = re.search(r"TimeCreated.*?SystemTime=['\"]([^'\"]+)['\"]", xml_content)
    timestamp = time_match.group(1) if time_match else ""

    # Extract computer name
    computer_match = re.search(r"<Computer>([^<]+)</Computer>", xml_content)
    computer = computer_match.group(1) if computer_match else ""

    # Extract IPs from EventData
    ip_matches = re.findall(r"(?:\d{1,3}\.){3}\d{1,3}", xml_content)
    ioc_ip = ip_matches[0] if ip_matches else None

    # Extract hashes
    hash_match = re.search(r"[0-9a-fA-F]{64}", xml_content)
    ioc_hash = hash_match.group(0) if hash_match else None

    # Map security EventIDs to alert types
    security_events = {
        "4624": "successful_logon",
        "4625": "failed_logon",
        "4648": "explicit_logon",
        "4672": "privilege_escalation",
        "4720": "user_created",
        "4732": "member_added_group",
        "4698": "scheduled_task_created",
        "7045": "service_installed",
        "1": "process_creation",
        "3": "network_connection",
        "7": "image_loaded",
        "8": "create_remote_thread",
        "10": "process_access",
        "11": "file_create",
        "13": "registry_setvalue",
        "17": "pipe_event",
        "22": "dns_query",
    }

    alert_type = security_events.get(event_id, f"windows_event_{event_id}")

    # Severity heuristics
    high_severity_events = {"4625", "4648", "4672", "4698", "7045", "8", "10"}
    medium_severity_events = {"4624", "4720", "4732", "1", "3", "13"}

    if event_id in high_severity_events:
        severity = "high"
    elif event_id in medium_severity_events:
        severity = "medium"
    else:
        severity = "low"

    return {
        "source": f"evtx:{source_file}",
        "alert_type": alert_type,
        "severity": severity,
        "ioc_ip": ioc_ip,
        "ioc_domain": None,
        "ioc_hash": ioc_hash,
        "raw_alert": {
            "event_id": event_id,
            "computer": computer,
            "timestamp": timestamp,
            "xml": xml_content[:4096],  # Truncate very large XML
        },
        "timestamp": timestamp,
    }
