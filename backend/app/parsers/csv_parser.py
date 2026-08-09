"""CSV alert parser — flexible column mapping for SIEM CSV exports."""
import csv
import io
from typing import List, Dict, Any, Optional, Mapping


# Common column name mappings (case-insensitive)
COLUMN_ALIASES = {
    "alert_type": ["alert_type", "type", "rule_description", "signature", "event_type", "category"],
    "severity": ["severity", "level", "priority", "criticality", "risk_level"],
    "ioc_ip": ["ioc_ip", "src_ip", "source_ip", "srcaddr", "source_address", "attacker_ip", "remote_ip"],
    "ioc_domain": ["ioc_domain", "domain", "dns_query", "hostname", "fqdn"],
    "ioc_hash": ["ioc_hash", "file_hash", "sha256", "md5", "sha1", "hash"],
    "source": ["source", "sensor", "detector", "siem", "product"],
    "timestamp": ["timestamp", "time", "date", "datetime", "@timestamp", "event_time"],
    "description": ["description", "message", "details", "info", "event_message"],
}


def _find_column(header: List[str], aliases: List[str]) -> Optional[int]:
    """Find the first matching column index (case-insensitive)."""
    header_lower = [h.lower().strip() for h in header]
    for alias in aliases:
        for i, h in enumerate(header_lower):
            if h == alias or h.startswith(alias):
                return i
    return None


def parse_csv_alerts(
    file_path: str,
    source: str = "csv_upload",
    delimiter: str = ",",
) -> List[dict]:
    """Parse CSV alert exports with flexible column mapping.

    Auto-detects common column names and maps them to SentinelIQ fields.
    """
    alerts = []
    with open(file_path, "r", encoding="utf-8-sig") as f:
        reader = csv.reader(f, delimiter=delimiter)
        header = next(reader, None)
        if not header:
            return []

        # Build column index mapping
        col_map = {}
        for field, aliases in COLUMN_ALIASES.items():
            idx = _find_column(header, aliases)
            if idx is not None:
                col_map[field] = idx

        for row in reader:
            if not row or all(cell.strip() == "" for cell in row):
                continue
            alert = _normalize_csv_row(row, col_map, source, header)
            alerts.append(alert)

    return alerts


def parse_csv_bytes(data: bytes, source: str = "csv_upload") -> List[dict]:
    """Parse CSV from raw bytes (for uploaded files)."""
    text = data.decode("utf-8-sig")
    return parse_csv_text(text, source)


def parse_csv_text(text: str, source: str = "csv_upload") -> List[dict]:
    """Parse CSV from a string."""
    alerts = []
    reader = csv.reader(io.StringIO(text))
    header = next(reader, None)
    if not header:
        return []

    col_map = {}
    for field, aliases in COLUMN_ALIASES.items():
        idx = _find_column(header, aliases)
        if idx is not None:
            col_map[field] = idx

    for row in reader:
        if not row or all(cell.strip() == "" for cell in row):
            continue
        alert = _normalize_csv_row(row, col_map, source, header)
        alerts.append(alert)

    return alerts


def _normalize_csv_row(
    row: List[str],
    col_map: Dict[str, int],
    source: str,
    header: List[str],
) -> dict:
    """Normalize a CSV row into a SentinelIQ alert dict."""
    def get(field: str) -> Optional[str]:
        idx = col_map.get(field)
        if idx is not None and idx < len(row):
            val = row[idx].strip()
            return val if val else None
        return None

    # Build raw_alert from all columns
    raw = {}
    for i, h in enumerate(header):
        if i < len(row):
            raw[h.strip()] = row[i].strip()

    alert_type = get("alert_type") or "csv_import"
    severity = get("severity") or "medium"

    # Normalize severity values
    severity = severity.lower()
    if severity in ("critical", "crit", "4", "very_high"):
        severity = "critical"
    elif severity in ("high", "3", "important"):
        severity = "high"
    elif severity in ("medium", "med", "2", "moderate"):
        severity = "medium"
    elif severity in ("low", "1", "info", "informational"):
        severity = "low"

    return {
        "source": get("source") or source,
        "alert_type": alert_type,
        "severity": severity,
        "ioc_ip": get("ioc_ip"),
        "ioc_domain": get("ioc_domain"),
        "ioc_hash": get("ioc_hash"),
        "raw_alert": raw,
        "timestamp": get("timestamp"),
    }
