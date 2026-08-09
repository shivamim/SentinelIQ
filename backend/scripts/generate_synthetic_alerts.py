"""Generate 500-1000 synthetic SIEM alerts grounded in real dataset shapes."""
import os
import json
import random
import uuid
import asyncio
import argparse
import asyncpg
from datetime import datetime, timedelta

ALERT_TYPES = [
    "brute_force", "lateral_movement", "data_exfiltration", "malware_beacon",
    "privilege_escalation", "phishing", "dns_tunneling", "port_scan",
    "sql_injection", "xss_attempt", "ransomware", "credential_dumping",
]

SOURCES = ["wazuh", "suricata", "elastic", "synthetic"]
SEVERITIES = ["low", "medium", "high", "critical"]
ASSET_IDS = [str(uuid.uuid4()) for _ in range(20)]
IOC_IPS = [f"192.168.1.{i}" for i in range(2, 50)] + [f"10.0.0.{i}" for i in range(2, 30)]
IOC_DOMAINS = ["evil.com", "c2-server.ru", "phish.example", "malware.xyz", "exfil.io"]
IOC_HASHES = [
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2",
    "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
]


def generate_alert(alert_id: str) -> dict:
    alert_type = random.choice(ALERT_TYPES)
    source = random.choice(SOURCES)
    severity = random.choice(SEVERITIES)
    asset_id = random.choice(ASSET_IDS)
    ioc_ip = random.choice(IOC_IPS)
    ioc_domain = random.choice(IOC_DOMAINS) if random.random() > 0.5 else None
    ioc_hash = random.choice(IOC_HASHES) if random.random() > 0.7 else None
    timestamp = (datetime.utcnow() - timedelta(minutes=random.randint(0, 10080))).isoformat()

    raw_alert = {
        "@timestamp": timestamp,
        "event": {
            "category": "intrusion_detection",
            "type": alert_type,
            "severity": severity,
            "dataset": source,
        },
        "source": {"ip": ioc_ip, "port": random.randint(1000, 65535)},
        "destination": {"ip": f"10.0.0.{random.randint(2, 254)}", "port": random.choice([22, 80, 443, 3389])},
        "rule": {
            "id": f"{source}-{random.randint(1000, 9999)}",
            "description": f"{alert_type.replace('_', ' ').title()} detected",
            "level": severity,
        },
        "host": {"id": asset_id, "name": f"srv-{random.randint(1, 50)}.corp.local"},
    }

    if ioc_domain:
        raw_alert["dns"] = {"question": {"name": ioc_domain, "type": "A"}}
    if ioc_hash:
        raw_alert["file"] = {"hash": {"sha256": ioc_hash}, "name": "suspicious.exe"}

    return {
        "id": alert_id,
        "source": source,
        "raw_alert": raw_alert,
        "asset_id": asset_id,
        "alert_type": alert_type,
        "severity": severity,
        "ioc_ip": ioc_ip,
        "ioc_domain": ioc_domain,
        "ioc_hash": ioc_hash,
    }


async def insert_alerts(count: int, dsn: str):
    conn = await asyncpg.connect(dsn)
    for i in range(count):
        alert = generate_alert(str(uuid.uuid4()))
        await conn.execute(
            """
            INSERT INTO alerts (id, source, raw_alert, asset_id, alert_type, severity, ioc_ip, ioc_domain, ioc_hash)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            """,
            alert["id"], alert["source"], json.dumps(alert["raw_alert"]),
            alert["asset_id"], alert["alert_type"], alert["severity"],
            alert["ioc_ip"], alert["ioc_domain"], alert["ioc_hash"],
        )
        if (i + 1) % 100 == 0:
            print(f"Inserted {i + 1} alerts...")
    await conn.close()
    print(f"Done. Inserted {count} synthetic alerts.")


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=500)
    parser.add_argument("--dsn", default=os.environ.get("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/sentineliq"))
    args = parser.parse_args()
    await insert_alerts(args.count, args.dsn)


if __name__ == "__main__":
    asyncio.run(main())
