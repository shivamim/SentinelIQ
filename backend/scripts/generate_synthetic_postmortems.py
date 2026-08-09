"""Generate 40-60 synthetic incident postmortems grounded in real CVE/ATT&CK patterns."""
import os
import json
import random
import uuid
import asyncio
import argparse
import asyncpg
from datetime import datetime, timedelta

POSTMORTEM_TEMPLATES = [
    {
        "title": "Brute Force SSH Compromise on {hostname}",
        "summary": "An attacker performed a brute-force attack against the SSH service on {hostname}, eventually gaining access using a weak credential.",
        "root_cause": "Weak password policy allowed dictionary-based brute force. No rate limiting on SSH.",
        "remediation": "Enforced key-based auth, deployed fail2ban, updated password policy.",
        "tags": ["brute_force", "T1110", "ssh", "credential_compromise"],
    },
    {
        "title": "Lateral Movement via SMB on {hostname}",
        "summary": "After initial compromise, attacker used SMB to move laterally from {ip} to multiple internal hosts.",
        "root_cause": "Overly permissive SMB shares and NTLM authentication without SMB signing.",
        "remediation": "Restricted SMB shares, enabled SMB signing, segmented network.",
        "tags": ["lateral_movement", "T1021.002", "smb", "pass_the_hash"],
    },
    {
        "title": "Data Exfiltration via DNS Tunneling from {hostname}",
        "summary": "Sensitive data was exfiltrated from {hostname} using DNS tunneling to domain {domain}.",
        "root_cause": "Outbound DNS was unrestricted; DLP controls did not inspect DNS payload.",
        "remediation": "Deployed DNS filtering, enabled DLP on DNS, restricted outbound DNS to internal resolvers.",
        "tags": ["data_exfiltration", "T1071.004", "dns_tunneling", "dlp_bypass"],
    },
    {
        "title": "Ransomware Deployment on {hostname}",
        "summary": "Ransomware was executed on {hostname}. Files were encrypted across multiple shares before detection.",
        "root_cause": "Phishing email delivered payload; endpoint protection was outdated.",
        "remediation": "Restored from backups, updated EDR, conducted phishing awareness training.",
        "tags": ["ransomware", "T1486", "malware", "phishing"],
    },
    {
        "title": "SQL Injection on Web App {hostname}",
        "summary": "Automated SQL injection attack against {hostname} web application from {ip}.",
        "root_cause": "Unparameterized queries in legacy PHP code; no WAF in front of app.",
        "remediation": "Refactored to parameterized queries, deployed WAF rule set, rotated all credentials.",
        "tags": ["sql_injection", "T1190", "web_attack", "data_breach"],
    },
    {
        "title": "Credential Dumping via LSASS on {hostname}",
        "summary": "Mimikatz-like tool was used to dump LSASS memory on {hostname}, extracting plaintext credentials.",
        "root_cause": "LSASS was running without8 Credential Guard; endpoint had excessive privileges.",
        "remediation": "Enabled Credential Guard, restricted admin rights, deployed EDR behavioral rules.",
        "tags": ["credential_dumping", "T1003.001", "lsass", "mimikatz"],
    },
]

HOSTNAMES = [f"srv-{i:02d}.corp.local" for i in range(1, 21)] + [f"web-{i:02d}.prod.local" for i in range(1, 11)]
IPS = [f"192.168.1.{i}" for i in range(2, 50)]
DOMAINS = ["evil.com", "c2-server.ru", "exfil.io", "tunnel.dns"]
SEVERITIES = ["low", "medium", "high", "critical"]


def generate_postmortem():
    tmpl =# ... (truncated for brevity, full version in original)
    tmpl = random.choice(POSTMORTEM_TEMPLATES)
    hostname = random.choice(HOSTNAMES)
    ip = random.choice(IPS)
    domain = random.choice(DOMAINS)

    summary = tmpl["summary"].format(hostname=hostname, ip=ip, domain=domain)
    title = tmpl["title"].format(hostname=hostname)

    return {
        "title": title,
        "summary": summary,
        "root_cause": tmpl["root_cause"],
        "remediation": tmpl["remediation"],
        "tags": tmpl["tags"],
    }


async def insert_postmortems(count: int, dsn: str):
    conn = await asyncpg.connect(dsn)
    for i in range(count):
        pm = generate_postmortem()
        incident_id = str(uuid.uuid4())

        await conn.execute(
            "INSERT INTO incidents (id, title, description, severity, status) VALUES ($1, $2, $3, $4, 'closed')",
            incident_id, pm["title"], pm["summary"], random.choice(SEVERITIES),
        )

        pm_id = await conn.fetchval(
            "INSERT INTO postmortems (incident_id, summary, root_cause, remediation, tags) VALUES ($1, $2, $3, $4, $5) RETURNING id",
            incident_id, pm["summary"], pm["root_cause"], pm["remediation"], pm["tags"],
        )

        from app.services.embeddings import embedding_service
        chunk = f"Title: {pm['title']}\nSummary: {pm['summary']}\nRoot Cause: {pm['root_cause']}\nRemediation: {pm['remediation']}"
        emb = embedding_service.embed([chunk])[0]

        await conn.execute(
            "INSERT INTO postmortem_embeddings (postmortem_id, chunk_text, embedding) VALUES ($1, $2, $3)",
            str(pm_id), chunk, str(emb),
        )

        if (i + 1) % 10 == 0:
            print(f"Inserted {i + 1} postmortems...")

    await conn.close()
    print(f"Done. Inserted {count} synthetic postmortems.")


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=50)
    parser.add_argument("--dsn", default=os.environ.get("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/sentineliq"))
    args = parser.parse_args()
    await insert_postmortems(args.count, args.dsn)


if __name__ == "__main__":
    asyncio.run(main())
