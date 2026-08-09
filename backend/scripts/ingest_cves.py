"""Pull real CVE data from NVD REST API and embed into pgvector."""
import os
import sys
import asyncio
import argparse
from datetime import datetime, timedelta

import httpx
import asyncpg
from app.services.embeddings import embedding_service

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


async def fetch_cves(start_date: str, end_date: str, api_key: str = ""):
    headers = {"apiKey": api_key} if api_key else {}
    all_cves = []
    start_index = 0
    results_per_page = 2000

    async with httpx.AsyncClient(timeout=60) as client:
        while True:
            params = {
                "pubStartDate": start_date,
                "pubEndDate": end_date,
                "startIndex": start_index,
                "resultsPerPage": results_per_page,
            }
            resp = await client.get(NVD_URL, params=params, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                break
            all_cves.extend(vulnerabilities)
            if len(vulnerabilities) < results_per_page:
                break
            start_index += results_per_page
            print(f"Fetched {len(all_cves)} CVEs so far...")

    return all_cves


async def insert_cves(cves, dsn: str):
    conn = await asyncpg.connect(dsn)
    inserted = 0

    for vuln in cves:
        cve = vuln.get("cve", {})
        cve_id = cve.get("id")
        descriptions = cve.get("descriptions", [])
        desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
        if not desc:
            desc = descriptions[0]["value"] if descriptions else ""

        metrics = cve.get("metrics", {})
        cvss = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore")
        if cvss is None:
            cvss = metrics.get("cvssMetricV30", [{}])[0].get("cvssData", {}).get("baseScore")
        if cvss is None:
            cvss = metrics.get("cvssMetricV2", [{}])[0].get("cvssData", {}).get("baseScore")

        published = cve.get("published", "")[:10]

        ref_id = await conn.fetchval(
            """
            INSERT INTO cve_references (cve_id, description, cvss_score, published_date)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (cve_id) DO UPDATE SET description = EXCLUDED.description,
                                               cvss_score = EXCLUDED.cvss_score,
                                               published_date = EXCLUDED.published_date
            RETURNING id
            """,
            cve_id, desc, cvss, published or None,
        )

        emb = embedding_service.embed([desc])[0]
        await conn.execute(
            """
            INSERT INTO cve_embeddings (cve_id, chunk_text, embedding)
            VALUES ($1, $2, $3)
            ON CONFLICT DO NOTHING
            """,
            cve_id, desc, str(emb),
        )
        inserted += 1

    await conn.close()
    print(f"Inserted/updated {inserted} CVEs.")


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--days", type=int, default=30)
    parser.add_argument("--dsn", default=os.environ.get("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/sentineliq"))
    parser.add_argument("--api-key", default=os.environ.get("NVD_API_KEY", ""))
    args = parser.parse_args()

    end = datetime.utcnow()
    start = end - timedelta(days=args.days)
    start_str = start.strftime("%Y-%m-%dT%H:%M:%S.000")
    end_str = end.strftime("%Y-%m-%dT%H:%M:%S.000")

    print(f"Fetching CVEs from {start_str} to {end_str}...")
    cves = await fetch_cves(start_str, end_str, args.api_key)
    print(f"Total CVEs fetched: {len(cves)}")
    await insert_cves(cves, args.dsn)


if __name__ == "__main__":
    asyncio.run(main())
