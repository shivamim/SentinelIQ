"""Pull real MITRE ATT&CK technique descriptions from MITRE CTI GitHub and embed."""
import os
import sys
import asyncio
import json
import httpx
import asyncpg
from app.services.embeddings import embedding_service

MITRE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"


async def fetch_mitre():
    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.get(MITRE_URL)
        resp.raise_for_status()
        return resp.json()


async def insert_mitre(data, dsn: str):
    conn = await asyncpg.connect(dsn)
    objects = data.get("objects", [])
    inserted = 0

    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        tech_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                tech_id = ref.get("external_id")
                break
        if not tech_id:
            continue

        name = obj.get("name", "")
        desc = obj.get("description", "")
        chunk = f"{tech_id}: {name}\n{desc}"

        emb = embedding_service.embed([chunk])[0]
        await conn.execute(
            """
            INSERT INTO mitre_technique_embeddings (technique_id, chunk_text, embedding)
            VALUES ($1, $2, $3)
            ON CONFLICT DO NOTHING
            """,
            tech_id, chunk, str(emb),
        )
        inserted += 1

    await conn.close()
    print(f"Inserted {inserted} MITRE techniques.")


async def main():
    dsn = os.environ.get("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/sentineliq")
    print("Fetching MITRE ATT&CK data...")
    data = await fetch_mitre()
    await insert_mitre(data, dsn)


if __name__ == "__main__":
    asyncio.run(main())
