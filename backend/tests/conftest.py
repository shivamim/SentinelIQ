"""Pytest fixtures for SentinelIQ RAG tests.

Provides:
- Mock DB session (SQLite in-memory for unit tests)
- Sample chunks for testing
- Mock embedding service
- Mock Cohere reranker
"""
import asyncio
import os
import sys
import types
import uuid
from typing import List, Dict, Any, AsyncGenerator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

# ─── Fix environment for tests ──────────────────────────────────────────────
# Tests always run in local development mode
os.environ["LOCAL_DEVELOPMENT"] = "true"
if not os.environ.get("DATABASE_URL", "").startswith("postgresql"):
    os.environ["DATABASE_URL"] = (
        "postgresql+asyncpg://postgres:postgres@localhost:5432/sentineliq"
    )

# ─── Pre-mock app.database to avoid import-time engine creation ──────────────
# app.database creates an engine at module level (connects to PostgreSQL).
# We mock this module so importing app.graph.retrieval and app.services.rag_pipeline
# works in the test environment without a running PostgreSQL instance.
# NOTE: We no longer need to mock app.models — the metadata_json fix resolves
# the SQLAlchemy 2.0 reserved attribute name conflict.

if "app.database" not in sys.modules:
    _mock_db = types.ModuleType("app.database")
    # Create a mock Base that supports model definitions
    from sqlalchemy.orm import declarative_base
    _mock_db.Base = declarative_base()
    _mock_db.engine = MagicMock()
    _mock_db.AsyncSessionLocal = MagicMock()
    _mock_db.get_db = AsyncMock()
    sys.modules["app.database"] = _mock_db

# ─── In-memory SQLite for unit tests ────────────────────────────────────────
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    create_async_engine,
    async_sessionmaker,
)
from sqlalchemy import text


@pytest_asyncio.fixture
async def mock_db_session() -> AsyncGenerator[AsyncSession, None]:
    """Provide an in-memory SQLite async session for unit tests."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.execute(text("""
            CREATE TABLE IF NOT EXISTS documents (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                source TEXT NOT NULL,
                source_url TEXT,
                document_type TEXT NOT NULL,
                content TEXT NOT NULL,
                metadata_json TEXT
            )
        """))
        await conn.execute(text("""
            CREATE TABLE IF NOT EXISTS document_chunks (
                id TEXT PRIMARY KEY,
                document_id TEXT NOT NULL,
                chunk_index INTEGER NOT NULL,
                chunk_text TEXT NOT NULL,
                metadata_json TEXT,
                similarity REAL,
                bm25_score REAL,
                rrf_score REAL,
                rerank_score REAL,
                FOREIGN KEY (document_id) REFERENCES documents(id)
            )
        """))

    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with session_factory() as session:
        yield session

    await engine.dispose()


# ─── Sample data fixtures ───────────────────────────────────────────────────

SAMPLE_DOCUMENTS = [
    {
        "id": str(uuid.uuid4()),
        "title": "MITRE ATT&CK T1059.001 - PowerShell",
        "source": "mitre_attack",
        "document_type": "mitre_attack",
        "content": "Adversaries may abuse PowerShell commands and scripts for execution.",
        "metadata_json": {"technique_id": "T1059.001", "tactic": "execution"},
    },
    {
        "id": str(uuid.uuid4()),
        "title": "CVE-2024-3094 - xz Utils Backdoor",
        "source": "nvd",
        "document_type": "cve",
        "content": "CVE-2024-3094 is a supply-chain compromise in xz utils that allows remote code execution via a backdoor in liblzma.",
        "metadata_json": {"cve_id": "CVE-2024-3094", "cvss_score": 10.0},
    },
    {
        "id": str(uuid.uuid4()),
        "title": "Postmortem: Lateral Movement Incident",
        "source": "internal",
        "document_type": "postmortem",
        "content": "Root cause was compromised service account credentials used for lateral movement via RDP.",
        "metadata_json": {"incident_id": "INC-2024-001", "severity": "high"},
    },
    {
        "id": str(uuid.uuid4()),
        "title": "MITRE ATT&CK T1078 - Valid Accounts",
        "source": "mitre_attack",
        "document_type": "mitre_attack",
        "content": "Adversaries may obtain and abuse credentials of existing accounts to gain initial access.",
        "metadata_json": {"technique_id": "T1078", "tactic": "initial-access"},
    },
    {
        "id": str(uuid.uuid4()),
        "title": "CVE-2023-44487 - HTTP/2 Rapid Reset",
        "source": "nvd",
        "document_type": "cve",
        "content": "CVE-2023-44487 is a denial of service vulnerability in the HTTP/2 protocol via Rapid Reset attack.",
        "metadata_json": {"cve_id": "CVE-2023-44487", "cvss_score": 7.5},
    },
]


@pytest.fixture
def sample_documents() -> List[Dict[str, Any]]:
    """Return sample document dicts for testing."""
    return SAMPLE_DOCUMENTS


SAMPLE_CHUNKS = [
    {
        "id": str(uuid.uuid4()),
        "document_id": SAMPLE_DOCUMENTS[0]["id"],
        "document_title": "MITRE ATT&CK T1059.001 - PowerShell",
        "document_source": "mitre_attack",
        "document_type": "mitre_attack",
        "chunk_index": 0,
        "chunk_text": "Adversaries may abuse PowerShell commands and scripts for execution. PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system.",
        "metadata_json": {"technique_id": "T1059.001", "tactic": "execution", "chunk_index": 0, "total_chunks": 1},
        "similarity": 0.92,
        "bm25_score": 0.85,
        "rrf_score": 0.032,
    },
    {
        "id": str(uuid.uuid4()),
        "document_id": SAMPLE_DOCUMENTS[1]["id"],
        "document_title": "CVE-2024-3094 - xz Utils Backdoor",
        "document_source": "nvd",
        "document_type": "cve",
        "chunk_index": 0,
        "chunk_text": "CVE-2024-3094 is a supply-chain compromise in xz utils that allows remote code execution via a backdoor in liblzma. The CVSS score is 10.0.",
        "metadata_json": {"cve_id": "CVE-2024-3094", "cvss_score": 10.0, "chunk_index": 0, "total_chunks": 1},
        "similarity": 0.88,
        "bm25_score": 0.90,
        "rrf_score": 0.030,
    },
    {
        "id": str(uuid.uuid4()),
        "document_id": SAMPLE_DOCUMENTS[2]["id"],
        "document_title": "Postmortem: Lateral Movement Incident",
        "document_source": "internal",
        "document_type": "postmortem",
        "chunk_index": 0,
        "chunk_text": "Root cause was compromised service account credentials used for lateral movement via RDP. The attacker gained initial access through phishing and then moved laterally.",
        "metadata_json": {"incident_id": "INC-2024-001", "severity": "high", "chunk_index": 0, "total_chunks": 1},
        "similarity": 0.85,
        "bm25_score": 0.70,
        "rrf_score": 0.028,
    },
    {
        "id": str(uuid.uuid4()),
        "document_id": SAMPLE_DOCUMENTS[3]["id"],
        "document_title": "MITRE ATT&CK T1078 - Valid Accounts",
        "document_source": "mitre_attack",
        "document_type": "mitre_attack",
        "chunk_index": 0,
        "chunk_text": "Adversaries may obtain and abuse credentials of existing accounts to gain initial access, persistence, privilege escalation, or defense evasion.",
        "metadata_json": {"technique_id": "T1078", "tactic": "initial-access", "chunk_index": 0, "total_chunks": 1},
        "similarity": 0.87,
        "bm25_score": 0.75,
        "rrf_score": 0.027,
    },
    {
        "id": str(uuid.uuid4()),
        "document_id": SAMPLE_DOCUMENTS[4]["id"],
        "document_title": "CVE-2023-44487 - HTTP/2 Rapid Reset",
        "document_source": "nvd",
        "document_type": "cve",
        "chunk_index": 0,
        "chunk_text": "CVE-2023-44487 is a denial of service vulnerability in the HTTP/2 protocol via Rapid Reset attack. CVSS score 7.5.",
        "metadata_json": {"cve_id": "CVE-2023-44487", "cvss_score": 7.5, "chunk_index": 0, "total_chunks": 1},
        "similarity": 0.80,
        "bm25_score": 0.65,
        "rrf_score": 0.025,
    },
]


@pytest.fixture
def sample_chunks() -> List[Dict[str, Any]]:
    """Return sample chunk dicts for testing."""
    return SAMPLE_CHUNKS


# ─── Mock embedding service ────────────────────────────────────────────────

class MockEmbeddingService:
    """Mock embedding service that returns deterministic fake embeddings."""

    def __init__(self, dimension: int = 1024):
        self._dimension = dimension

    def embed(self, texts: List[str]) -> List[List[float]]:
        """Return deterministic fake embeddings based on text hash."""
        results = []
        for t in texts:
            base_val = hash(t) % 1000 / 1000.0
            embedding = [base_val + (i * 0.001) for i in range(self._dimension)]
            norm = sum(x * x for x in embedding) ** 0.5
            embedding = [x / norm for x in embedding]
            results.append(embedding)
        return results

    async def embed_async(self, texts: List[str]) -> List[List[float]]:
        return self.embed(texts)

    @property
    def dimension(self) -> int:
        return self._dimension


@pytest.fixture
def mock_embedding_service():
    """Provide a mock embedding service instance."""
    return MockEmbeddingService()


@pytest.fixture
def mock_embedding_patch():
    """Patch app.services.embeddings.embedding_service with MockEmbeddingService."""
    mock = MockEmbeddingService()
    with patch("app.services.embeddings.embedding_service", mock):
        yield mock


# ─── Mock Cohere reranker ──────────────────────────────────────────────────

@pytest.fixture
def mock_cohere_key():
    """Set COHERE_API_KEY in settings for reranker tests."""
    from app.config import get_settings
    settings = get_settings()
    with patch.object(settings, "COHERE_API_KEY", "test-cohere-key"):
        yield "test-cohere-key"


@pytest.fixture
def no_cohere_key():
    """Ensure COHERE_API_KEY is empty for fallback tests."""
    from app.config import get_settings
    settings = get_settings()
    with patch.object(settings, "COHERE_API_KEY", ""):
        yield
