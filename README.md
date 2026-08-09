# SentinelIQ

**Agentic Hybrid RAG for cybersecurity investigation.**

An agentic cybersecurity RAG platform using dense vector retrieval, BM25 lexical retrieval, Reciprocal Rank Fusion, Cohere reranking, metadata filtering, LangGraph orchestration, Groq LLMs, grounded responses, source citations, retrieval confidence with abstention, and comprehensive RAG evaluation.

## Architecture

```
Documents
    ↓
Chunking (2000 tokens, 300 overlap)
    ↓
Voyage AI Embeddings (voyage-3, 1024 dims)
    ↓
pgvector ─────────────┐
                      ├── RRF → Cohere Reranker → Groq → Grounding → Citations
PostgreSQL BM25 ──────┘
    ↓
Metadata Filtering (document_type, source, technique_id, cve_id, severity, asset)
    ↓
Query Rewriting + Conversation-Aware Retrieval (Redis-backed history)
    ↓
Source Citations + Grounding Verification + Abstention
    ↓
Real LLM Streaming (SSE) or Non-Streaming Response
```

## Locked Stack

| Component | Technology |
|-----------|-----------|
| Frontend | Next.js 14 + shadcn/ui + React Flow + Plotly |
| Auth | Supabase Auth (frontend + backend) |
| Backend | FastAPI (async) |
| Database | PostgreSQL + pgvector |
| Migrations | Alembic |
| Knowledge Graph | Neo4j + real Cypher queries |
| Checkpointer | Redis / Upstash |
| LLM | Groq (llama-3.3-70b-versatile) — native streaming |
| Embeddings | Voyage AI voyage-3 (1024 dims) — NO fallback |
| Retrieval | BM25 (tsvector) + pgvector cosine + Reciprocal Rank Fusion (k=60) |
| Reranker | Cohere rerank-v3-enterprise (optional second stage after RRF) |
| Conversation Memory | Redis-backed per-conversation turn storage |
| Pipeline | LangGraph StateGraph — 11 nodes with grounding loop |
| Parsers | EVTX, CSV, Syslog |
| Reports | ReportLab PDF |
| Observability | Langfuse |

## RAG Techniques

| Technique | Description |
|-----------|-------------|
| **Dense Retrieval** | pgvector cosine similarity search on Voyage AI embeddings (1024-dim HNSW indexes) |
| **BM25 Lexical Retrieval** | PostgreSQL tsvector + GIN indexes for full-text search with `ts_rank_cd` scoring |
| **Hybrid Retrieval** | Combined BM25 + vector search with Reciprocal Rank Fusion: `RRF_score(d) = Σ 1/(k + rank_i)`, k=60 |
| **Metadata Filtering** | Pre-retrieval filtering on document_type, source, technique_id, cve_id, severity, asset (applied to both BM25 and vector queries) |
| **Cohere Reranking** | Optional second-stage reranking with Cohere rerank-v3-enterprise after RRF fusion. Status always reported: `success`, `skipped`, or `failed` |
| **Query Rewriting** | Groq LLM (temperature=0) rewrites vague/ambiguous queries for better retrieval. Simple factual queries (CVE IDs, technique IDs) pass through unchanged |
| **Conversational Retrieval** | Follow-up questions resolved via Redis-backed conversation history. Last N turns loaded before query rewriting. Configurable via `CONVERSATION_MAX_TURNS` |
| **Source Citations** | Every answer includes structured citations with chunk_id, document_id, title, source, document_type, score, and chunk_text preview. Citations are NEVER fabricated — only chunks actually retrieved are cited |
| **Grounding Verification** | Answers verified against retrieved evidence. Returns: `fully_grounded`, `partially_grounded`, `ungrounded`, or `evidence_insufficient`. Fabricated citation IDs are detected |
| **Abstention** | Configurable retrieval threshold (`RETRIEVAL_CONFIDENCE_THRESHOLD`). When retrieval scores are below threshold, system returns an explicit evidence-insufficient response instead of generating an unsupported answer. Uses `retrieval_score` / `retrieval_threshold` terminology — NOT percentage confidence claims |
| **Real LLM Streaming** | `/chat/stream` uses Groq's native streaming API via LangChain — tokens are emitted as generated via SSE. Not word-splitting of a pre-computed answer. Final SSE event contains answer, citations, metrics, grounding status, and reranker status |
| **RAG Evaluation** | Recall@K, MRR, NDCG@K metrics with 18-question cybersecurity dataset. Supports gold-labeled `relevant_document_ids`/`relevant_chunk_ids` for independent benchmarks. Approximate keyword-based estimation clearly marked when gold labels unavailable |
| **Retrieval Comparison** | Side-by-side: BM25-only vs Vector-only vs Hybrid (RRF) vs Hybrid+Rerank. Includes NDCG@K and reranker status per strategy |

## Local Development

### Backend Setup

```bash
# 1. Copy environment template
cp backend/.env.example backend/.env
# Edit .env with your API keys (at minimum: GROQ_API_KEY, VOYAGE_API_KEY)

# 2. Set development mode (enables localhost defaults for DB/Redis/Neo4j)
echo "LOCAL_DEVELOPMENT=true" >> backend/.env

# 3. Install dependencies
cd backend
pip install -r requirements.txt

# 4. Start infrastructure (PostgreSQL + pgvector, Redis, Neo4j)
docker-compose up -d postgres neo4j redis

# 5. Run Alembic migrations
alembic upgrade head

# 6. Start backend
uvicorn app.main:app --reload
```

### Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

### Required Environment Variables

**Required for all environments:**
- `GROQ_API_KEY` — Groq LLM inference (get from https://console.groq.com)
- `VOYAGE_API_KEY` — Voyage AI embeddings (get from https://docs.voyageai.com)

**Required in production (app will refuse to start without these):**
- `DATABASE_URL` — PostgreSQL+pgvector connection string
- `SUPABASE_URL` + `SUPABASE_ANON_KEY` — Supabase Auth
- `REDIS_URL` — Redis for state persistence + conversation memory
- `NEO4J_URI` + `NEO4J_PASSWORD` — Neo4j knowledge graph
- `CORS_ORIGINS` — Allowed CORS origins

**Optional:**
- `COHERE_API_KEY` — Cohere reranker (skip if blank)
- `LANGFUSE_PUBLIC_KEY` + `LANGFUSE_SECRET_KEY` — Observability

**In development mode** (`LOCAL_DEVELOPMENT=true`), missing infrastructure variables default to localhost.

### RAG Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `RETRIEVAL_CONFIDENCE_THRESHOLD` | `0.0` | Minimum RRF retrieval_score for top result. Set >0 to enable abstention |
| `CONVERSATION_MAX_TURNS` | `20` | Maximum conversation turns stored per conversation |
| `RAG_TOP_K` | `20` | Number of chunks retrieved from each search method |
| `RAG_RERANK_TOP_N` | `5` | Number of results after reranking |

## Deployment

```
GitHub
 ├── frontend → Vercel
 └── backend → Railway
```

**External services:**

| Service | Provider | Purpose |
|---------|----------|---------|
| PostgreSQL + pgvector | Supabase | Primary data store + vector search |
| Redis | Upstash | State persistence + conversation memory |
| Knowledge graph | Neo4j Aura | Asset correlation + blast radius |
| Embeddings | Voyage AI | voyage-3 (1024 dims) |
| LLM | Groq | llama-3.3-70b-versatile |
| Reranking | Cohere | rerank-v3-enterprise (optional) |
| Auth | Supabase | JWT auth + row-level security |
| Observability | Langfuse | Trace + eval (optional) |

**Production deployment checklist:**
1. Do NOT set `LOCAL_DEVELOPMENT=true` in production
2. Set all required environment variables in Railway/Vercel
3. Run `alembic upgrade head` against the production database
4. Ensure `CORS_ORIGINS` includes your Vercel frontend URL
5. Verify health endpoint: `GET /health`

## API Endpoints

### RAG Chat
- `POST /chat/` — RAG-powered Q&A (non-streaming, conversation memory enabled)
- `POST /chat/stream` — RAG-powered Q&A (real SSE streaming with Groq token-by-token generation)

Response includes:
```json
{
  "answer": "...",
  "sources": [...],
  "retrieval_metrics": {
    "chunks_retrieved": 20,
    "reranked_count": 5,
    "sources_used": 5,
    "vector_score_range": "0.65-0.95",
    "bm25_score_range": "0.12-0.85",
    "rrf_score_range": "0.008-0.032",
    "reranker": "cohere",
    "reranker_status": "success"
  },
  "grounding_status": "fully_grounded",
  "conversation_id": "uuid"
}
```

### Document Management
- `POST /documents/ingest` — Ingest document (auto-chunk + embed)
- `GET /documents/` — List documents (paginated)
- `GET /documents/{id}` — Get document with chunks

### Alert Correlation (LangGraph)
- `POST /alerts/ingest` — Ingest a SIEM alert
- `POST /alerts/{id}/correlate` — Trigger LangGraph correlation
- `GET /alerts/{id}/correlation` — Get correlation result
- `POST /alerts/parse/evtx` — Parse EVTX file
- `POST /alerts/parse/csv` — Parse CSV file
- `POST /alerts/parse/syslog` — Parse syslog file

### Incidents
- `GET /incidents` — List incidents
- `POST /incidents/{id}/postmortem` — Add postmortem

### Review Queue
- `GET /review-queue` — List escalated/uncertain items
- `POST /review-queue/{id}/resolve` — Resolve review item

### Webhooks
- `POST /webhooks/siem` — Live SIEM webhook
- `POST /webhooks/connectors/{id}` — Connector webhook (Splunk, QRadar, Sentinel, Wazuh)

### Reports & Dashboard
- `GET /reports/incidents/{id}/pdf` — Generate PDF report
- `GET /reports/dashboard` — Dashboard data

### Auth & Audit
- `POST /auth/login` — Supabase auth (client-side)
- `GET /auth/me` — Current user info
- `GET /audit-trail/{id}` — Audit trail

## Ingesting the Knowledge Base

```bash
# Ingest MITRE ATT&CK techniques
python scripts/ingest_mitre.py

# Ingest CVEs from NVD (specify year range)
python scripts/ingest_cves.py --start-year 2023 --end-year 2024

# Or use the documents API for custom content
curl -X POST http://localhost:8000/documents/ingest \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "PowerShell Execution Technique",
    "source": "MITRE",
    "document_type": "mitre_attack",
    "content": "T1059.001: Adversaries may abuse PowerShell...",
    "metadata_json": {"technique_id": "T1059.001"}
  }'
```

## Running RAG Evaluation

```bash
# Evaluate RAG pipeline quality (uses gold labels when available)
python -m eval.evaluate_rag --top-k 20

# Compare retrieval strategies (BM25 vs Vector vs Hybrid vs Hybrid+Rerank)
python -m eval.compare_retrieval --top-k 20

# Manually set gold labels for a specific question
python -m eval.label_gold --index 0 --chunk-ids "id1,id2,id3"
```

**Important:** Evaluation metrics are computed against gold-labeled `relevant_chunk_ids`/`relevant_document_ids` when available. If gold labels are not yet populated, metrics are estimated from keyword matching and are clearly marked as "estimated" — they are NOT valid independent benchmarks. Label the dataset manually with `python -m eval.label_gold` before relying on metrics.

## Running Tests

```bash
# Install test dependencies
pip install pytest pytest-asyncio aiosqlite

# Run all unit tests
pytest tests/ -v -m "not integration"

# Run only RAG quality tests (streaming, memory, abstention, reranker status, grounding)
pytest tests/test_rag_quality.py -v

# Run only chunking tests
pytest tests/test_chunking.py -v

# Run only grounding tests
pytest tests/test_grounding.py -v

# Run pgvector integration test (requires PostgreSQL+pgvector)
DATABASE_URL=postgresql+asyncpg://postgres:postgres@localhost:5432/sentineliq \
  pytest tests/test_pgvector_integration.py -v
```

## Docker

```bash
# Start all services
docker-compose up -d

# Backend + infrastructure only
docker-compose up -d postgres neo4j redis backend

# Build backend image
docker build -t sentineliq-backend ./backend
```

## Security

- No API keys in source code — all via environment variables
- `.env` and `.env.local` are gitignored — never commit real credentials
- Supabase Auth for authentication (no custom JWT implementation)
- RBAC with three roles: analyst, senior_analyst, admin
- Audit trail for all actions
- CORS configured via environment variable
- Production: required variables validated at startup — no silent localhost fallbacks
- Development: `LOCAL_DEVELOPMENT=true` enables localhost defaults explicitly
- Reranker failures are reported, not silently hidden
- Citations are never fabricated — only actually retrieved chunks are cited
- RRF scores are reported as `retrieval_score`, not as percentage confidence
