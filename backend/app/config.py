"""Application configuration loaded from environment variables.

Production: Required variables must be set — no silent localhost fallbacks.
Development: Set LOCAL_DEVELOPMENT=true to enable dev-mode defaults.
"""
import os
from functools import lru_cache


class Settings:
    """Centralized settings — no hardcoded secrets, no silent fallbacks in production."""

    # Development mode flag — when true, missing optional services use localhost defaults
    LOCAL_DEVELOPMENT: bool = os.environ.get("LOCAL_DEVELOPMENT", "false").lower() in ("true", "1", "yes")

    # PostgreSQL + pgvector (REQUIRED in production)
    DATABASE_URL: str = os.environ.get(
        "DATABASE_URL",
        "postgresql+asyncpg://postgres:postgres@localhost:5432/sentineliq"
        if os.environ.get("LOCAL_DEVELOPMENT", "false").lower() in ("true", "1", "yes")
        else "",
    )

    # Supabase Auth (REQUIRED in production)
    SUPABASE_URL: str = os.environ.get("SUPABASE_URL", "")
    SUPABASE_ANON_KEY: str = os.environ.get("SUPABASE_ANON_KEY", "")
    SUPABASE_JWT_SECRET: str = os.environ.get("SUPABASE_JWT_SECRET", "")

    # Groq inference (REQUIRED — no Anthropic fallback)
    GROQ_API_KEY: str = os.environ.get("GROQ_API_KEY", "")
    GROQ_MODEL: str = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")

    # Voyage AI embeddings (REQUIRED — no OpenAI fallback)
    VOYAGE_API_KEY: str = os.environ.get("VOYAGE_API_KEY", "")
    VOYAGE_MODEL: str = os.environ.get("VOYAGE_MODEL", "voyage-3")
    EMBEDDING_DIM: int = int(os.environ.get("EMBEDDING_DIM", "1024"))

    # Cohere reranker (optional second stage after RRF)
    COHERE_API_KEY: str = os.environ.get("COHERE_API_KEY", "")
    RERANKER_MODEL: str = os.environ.get("RERANKER_MODEL", "rerank-v3-enterprise")

    # CORS (REQUIRED in production, defaults to localhost in dev mode)
    CORS_ORIGINS: str = os.environ.get(
        "CORS_ORIGINS",
        "http://localhost:3000"
        if os.environ.get("LOCAL_DEVELOPMENT", "false").lower() in ("true", "1", "yes")
        else "",
    )

    # Neo4j knowledge graph (REQUIRED in production)
    NEO4J_URI: str = os.environ.get(
        "NEO4J_URI",
        "bolt://localhost:7687"
        if os.environ.get("LOCAL_DEVELOPMENT", "false").lower() in ("true", "1", "yes")
        else "",
    )
    NEO4J_USER: str = os.environ.get("NEO4J_USER", "neo4j")
    NEO4J_PASSWORD: str = os.environ.get("NEO4J_PASSWORD", "")

    # Redis / Upstash checkpointer (REQUIRED in production)
    REDIS_URL: str = os.environ.get(
        "REDIS_URL",
        "redis://localhost:6379/0"
        if os.environ.get("LOCAL_DEVELOPMENT", "false").lower() in ("true", "1", "yes")
        else "",
    )

    # RAG pipeline
    CHUNK_SIZE: int = int(os.environ.get("CHUNK_SIZE", "2000"))
    CHUNK_OVERLAP: int = int(os.environ.get("CHUNK_OVERLAP", "300"))
    RAG_TOP_K: int = int(os.environ.get("RAG_TOP_K", "20"))
    RAG_RERANK_TOP_N: int = int(os.environ.get("RAG_RERANK_TOP_N", "5"))

    # Retrieval confidence / abstention threshold
    # Minimum RRF score for the top result to consider retrieval confident.
    # If the top result's score is below this threshold, the system returns
    # an evidence-insufficient response instead of generating an answer.
    RETRIEVAL_CONFIDENCE_THRESHOLD: float = float(
        os.environ.get("RETRIEVAL_CONFIDENCE_THRESHOLD", "0.0")
    )

    # Conversation memory
    # Maximum number of conversation turns to store/load per conversation.
    CONVERSATION_MAX_TURNS: int = int(os.environ.get("CONVERSATION_MAX_TURNS", "20"))

    # Langfuse observability (optional)
    LANGFUSE_PUBLIC_KEY: str = os.environ.get("LANGFUSE_PUBLIC_KEY", "")
    LANGFUSE_SECRET_KEY: str = os.environ.get("LANGFUSE_SECRET_KEY", "")
    LANGFUSE_HOST: str = os.environ.get("LANGFUSE_HOST", "https://cloud.langfuse.com")

    def validate_production(self) -> None:
        """Validate that all required production variables are set.

        Call this at application startup in production mode.
        Raises RuntimeError with a clear message listing missing variables.
        """
        if self.LOCAL_DEVELOPMENT:
            return  # Skip validation in dev mode

        missing = []
        if not self.DATABASE_URL:
            missing.append("DATABASE_URL")
        if not self.SUPABASE_URL:
            missing.append("SUPABASE_URL")
        if not self.SUPABASE_ANON_KEY:
            missing.append("SUPABASE_ANON_KEY")
        if not self.GROQ_API_KEY:
            missing.append("GROQ_API_KEY")
        if not self.VOYAGE_API_KEY:
            missing.append("VOYAGE_API_KEY")
        if not self.CORS_ORIGINS:
            missing.append("CORS_ORIGINS")
        if not self.NEO4J_URI:
            missing.append("NEO4J_URI")
        if not self.NEO4J_PASSWORD:
            missing.append("NEO4J_PASSWORD")
        if not self.REDIS_URL:
            missing.append("REDIS_URL")

        if missing:
            raise RuntimeError(
                f"Missing required production environment variables: {', '.join(missing)}. "
                f"Set LOCAL_DEVELOPMENT=true for development defaults."
            )


@lru_cache
def get_settings() -> Settings:
    return Settings()
