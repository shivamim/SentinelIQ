"""Voyage AI embeddings — NO fallback, fail hard if key missing."""
import asyncio
from typing import List
from app.config import get_settings

settings = get_settings()


class EmbeddingService:
    """Voyage AI embedding client. Raises if VOYAGE_API_KEY is not set."""

    def __init__(self):
        self._client = None

    def _init_client(self):
        if self._client is not None:
            return
        if not settings.VOYAGE_API_KEY:
            raise RuntimeError(
                "VOYAGE_API_KEY is required — no fallback provider allowed. "
                "Set the VOYAGE_API_KEY environment variable."
            )
        import voyageai
        self._client = voyageai.Client(api_key=settings.VOYAGE_API_KEY)

    def embed(self, texts: List[str]) -> List[List[float]]:
        """Embed texts using Voyage AI voyage-3 model (1024 dims).

        This is a synchronous method that calls the Voyage AI API.
        For async usage, use embed_async() or call via asyncio.to_thread().
        """
        self._init_client()
        result = self._client.embed(texts, model=settings.VOYAGE_MODEL)
        return result.embeddings

    async def embed_async(self, texts: List[str]) -> List[List[float]]:
        """Async wrapper for embed() — runs the synchronous Voyage AI call in a thread.

        Use this in async contexts to avoid blocking the event loop.
        """
        return await asyncio.to_thread(self.embed, texts)

    @property
    def dimension(self) -> int:
        return settings.EMBEDDING_DIM


embedding_service = EmbeddingService()
