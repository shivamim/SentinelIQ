"""Langfuse observability wrapper — one trace per graph run, span per node."""
from contextlib import contextmanager
from typing import Optional, Generator, Any
from app.config import get_settings

settings = get_settings()


class LangfuseTracer:
    """Lazy-initialized Langfuse client."""

    def __init__(self):
        self._client = None

    def _init(self):
        if self._client is not None:
            return
        if not settings.LANGFUSE_PUBLIC_KEY or not settings.LANGFUSE_SECRET_KEY:
            # No-op tracer if Langfuse is not configured
            self._client = False
            return
        from langfuse import Langfuse
        self._client = Langfuse(
            public_key=settings.LANGFUSE_PUBLIC_KEY,
            secret_key=settings.LANGFUSE_SECRET_KEY,
            host=settings.LANGFUSE_HOST,
        )

    @contextmanager
    def trace_node(
        self,
        trace_id: str,
        node_name: str,
        input_data: Optional[dict] = None,
    ) -> Generator[Optional[Any], None, None]:
        self._init()
        if not self._client:
            yield None
            return
        span = self._client.span(
            trace_id=trace_id,
            name=node_name,
            input=input_data,
        )
        try:
            yield span
        finally:
            span.end()

    def score_trace(self, trace_id: str, name: str, value: float):
        self._init()
        if not self._client:
            return
        self._client.score(trace_id=trace_id, name=name, value=value)


tracer = LangfuseTracer()
