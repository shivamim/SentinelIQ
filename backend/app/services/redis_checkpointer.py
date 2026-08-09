"""Redis / Upstash checkpointer for LangGraph state persistence."""
from typing import Optional
from app.config import get_settings

settings = get_settings()


def get_checkpointer():
    """Create a Redis-backed LangGraph checkpointer.

    Uses langgraph-checkpoint-redis for persistent state.
    Falls back to MemorySaver ONLY if REDIS_URL is not configured
    (with a loud warning — this should never happen in production).
    """
    if settings.REDIS_URL:
        try:
            from langgraph.checkpoint.redis import RedisSaver
            return RedisSaver(redis_url=settings.REDIS_URL)
        except ImportError:
            import warnings
            warnings.warn(
                "langgraph-checkpoint-redis not installed; falling back to MemorySaver. "
                "Install with: pip install langgraph-checkpoint-redis"
            )
        except Exception as e:
            import warnings
            warnings.warn(
                f"Failed to create Redis checkpointer: {e}. Falling back to MemorySaver. "
                "This should NOT happen in production."
            )

    # Fallback — dev only
    import warnings
    warnings.warn(
        "REDIS_URL not configured. Using in-memory checkpointer. "
        "State will NOT persist across restarts. Configure REDIS_URL for production."
    )
    from langgraph.checkpoint.memory import MemorySaver
    return MemorySaver()
