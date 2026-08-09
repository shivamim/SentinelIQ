"""Conversation memory service using Redis for persistent chat history.

Stores recent user/assistant turns by conversation_id, enabling
follow-up questions to resolve context from prior turns.
"""
import json
import logging
from typing import List, Dict, Any, Optional

from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

# Lazy-init Redis client
_redis_client = None


def _get_redis():
    """Lazy-initialize the Redis client for conversation memory."""
    global _redis_client
    if _redis_client is not None:
        return _redis_client
    if not settings.REDIS_URL:
        return None
    try:
        import redis
        _redis_client = redis.from_url(settings.REDIS_URL, decode_responses=True)
        # Test connection
        _redis_client.ping()
        return _redis_client
    except Exception as e:
        logger.warning(
            f"Failed to connect Redis for conversation memory: {e}. "
            "Conversation history will NOT persist."
        )
        _redis_client = None
        return None


def _conversation_key(conversation_id: str) -> str:
    """Redis key for a conversation's turn history."""
    return f"sentineliq:conversation:{conversation_id}"


async def load_conversation_history(
    conversation_id: str,
    max_turns: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """Load conversation history for the given conversation_id.

    Returns a list of turns, each a dict with 'role' and 'content' keys.
    Returns empty list if no history exists or Redis is unavailable.
    """
    if max_turns is None:
        max_turns = settings.CONVERSATION_MAX_TURNS

    redis_client = _get_redis()
    if not redis_client:
        return []

    try:
        key = _conversation_key(conversation_id)
        # Get the most recent max_turns entries from the list
        # LRANGE returns from oldest to newest, so we take the last max_turns
        total = redis_client.llen(key)
        if total == 0:
            return []

        start = max(0, total - max_turns)
        raw_entries = redis_client.lrange(key, start, -1)

        history = []
        for entry in raw_entries:
            try:
                turn = json.loads(entry)
                history.append(turn)
            except json.JSONDecodeError:
                continue
        return history
    except Exception as e:
        logger.warning(f"Failed to load conversation history for {conversation_id}: {e}")
        return []


async def save_conversation_turn(
    conversation_id: str,
    role: str,
    content: str,
) -> None:
    """Save a conversation turn to Redis.

    Args:
        conversation_id: The conversation identifier.
        role: Either 'user' or 'assistant'.
        content: The message content.
    """
    redis_client = _get_redis()
    if not redis_client:
        return

    try:
        key = _conversation_key(conversation_id)
        turn = json.dumps({"role": role, "content": content})
        redis_client.rpush(key, turn)
        # Trim to keep only the most recent turns
        max_turns = settings.CONVERSATION_MAX_TURNS
        redis_client.ltrim(key, -max_turns, -1)
    except Exception as e:
        logger.warning(f"Failed to save conversation turn for {conversation_id}: {e}")


async def save_conversation_turns(
    conversation_id: str,
    turns: List[Dict[str, Any]],
) -> None:
    """Save multiple conversation turns at once."""
    redis_client = _get_redis()
    if not redis_client:
        return

    try:
        key = _conversation_key(conversation_id)
        pipe = redis_client.pipeline()
        for turn in turns:
            entry = json.dumps({
                "role": turn.get("role", "unknown"),
                "content": turn.get("content", ""),
            })
            pipe.rpush(key, entry)
        # Trim to keep only the most recent turns
        max_turns = settings.CONVERSATION_MAX_TURNS
        pipe.ltrim(key, -max_turns, -1)
        pipe.execute()
    except Exception as e:
        logger.warning(f"Failed to save conversation turns for {conversation_id}: {e}")


def is_available() -> bool:
    """Check if Redis conversation memory is available."""
    return _get_redis() is not None
