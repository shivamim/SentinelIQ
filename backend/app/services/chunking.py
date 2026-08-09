"""Deterministic chunking service with overlap and metadata preservation.

Splits documents into chunks of ~1600-2400 characters (approx 400-600 tokens
at ~4 chars/token) with ~15% overlap between consecutive chunks.
"""
from typing import List, Dict, Any


def chunk_document(
    content: str,
    metadata: Dict[str, Any],
    chunk_size: int = 2000,
    overlap: int = 300,
) -> List[Dict[str, Any]]:
    """Split a document into overlapping chunks with enriched metadata.

    Args:
        content: The full document text to chunk.
        metadata: Parent document metadata to propagate into each chunk.
            May contain keys like document_id, document_type, source,
            technique_id, cve_id, incident_id.
        chunk_size: Target chunk size in characters (~2000 = ~500 tokens).
        overlap: Number of overlapping characters between consecutive chunks
            (~300 = ~15% of 2000).

    Returns:
        List of chunk dicts, each containing:
            - chunk_text: the text of this chunk
            - chunk_index: zero-based position index
            - metadata: parent metadata merged with chunk-specific info
    """
    if not content or not content.strip():
        return []

    # Normalize whitespace but preserve intentional line breaks
    text = content.strip()

    # If the document fits in a single chunk, return it as-is
    if len(text) <= chunk_size:
        chunk_meta = dict(metadata)
        chunk_meta["chunk_index"] = 0
        chunk_meta["total_chunks"] = 1
        return [
            {
                "chunk_text": text,
                "chunk_index": 0,
                "metadata": chunk_meta,
            }
        ]

    # Calculate effective step (chunk_size - overlap), ensuring positive step
    step = max(chunk_size - overlap, 1)
    chunks: List[Dict[str, Any]] = []
    start = 0
    chunk_index = 0

    while start < len(text):
        end = start + chunk_size

        # If this is not the last chunk, try to break at a sentence/paragraph
        # boundary to avoid cutting mid-sentence.
        if end < len(text):
            boundary = _find_boundary(text, start, end)
            if boundary is not None:
                end = boundary

        chunk_text = text[start:end].strip()
        if chunk_text:  # Skip empty chunks
            chunk_meta = dict(metadata)
            chunk_meta["chunk_index"] = chunk_index
            chunks.append(
                {
                    "chunk_text": chunk_text,
                    "chunk_index": chunk_index,
                    "metadata": chunk_meta,
                }
            )
            chunk_index += 1

        # Advance by step, but if we broke at a boundary we advance to end
        # of current chunk minus overlap
        start = end - overlap

        # Safety: ensure progress (avoid infinite loop)
        if start <= (end - step) and end < len(text):
            start = end - overlap

    # Set total_chunks on all metadata dicts
    total = len(chunks)
    for chunk in chunks:
        chunk["metadata"]["total_chunks"] = total

    return chunks


def _find_boundary(text: str, start: int, end: int) -> int | None:
    """Find a natural text boundary (sentence or paragraph) near `end`.

    Searches backwards from `end` for sentence-ending punctuation followed
    by whitespace, or a double newline (paragraph break). Falls back to
    a single newline if no sentence boundary is found.

    Returns the boundary position (inclusive of the punctuation), or None
    if no suitable boundary is found within the search window.
    """
    # Search window: look back up to 20% of chunk_size from `end`
    search_start = max(start + (end - start) // 2, start)

    # Try paragraph break (double newline) first — strongest boundary
    for i in range(end, search_start, -1):
        if i < len(text) - 1 and text[i] == '\n' and i + 1 < len(text) and text[i + 1] == '\n':
            return i

    # Try sentence-ending punctuation (. ! ?) followed by whitespace
    for i in range(min(end, len(text) - 1), search_start, -1):
        if text[i] in ('.', '!', '?') and i + 1 < len(text) and text[i + 1] in (' ', '\n', '\t'):
            return i + 1  # Include the punctuation, break after the space

    # Try single newline as a weaker boundary
    for i in range(min(end, len(text) - 1), search_start, -1):
        if text[i] == '\n':
            return i

    return None
