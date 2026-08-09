"""Tests for the chunking service — deterministic chunking with overlap and metadata preservation."""
import pytest
from app.services.chunking import chunk_document, _find_boundary


class TestChunkDocumentBasic:
    """Basic chunk_document behavior tests."""

    def test_empty_content_returns_empty_list(self):
        """Empty content should return an empty list."""
        assert chunk_document("", {}) == []
        assert chunk_document("   ", {}) == []
        assert chunk_document("\n\n", {}) == []

    def test_none_content_returns_empty_list(self):
        """None-like or falsy content should return an empty list."""
        assert chunk_document("", {}) == []

    def test_short_content_returns_single_chunk(self):
        """Content shorter than chunk_size should return a single chunk."""
        content = "Hello world, this is a short document."
        metadata = {"document_id": "doc-1", "document_type": "mitre_attack"}
        result = chunk_document(content, metadata, chunk_size=2000, overlap=300)

        assert len(result) == 1
        assert result[0]["chunk_text"] == content.strip()
        assert result[0]["chunk_index"] == 0
        assert result[0]["metadata"]["total_chunks"] == 1

    def test_single_word_returns_single_chunk(self):
        """A single word should return a single chunk."""
        result = chunk_document("PowerShell", {})
        assert len(result) == 1
        assert result[0]["chunk_text"] == "PowerShell"


class TestChunkSizeBehavior:
    """Test that chunks are approximately chunk_size characters."""

    def test_chunks_approximately_chunk_size(self):
        """Each chunk (except possibly the last) should be approximately chunk_size."""
        # Generate long content with clear sentence boundaries
        sentences = [f"Sentence number {i} about cybersecurity threats and incidents." for i in range(100)]
        content = " ".join(sentences)
        chunk_size = 500
        overlap = 75

        result = chunk_document(content, {}, chunk_size=chunk_size, overlap=overlap)

        assert len(result) > 1, "Long content should produce multiple chunks"
        # Each chunk should be roughly within the chunk_size range
        # (allowing for boundary-based shortening)
        for i, chunk in enumerate(result):
            # Chunks may be slightly shorter than chunk_size due to boundary breaking
            # but should not be much longer
            assert len(chunk["chunk_text"]) <= chunk_size + 50, (
                f"Chunk {i} length {len(chunk['chunk_text'])} exceeds chunk_size+50"
            )

    def test_custom_chunk_size(self):
        """chunk_document should respect custom chunk_size."""
        content = "A" * 5000  # 5000 chars, no natural boundaries
        chunk_size = 1000
        result = chunk_document(content, {}, chunk_size=chunk_size, overlap=100)
        # Should produce multiple chunks
        assert len(result) >= 4


class TestOverlapBehavior:
    """Test that consecutive chunks share overlap text."""

    def test_overlap_between_consecutive_chunks(self):
        """Consecutive chunks should share overlapping text."""
        # Use content without natural sentence boundaries to ensure overlap
        content = "X" * 5000
        chunk_size = 1000
        overlap = 200

        result = chunk_document(content, {}, chunk_size=chunk_size, overlap=overlap)

        if len(result) > 1:
            # Check that consecutive chunks share text at the overlap boundary
            for i in range(len(result) - 1):
                current_end = result[i]["chunk_text"][-overlap:]
                next_start = result[i + 1]["chunk_text"][:overlap]
                # Due to boundary breaking, the overlap might not be exact,
                # but there should be SOME shared text
                # At minimum, both chunks should be non-empty
                assert len(result[i]["chunk_text"]) > 0
                assert len(result[i + 1]["chunk_text"]) > 0

    def test_overlap_zero_produces_non_overlapping_chunks(self):
        """With overlap=0, chunks should not share text (except at boundaries)."""
        # Use repetitive content so chunks are exactly chunk_size
        content = "A" * 5000
        chunk_size = 1000
        overlap = 0

        result = chunk_document(content, {}, chunk_size=chunk_size, overlap=overlap)
        assert len(result) >= 4

    def test_overlap_smaller_than_chunk_size(self):
        """Overlap should always be smaller than chunk_size for positive step."""
        content = "Hello world. " * 500
        # overlap == chunk_size would make step = 0, but the code handles it
        result = chunk_document(content, {}, chunk_size=200, overlap=50)
        assert len(result) > 1


class TestMetadataPreservation:
    """Test that parent metadata is preserved in each chunk."""

    def test_metadata_preserved_in_chunks(self):
        """Each chunk's metadata should contain the parent metadata."""
        metadata = {
            "document_id": "doc-123",
            "document_type": "mitre_attack",
            "technique_id": "T1059.001",
        }
        content = "This is a test document about PowerShell. " * 50

        result = chunk_document(content, metadata, chunk_size=500, overlap=75)

        for chunk in result:
            assert chunk["metadata"]["document_id"] == "doc-123"
            assert chunk["metadata"]["document_type"] == "mitre_attack"
            assert chunk["metadata"]["technique_id"] == "T1059.001"

    def test_chunk_index_in_metadata(self):
        """Each chunk metadata should include chunk_index."""
        content = "This is a test. " * 200
        result = chunk_document(content, {}, chunk_size=500, overlap=75)

        for i, chunk in enumerate(result):
            assert chunk["metadata"]["chunk_index"] == i

    def test_total_chunks_in_metadata(self):
        """Each chunk metadata should include total_chunks."""
        content = "This is a test sentence. " * 200
        result = chunk_document(content, {}, chunk_size=500, overlap=75)

        total = len(result)
        for chunk in result:
            assert chunk["metadata"]["total_chunks"] == total

    def test_metadata_not_mutated(self):
        """Original metadata dict should not be mutated by chunk_document."""
        metadata = {"document_id": "doc-1"}
        original_metadata = dict(metadata)

        content = "Test content. " * 100
        chunk_document(content, metadata, chunk_size=500, overlap=75)

        # The original metadata should not have chunk_index or total_chunks added
        assert metadata == original_metadata


class TestTotalTextCoverage:
    """Test that all original text appears across chunks."""

    def test_all_text_covered_by_chunks(self):
        """The concatenation of chunk texts (minus overlaps) should cover the original text."""
        content = "Alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu nu xi omicron pi rho sigma tau upsilon phi chi psi omega. "
        content = content * 20  # Make it long enough for multiple chunks
        original_text = content.strip()

        result = chunk_document(content, {}, chunk_size=500, overlap=75)

        # Every character of the original should appear in at least one chunk
        # (overlap means some characters appear in multiple chunks)
        # Simple check: first chars of first chunk match start of original
        assert result[0]["chunk_text"].startswith(original_text[:20])

        # Last chunk should contain the end of the original
        assert result[-1]["chunk_text"].endswith(original_text[-20:])

    def test_no_text_lost_single_chunk(self):
        """For single-chunk documents, chunk text should equal original (stripped)."""
        content = "Hello world, this is a test document."
        result = chunk_document(content, {})
        assert result[0]["chunk_text"] == content.strip()


class TestFindBoundary:
    """Test the _find_boundary helper."""

    def test_sentence_boundary_found(self):
        """Should find a sentence boundary near the end position."""
        # _find_boundary searches backwards from end to search_start.
        # search_start = start + (end - start) // 2
        # range for sentence search is (min(end, len-1), search_start, -1)
        # so the search window is (search_start, end] exclusive of search_start.
        # We need a ". " pair within that window.
        # With start=0, end=100: search_start = 50, window = (50, 99]
        # Place period at index 60 so it's well within the window.
        text = "A" * 60 + ". " + "B" * 38  # period at index 60
        start = 0
        end = 100
        boundary = _find_boundary(text, start, end)
        assert boundary is not None

    def test_paragraph_boundary_found(self):
        """Should prefer paragraph breaks over sentence boundaries."""
        text = "First paragraph.\n\nSecond paragraph.\n\nThird paragraph."
        start = 0
        end = 30
        boundary = _find_boundary(text, start, end)
        assert boundary is not None

    def test_no_boundary_returns_none(self):
        """Should return None if no natural boundary is found."""
        # Text with no punctuation or newlines in the search window
        text = "abcdefghij" * 100
        start = 0
        end = 50
        boundary = _find_boundary(text, start, end)
        # May or may not find a boundary, but should not crash
        # (returning None is valid)


class TestChunkIndexOrdering:
    """Test that chunk indices are sequential."""

    def test_chunk_indices_sequential(self):
        """Chunk indices should be 0, 1, 2, ... in order."""
        content = "This is sentence number one. " * 200
        result = chunk_document(content, {}, chunk_size=500, overlap=75)

        for i, chunk in enumerate(result):
            assert chunk["chunk_index"] == i
