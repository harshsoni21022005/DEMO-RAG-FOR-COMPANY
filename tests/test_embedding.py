"""
tests/test_embedding.py

Unit tests for the embedding worker logic.

Tests the pure helper functions and retry behavior (no real API calls).
Uses unittest.mock to patch the HuggingFaceEmbeddings client.
"""

import asyncio
import pytest
import unittest.mock as mock
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

# ---------------------------------------------------------------------------
# Tests: EmbeddingWorker.run_once (with mocked DB + HF Embeddings)
# ---------------------------------------------------------------------------

class TestEmbeddingWorkerRunOnce:
    """Integration-level tests for run_once with fully mocked dependencies."""

    def _make_worker(self, pending_docs=None, embed_result=None):
        """Create an EmbeddingWorker with all dependencies mocked."""
        from workers.embedding_worker import EmbeddingWorker

        # We must mock HuggingFaceEmbeddings before initializing the worker
        # so it doesn't download models during tests.
        with patch("workers.embedding_worker.HuggingFaceEmbeddings") as MockEmbedder:
            mock_embed_client = MagicMock()
            if isinstance(embed_result, Exception):
                mock_embed_client.aembed_documents = AsyncMock(side_effect=embed_result)
            else:
                mock_embed_client.aembed_documents = AsyncMock(return_value=embed_result or [])
            MockEmbedder.return_value = mock_embed_client

            worker = EmbeddingWorker()

        # Mock MongoDB
        mock_col = MagicMock()
        pending_docs = pending_docs or []

        async def mock_to_list(length):
            return pending_docs

        mock_cursor = MagicMock()
        mock_cursor.to_list = mock_to_list
        mock_col.find.return_value.limit.return_value = mock_cursor
        mock_col.bulk_write = AsyncMock(return_value=MagicMock(modified_count=len(pending_docs)))
        mock_col.update_many = AsyncMock()

        worker.summaries_col = mock_col
        return worker

    @pytest.mark.asyncio
    async def test_no_pending_docs_returns_zero(self):
        """run_once should return 0 when no documents are pending."""
        worker = self._make_worker(pending_docs=[])

        result = await worker.run_once()
        assert result == 0

    @pytest.mark.asyncio
    async def test_skips_empty_summary_text(self):
        """Documents with empty summary_text should be marked as error."""
        from bson import ObjectId

        pending_docs = [
            {"_id": ObjectId(), "summary_text": ""},
            {"_id": ObjectId(), "summary_text": "   "},
        ]
        # Even if we return no vectors, it shouldn't crash
        worker = self._make_worker(pending_docs=pending_docs, embed_result=[])

        result = await worker.run_once()

        # Empty docs should be marked as error, not embedded
        assert result == 0
        worker.summaries_col.update_many.assert_called_once()
        
    @pytest.mark.asyncio
    async def test_successful_embedding(self):
        """Should embed successfully and return number of embedded docs."""
        from bson import ObjectId
        pending_docs = [
            {"_id": ObjectId(), "summary_text": "hello"},
            {"_id": ObjectId(), "summary_text": "world"},
        ]
        worker = self._make_worker(pending_docs=pending_docs, embed_result=[[0.1, 0.2], [0.3, 0.4]])

        result = await worker.run_once()
        
        # 2 documents processed successfully
        assert result == 2
        worker.summaries_col.bulk_write.assert_called_once()
        
    @pytest.mark.asyncio
    async def test_embedding_api_failure(self):
        """If embedding model throws, docs should be marked as error."""
        from bson import ObjectId
        pending_docs = [
            {"_id": ObjectId(), "summary_text": "hello"},
        ]
        worker = self._make_worker(pending_docs=pending_docs, embed_result=RuntimeError("Model error"))

        result = await worker.run_once()
        
        # 0 embedded, marked as error
        assert result == 0
        worker.summaries_col.update_many.assert_called_once()
