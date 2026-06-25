"""
workers/embedding_worker.py

Embedding Worker for the XDR RAG Pipeline.

Reads xdr_summaries documents where embedding_status="pending" in batches,
calls the local HuggingFace embedding model, and updates each document with:
  - embedding: list[float]
  - embedding_status: "done"
  - embedded_at: datetime

Runs in a continuous loop with EMBEDDING_SLEEP seconds between batches.
"""

import asyncio
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any

import motor.motor_asyncio
from dotenv import load_dotenv
from langchain_huggingface import HuggingFaceEmbeddings
from pymongo import UpdateOne
from pymongo.errors import BulkWriteError, PyMongoError

load_dotenv()

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] embedding_worker — %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
MONGODB_URI: str = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
MONGODB_DB: str = os.getenv("MONGODB_DB", "xdr_db")

EMBED_MODEL: str = os.getenv("EMBED_MODEL", "all-MiniLM-L6-v2")

EMBEDDING_BATCH_SIZE: int = int(os.getenv("EMBEDDING_BATCH_SIZE", "50"))
EMBEDDING_SLEEP: int = int(os.getenv("EMBEDDING_SLEEP", "10"))


# ---------------------------------------------------------------------------
# Core Worker
# ---------------------------------------------------------------------------

class EmbeddingWorker:
    """
    Continuously fetches xdr_summaries with embedding_status='pending',
    embeds their summary_text, and stores the embedding back.
    """

    def __init__(self) -> None:
        self.client = motor.motor_asyncio.AsyncIOMotorClient(MONGODB_URI)
        self.db = self.client[MONGODB_DB]
        self.summaries_col = self.db["xdr_summaries"]
        
        log.info("Loading HuggingFace model: %s...", EMBED_MODEL)
        self.embed_client = HuggingFaceEmbeddings(model_name=EMBED_MODEL)
        log.info("HuggingFace model loaded.")

    async def ensure_indexes(self) -> None:
        """Ensure indexes are present."""
        await self.summaries_col.create_index(
            [("embedding_status", 1)],
            name="idx_embedding_status",
        )
        log.info("Indexes ensured on xdr_summaries.")

    async def fetch_pending_batch(self) -> list[dict[str, Any]]:
        """Fetch the next batch of summaries awaiting embedding."""
        cursor = self.summaries_col.find(
            {"embedding_status": "pending"},
            projection={"_id": 1, "summary_text": 1},
        ).limit(EMBEDDING_BATCH_SIZE)
        return await cursor.to_list(length=EMBEDDING_BATCH_SIZE)

    async def mark_batch_error(self, doc_ids: list[Any]) -> None:
        """Mark a batch of documents as failed so they don't block the queue."""
        await self.summaries_col.update_many(
            {"_id": {"$in": doc_ids}},
            {"$set": {"embedding_status": "error", "updated_at": datetime.now(tz=timezone.utc)}},
        )

    async def run_once(self) -> int:
        """
        Process one batch of pending summaries.

        Returns the number of documents successfully embedded.
        """
        batch = await self.fetch_pending_batch()
        if not batch:
            return 0

        log.info("Processing batch of %d pending summaries.", len(batch))

        doc_ids = [doc["_id"] for doc in batch]
        texts = [doc.get("summary_text", "") for doc in batch]

        # Filter out empty texts to avoid API errors
        non_empty_indices = [i for i, t in enumerate(texts) if t.strip()]
        if not non_empty_indices:
            log.warning("Batch contains only empty summary_text. Skipping.")
            await self.mark_batch_error(doc_ids)
            return 0

        non_empty_texts = [texts[i] for i in non_empty_indices]
        non_empty_ids = [doc_ids[i] for i in non_empty_indices]

        try:
            # HuggingFaceEmbeddings uses a threadpool internally for aembed_documents
            vectors = await self.embed_client.aembed_documents(non_empty_texts)
        except Exception as exc:
            log.error("Embedding failed for batch: %s. Marking as error.", exc)
            await self.mark_batch_error(doc_ids)
            return 0

        if len(vectors) != len(non_empty_texts):
            log.error(
                "Embedding model returned %d vectors for %d texts. Marking as error.",
                len(vectors), len(non_empty_texts),
            )
            await self.mark_batch_error(doc_ids)
            return 0

        # Build bulk update operations
        now = datetime.now(tz=timezone.utc)
        operations: list[UpdateOne] = []
        for doc_id, vector in zip(non_empty_ids, vectors):
            operations.append(
                UpdateOne(
                    {"_id": doc_id},
                    {
                        "$set": {
                            "embedding": vector,
                            "embedding_status": "done",
                            "embedded_at": now,
                            "updated_at": now,
                            "dirty": False,
                        }
                    },
                )
            )

        # Mark empty-text docs as error
        empty_ids = [doc_ids[i] for i in range(len(doc_ids)) if i not in non_empty_indices]
        for doc_id in empty_ids:
            operations.append(
                UpdateOne(
                    {"_id": doc_id},
                    {
                        "$set": {
                            "embedding_status": "error",
                            "updated_at": now,
                        }
                    },
                )
            )

        try:
            result = await self.summaries_col.bulk_write(operations, ordered=False)
            embedded = result.modified_count
            log.info(
                "Embedded %d summaries (modified=%d).",
                len(non_empty_ids),
                embedded,
            )
            return embedded
        except BulkWriteError as exc:
            log.error("Bulk write error saving embeddings: %s", exc.details)
            return 0

    async def run(self) -> None:
        """Main loop — continuously embeds pending summaries."""
        log.info(
            "Embedding worker starting. "
            "Model=%s | BatchSize=%d | Sleep=%ds",
            EMBED_MODEL,
            EMBEDDING_BATCH_SIZE,
            EMBEDDING_SLEEP,
        )

        await self.ensure_indexes()

        total_embedded = 0
        while True:
            try:
                n = await self.run_once()
                total_embedded += n
                if n == 0:
                    log.debug("No pending summaries. Sleeping %ds...", EMBEDDING_SLEEP)
                else:
                    log.info(
                        "Batch done. Total embedded this session: %d",
                        total_embedded,
                    )
            except PyMongoError as exc:
                log.error("MongoDB error in embedding loop: %s", exc)
            except Exception as exc:  # noqa: BLE001
                log.exception("Unexpected error in embedding loop: %s", exc)

            await asyncio.sleep(EMBEDDING_SLEEP)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    worker = EmbeddingWorker()
    try:
        asyncio.run(worker.run())
    except KeyboardInterrupt:
        log.info("Embedding worker stopped by user.")
