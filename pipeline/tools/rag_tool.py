"""
pipeline/tools/rag_tool.py

Vector search tool for the XDR RAG pipeline.

Uses langchain_mongodb MongoDBAtlasVectorSearch to retrieve the top-5
most similar xdr_summaries documents via cosine similarity.

Supports pre-filtering on:
  - host
  - event_type
  - severity (matched against severity_distribution keys)
  - timestamp range (window_start / window_end)

Returns a formatted string suitable for use as LangGraph tool output.
"""

import logging
import os
from typing import Any, Optional

from dotenv import load_dotenv
from langchain_core.documents import Document
from langchain_core.tools import tool
from langchain_mongodb import MongoDBAtlasVectorSearch
from langchain_huggingface import HuggingFaceEmbeddings
from pymongo import MongoClient

load_dotenv()

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
MONGODB_URI: str = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
MONGODB_DB: str = os.getenv("MONGODB_DB", "xdr_db")
VECTOR_INDEX_NAME: str = os.getenv("VECTOR_INDEX_NAME", "xdr_vector_index")
EMBED_MODEL: str = os.getenv("EMBED_MODEL", "all-MiniLM-L6-v2")
EMBED_DIMENSIONS: int = int(os.getenv("EMBED_DIMENSIONS", "384"))


# ---------------------------------------------------------------------------
# Embedding model factory
# ---------------------------------------------------------------------------

def _build_embeddings() -> HuggingFaceEmbeddings:
    return HuggingFaceEmbeddings(model_name=EMBED_MODEL)


# ---------------------------------------------------------------------------
# Lazy-initialized singletons
# ---------------------------------------------------------------------------
_mongo_client: Optional[MongoClient] = None
_vector_store: Optional[MongoDBAtlasVectorSearch] = None


def _get_vector_store() -> MongoDBAtlasVectorSearch:
    global _mongo_client, _vector_store
    if _vector_store is None:
        _mongo_client = MongoClient(MONGODB_URI)
        collection = _mongo_client[MONGODB_DB]["xdr_summaries"]
        _vector_store = MongoDBAtlasVectorSearch(
            collection=collection,
            embedding=_build_embeddings(),
            index_name=VECTOR_INDEX_NAME,
            text_key="summary_text",
            embedding_key="embedding",
        )
        log.info("MongoDBAtlasVectorSearch initialized (index=%s).", VECTOR_INDEX_NAME)
    return _vector_store


# ---------------------------------------------------------------------------
# Pre-filter builder
# ---------------------------------------------------------------------------

def _build_prefilter(
    host: Optional[str] = None,
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    after: Optional[str] = None,
    before: Optional[str] = None,
) -> dict[str, Any]:
    """
    Build an Atlas Vector Search pre-filter document.

    Only adds conditions for non-None arguments to avoid over-constraining.
    """
    from datetime import datetime

    conditions: list[dict[str, Any]] = []

    if host:
        conditions.append({"host": {"$eq": host}})
    if event_type:
        conditions.append({"event_type": {"$eq": event_type}})
    # embedding_status must be "done" — always filter to avoid searching null embeddings
    conditions.append({"embedding_status": {"$eq": "done"}})

    if after:
        try:
            after_dt = datetime.fromisoformat(after)
            conditions.append({"window_start": {"$gte": after_dt}})
        except ValueError:
            log.warning("Invalid 'after' timestamp: %s", after)
    if before:
        try:
            before_dt = datetime.fromisoformat(before)
            conditions.append({"window_end": {"$lte": before_dt}})
        except ValueError:
            log.warning("Invalid 'before' timestamp: %s", before)

    if not conditions:
        return {}
    if len(conditions) == 1:
        return conditions[0]
    return {"$and": conditions}


# ---------------------------------------------------------------------------
# Format results
# ---------------------------------------------------------------------------

def _format_results(docs: list[Any]) -> str:
    """Format retrieved documents into a readable string."""
    if not docs:
        return "No matching summaries found."

    lines: list[str] = ["=== RAG Search Results ===\n"]
    for i, doc in enumerate(docs, 1):
        meta = doc.metadata if hasattr(doc, "metadata") else {}
        lines.append(
            f"[{i}] Host: {meta.get('host', 'N/A')} | "
            f"Type: {meta.get('event_type', 'N/A')} | "
            f"Window: {meta.get('window_start', 'N/A')} → {meta.get('window_end', 'N/A')}\n"
        )
        content = doc.page_content if hasattr(doc, "page_content") else str(doc)
        # Truncate very long summaries
        if len(content) > 800:
            content = content[:797] + "..."
        lines.append(f"{content}\n")
        lines.append("-" * 60 + "\n")

    return "".join(lines)


# ---------------------------------------------------------------------------
# Public tool function
# ---------------------------------------------------------------------------

def rag_search(
    query: str,
    host: Optional[str] = None,
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    after: Optional[str] = None,
    before: Optional[str] = None,
    top_k: int = 5,
) -> str:
    """
    Perform a vector similarity search over xdr_summaries.

    Args:
        query:      Natural language question or description.
        host:       Optional host filter (e.g., "PC-101").
        event_type: Optional event type filter (e.g., "Malware").
        severity:   Optional severity filter (not directly indexed; informational).
        after:      Optional ISO timestamp — only windows starting after this.
        before:     Optional ISO timestamp — only windows ending before this.
        top_k:      Number of top results to return (default 5).

    Returns:
        Formatted string of matching summary documents.
    """
    try:
        store = _get_vector_store()
        prefilter = _build_prefilter(
            host=host,
            event_type=event_type,
            severity=severity,
            after=after,
            before=before,
        )

        log.info(
            "RAG search | query='%s' | filter=%s | top_k=%d",
            query[:80],
            prefilter,
            top_k,
        )

        if prefilter:
            docs = store.similarity_search(
                query,
                k=top_k,
                pre_filter=prefilter,
            )
        else:
            docs = store.similarity_search(query, k=top_k)

        return _format_results(docs)

    except Exception as exc:  # noqa: BLE001
        log.error("RAG search error: %s", exc)
        return f"[RAG Error] {exc}"
