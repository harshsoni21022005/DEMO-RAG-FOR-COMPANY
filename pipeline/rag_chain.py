"""
pipeline/rag_chain.py

LangChain RAG Chain for the XDR RAG Pipeline.

Provides a simple retrieval-augmented generation chain that:
1. Embeds the user question
2. Performs vector similarity search over xdr_summaries
3. Formats retrieved context
4. Invokes the configured LLM to produce a final answer

This is the "simple" (non-agent) path. For multi-tool orchestration
see pipeline/agent.py.
"""

import logging
import os
from typing import Any, Optional

from dotenv import load_dotenv
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.runnables import RunnablePassthrough
from langchain_mongodb import MongoDBAtlasVectorSearch
from langchain_groq import ChatGroq
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

GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
LLM_MODEL: str = os.getenv("LLM_MODEL", "llama3-70b-8192")
LLM_BASE_URL: Optional[str] = os.getenv("LLM_BASE_URL") or None
LLM_TEMPERATURE: float = float(os.getenv("LLM_TEMPERATURE", "0.0"))

EMBED_MODEL: str = os.getenv("EMBED_MODEL", "all-MiniLM-L6-v2")
EMBED_DIMENSIONS: int = int(os.getenv("EMBED_DIMENSIONS", "384"))

# Number of documents to retrieve
RAG_TOP_K: int = 5

# ---------------------------------------------------------------------------
# RAG system prompt
# ---------------------------------------------------------------------------
RAG_SYSTEM_PROMPT = """You are an expert XDR (Extended Detection and Response) security analyst.

You have access to a knowledge base of XDR event summaries from a fleet of monitored hosts.
Each summary covers a 5-minute window and describes security events including:
  - Attack types and signatures
  - Severity distributions  
  - Source and destination IP patterns
  - Process names, usernames, and MITRE ATT&CK techniques

Use the provided context to answer the security analyst's question accurately and concisely.
If the context is insufficient, say so clearly rather than speculating.

Format your response as a security analyst would:
  - Lead with the most critical findings
  - Use bullet points for multiple items
  - Reference specific hosts, event types, and time windows from the context
  - Note any patterns or correlations you observe

Context from XDR summaries:
{context}"""

RAG_HUMAN_PROMPT = "Security Question: {question}"


# ---------------------------------------------------------------------------
# LLM factory
# ---------------------------------------------------------------------------

def _build_llm() -> ChatGroq:
    kwargs: dict[str, Any] = {
        "model": LLM_MODEL,
        "api_key": GROQ_API_KEY,
        "temperature": LLM_TEMPERATURE,
    }
    if LLM_BASE_URL:
        kwargs["base_url"] = LLM_BASE_URL
        log.info("LLM using custom base URL: %s (model=%s)", LLM_BASE_URL, LLM_MODEL)
    else:
        log.info("LLM using Groq API (model=%s).", LLM_MODEL)
    return ChatGroq(**kwargs)


def _build_embeddings() -> HuggingFaceEmbeddings:
    return HuggingFaceEmbeddings(model_name=EMBED_MODEL)


# ---------------------------------------------------------------------------
# Lazy-initialized RAG chain singleton
# ---------------------------------------------------------------------------
_mongo_client: Optional[MongoClient] = None
_rag_chain = None


def _get_rag_chain():
    """
    Build and return a LangChain RAG chain.

    Chain:
      question → retriever → format context → LLM → string output
    """
    global _mongo_client, _rag_chain
    if _rag_chain is not None:
        return _rag_chain

    # Build vector store
    _mongo_client = MongoClient(MONGODB_URI)
    collection = _mongo_client[MONGODB_DB]["xdr_summaries"]

    vector_store = MongoDBAtlasVectorSearch(
        collection=collection,
        embedding=_build_embeddings(),
        index_name=VECTOR_INDEX_NAME,
        text_key="summary_text",
        embedding_key="embedding",
    )

    # Only retrieve documents that have been embedded
    retriever = vector_store.as_retriever(
        search_type="similarity",
        search_kwargs={
            "k": RAG_TOP_K,
            "pre_filter": {"embedding_status": {"$eq": "done"}},
        },
    )

    # Prompt template
    prompt = ChatPromptTemplate.from_messages(
        [
            ("system", RAG_SYSTEM_PROMPT),
            ("human", RAG_HUMAN_PROMPT),
        ]
    )

    llm = _build_llm()

    def _format_docs(docs) -> str:
        """Format retrieved documents into a single context string."""
        if not docs:
            return "No relevant XDR summaries found."
        parts = []
        for i, doc in enumerate(docs, 1):
            meta = doc.metadata if hasattr(doc, "metadata") else {}
            header = (
                f"--- Summary {i} | Host: {meta.get('host', '?')} | "
                f"Type: {meta.get('event_type', '?')} | "
                f"Window: {meta.get('window_start', '?')} → {meta.get('window_end', '?')} ---"
            )
            parts.append(f"{header}\n{doc.page_content}")
        return "\n\n".join(parts)

    # Build LCEL chain
    _rag_chain = (
        {
            "context": retriever | _format_docs,
            "question": RunnablePassthrough(),
        }
        | prompt
        | llm
        | StrOutputParser()
    )

    log.info("RAG chain initialized (vector_index=%s, top_k=%d).", VECTOR_INDEX_NAME, RAG_TOP_K)
    return _rag_chain


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def run_rag_chain(question: str) -> str:
    """
    Run the simple RAG chain for a given security question.

    Args:
        question: Natural language security question.

    Returns:
        LLM-generated answer grounded in retrieved XDR summaries.
    """
    try:
        chain = _get_rag_chain()
        log.info("Running RAG chain for question: '%s'", question[:100])
        result = chain.invoke(question)
        return result
    except Exception as exc:  # noqa: BLE001
        log.error("RAG chain error: %s", exc)
        return f"[RAG Chain Error] {exc}"
