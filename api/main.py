"""
api/main.py

FastAPI Application for the XDR RAG Pipeline.

Endpoints:
  POST /query       — Run RAG chain or LangGraph agent
  GET  /health      — Check MongoDB and Elasticsearch connectivity
  GET  /stats       — Return document counts from MongoDB

CORS enabled for Streamlit (localhost:8501 by default).
"""

import logging
import os
import sys
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Optional

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

load_dotenv()

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] api — %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
MONGODB_URI: str = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
MONGODB_DB: str = os.getenv("MONGODB_DB", "xdr_db")
ELASTICSEARCH_URL: str = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")
CORS_ORIGINS_RAW: str = os.getenv("CORS_ORIGINS", "http://localhost:8501")
CORS_ORIGINS: list[str] = [o.strip() for o in CORS_ORIGINS_RAW.split(",") if o.strip()]

# ---------------------------------------------------------------------------
# Lazy MongoDB connection — declared before lifespan so global is in scope
# ---------------------------------------------------------------------------
_mongo_client = None


def _get_mongo_db():
    global _mongo_client
    if _mongo_client is None:
        import pymongo
        _mongo_client = pymongo.MongoClient(MONGODB_URI, serverSelectionTimeoutMS=3000)
    return _mongo_client[MONGODB_DB]


# ---------------------------------------------------------------------------
# Application lifespan (replaces deprecated @app.on_event)
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(application: FastAPI):
    """Startup and shutdown logic using the modern lifespan context manager."""
    log.info("XDR RAG Pipeline API starting up...")
    log.info("CORS origins: %s", CORS_ORIGINS)
    log.info("MongoDB DB: %s", MONGODB_DB)
    log.info("Elasticsearch: %s", ELASTICSEARCH_URL)
    yield
    # Shutdown: close MongoDB connection
    global _mongo_client
    if _mongo_client is not None:
        _mongo_client.close()
    log.info("XDR RAG Pipeline API shut down.")


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------
app = FastAPI(
    title="XDR RAG Pipeline API",
    description=(
        "REST API for the XDR Extended Detection and Response RAG pipeline. "
        "Provides query, health check, and statistics endpoints."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS + ["http://localhost:3000"],  # also allow dev React apps
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class QueryRequest(BaseModel):
    question: str = Field(..., min_length=3, max_length=2000, description="Security question to ask")
    use_agent: bool = Field(default=True, description="Use LangGraph agent (true) or simple RAG chain (false)")


class QueryResponse(BaseModel):
    question: str
    answer: str
    tools_used: list[str] = Field(default_factory=list)
    mode: str  # "agent" or "rag"
    elapsed_ms: float


class HealthStatus(BaseModel):
    status: str  # "healthy" | "degraded" | "unhealthy"
    timestamp: str
    services: dict[str, dict[str, Any]]


class StatsResponse(BaseModel):
    total_events: int
    total_summaries: int
    embedded_summaries: int
    pending_summaries: int
    error_summaries: int
    timestamp: str


# ---------------------------------------------------------------------------
# Endpoint: POST /query
# ---------------------------------------------------------------------------

@app.post("/query", response_model=QueryResponse)
async def query_endpoint(request: QueryRequest):
    """
    Submit a security question to the XDR RAG pipeline.

    - **use_agent=true**: Routes through the LangGraph ReAct agent (recommended).
      The agent selects the best tool(s): vector search, MongoDB aggregation,
      or Elasticsearch full-text search.
    - **use_agent=false**: Runs the simple LangChain RAG chain (vector search only).
    """
    import time

    log.info(
        "Query received | mode=%s | question='%s'",
        "agent" if request.use_agent else "rag",
        request.question[:100],
    )

    start = time.perf_counter()
    try:
        if request.use_agent:
            from pipeline.agent import run_agent
            result = run_agent(request.question)
            answer = result["answer"]
            tools_used = result["tools_used"]
            mode = "agent"
        else:
            from pipeline.rag_chain import run_rag_chain
            answer = run_rag_chain(request.question)
            tools_used = ["rag_search"]
            mode = "rag"

    except Exception as exc:  # noqa: BLE001
        log.error("Query error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    elapsed = (time.perf_counter() - start) * 1000

    return QueryResponse(
        question=request.question,
        answer=answer,
        tools_used=tools_used,
        mode=mode,
        elapsed_ms=round(elapsed, 2),
    )


# ---------------------------------------------------------------------------
# Endpoint: GET /health
# ---------------------------------------------------------------------------

@app.get("/health", response_model=HealthStatus)
async def health_endpoint():
    """
    Check connectivity to MongoDB and Elasticsearch.

    Returns overall status and per-service details.
    """
    services: dict[str, dict[str, Any]] = {}
    all_ok = True

    # --- MongoDB ---
    try:
        db = _get_mongo_db()
        db.command("ping")
        # Check collections exist
        collection_names = db.list_collection_names()
        services["mongodb"] = {
            "status": "up",
            "collections": collection_names,
            "uri": MONGODB_URI[:40] + "..." if len(MONGODB_URI) > 40 else MONGODB_URI,
        }
    except Exception as exc:  # noqa: BLE001
        services["mongodb"] = {"status": "down", "error": str(exc)}
        all_ok = False

    # --- Elasticsearch ---
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"{ELASTICSEARCH_URL}/_cluster/health")
            resp.raise_for_status()
            es_data = resp.json()
        services["elasticsearch"] = {
            "status": "up",
            "cluster_status": es_data.get("status", "unknown"),
            "number_of_nodes": es_data.get("number_of_nodes", 0),
            "url": ELASTICSEARCH_URL,
        }
    except Exception as exc:  # noqa: BLE001
        services["elasticsearch"] = {"status": "down", "error": str(exc)}
        all_ok = False

    overall = "healthy" if all_ok else "degraded"
    if not any(s.get("status") == "up" for s in services.values()):
        overall = "unhealthy"

    return HealthStatus(
        status=overall,
        timestamp=datetime.now(tz=timezone.utc).isoformat(),
        services=services,
    )


# ---------------------------------------------------------------------------
# Endpoint: GET /stats
# ---------------------------------------------------------------------------

@app.get("/stats", response_model=StatsResponse)
async def stats_endpoint():
    """
    Return document counts from the XDR MongoDB collections.

    Useful for monitoring pipeline progress:
      - total_events: raw events ingested from Kafka
      - total_summaries: number of 5-minute window summaries
      - embedded_summaries: summaries with vector embeddings ready
      - pending_summaries: summaries awaiting embedding
      - error_summaries: summaries that failed embedding
    """
    try:
        db = _get_mongo_db()
        events_col = db["xdr_events"]
        summaries_col = db["xdr_summaries"]

        total_events = events_col.count_documents({})
        total_summaries = summaries_col.count_documents({})
        embedded = summaries_col.count_documents({"embedding_status": "done"})
        pending = summaries_col.count_documents({"embedding_status": "pending"})
        error = summaries_col.count_documents({"embedding_status": "error"})

        return StatsResponse(
            total_events=total_events,
            total_summaries=total_summaries,
            embedded_summaries=embedded,
            pending_summaries=pending,
            error_summaries=error,
            timestamp=datetime.now(tz=timezone.utc).isoformat(),
        )
    except Exception as exc:  # noqa: BLE001
        log.error("Stats error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Entry point (for running directly with python api/main.py)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys
    from pathlib import Path
    
    # Add project root to path
    project_root = str(Path(__file__).parent.parent)
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
        
    import uvicorn

    port = int(os.getenv("API_PORT", "8000"))
    uvicorn.run(
        "api.main:app",
        host="0.0.0.0",
        port=port,
        reload=True,
        log_level="info",
    )
