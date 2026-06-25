"""
pipeline/tools/aggregation_tool.py

MongoDB Aggregation Tool for the XDR RAG Pipeline.

Performs analytical / statistical queries against xdr_events using
pre-built aggregation pipelines triggered by keyword matching.

Supported query patterns:
  - "how many" / "count"       → count by event_type
  - "top host" / "most alerts" → rank hosts by event count
  - "yesterday"                → filter last 24 hours
  - "last 24 hours"            → same
  - "severity"                 → group by severity
  - "today"                    → today's date range
  - raw JSON pipeline          → execute directly

Returns a formatted string result.
"""

import json
import logging
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from dotenv import load_dotenv
from pymongo import MongoClient
from pymongo.errors import PyMongoError

load_dotenv()

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
MONGODB_URI: str = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
MONGODB_DB: str = os.getenv("MONGODB_DB", "xdr_db")


# ---------------------------------------------------------------------------
# Lazy-initialized singleton
# ---------------------------------------------------------------------------
_mongo_client: Optional[MongoClient] = None


def _get_events_collection():
    global _mongo_client
    if _mongo_client is None:
        _mongo_client = MongoClient(MONGODB_URI)
        log.info("MongoDB client initialized for aggregation tool.")
    return _mongo_client[MONGODB_DB]["xdr_events"]


def _get_summaries_collection():
    global _mongo_client
    if _mongo_client is None:
        _mongo_client = MongoClient(MONGODB_URI)
    return _mongo_client[MONGODB_DB]["xdr_summaries"]


# ---------------------------------------------------------------------------
# Pre-built pipeline library
# ---------------------------------------------------------------------------

def _pipeline_count_by_event_type() -> list[dict]:
    """Count events grouped by event_type."""
    return [
        {"$group": {"_id": "$event_type", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$project": {"event_type": "$_id", "count": 1, "_id": 0}},
    ]


def _pipeline_top_hosts(limit: int = 10) -> list[dict]:
    """Rank hosts by total alert count."""
    return [
        {"$group": {"_id": "$host", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": limit},
        {"$project": {"host": "$_id", "count": 1, "_id": 0}},
    ]


def _pipeline_last_24h() -> list[dict]:
    """Filter events from the last 24 hours and count by event_type."""
    cutoff = datetime.now(tz=timezone.utc) - timedelta(hours=24)
    return [
        {"$match": {"timestamp": {"$gte": cutoff}}},
        {"$group": {"_id": "$event_type", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$project": {"event_type": "$_id", "count": 1, "_id": 0}},
    ]


def _pipeline_today() -> list[dict]:
    """Filter events from today (UTC midnight to now)."""
    now = datetime.now(tz=timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    return [
        {"$match": {"timestamp": {"$gte": today_start, "$lte": now}}},
        {"$group": {"_id": "$event_type", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$project": {"event_type": "$_id", "count": 1, "_id": 0}},
    ]


def _pipeline_severity_distribution() -> list[dict]:
    """Count events grouped by severity across all event types."""
    return [
        {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$project": {"severity": "$_id", "count": 1, "_id": 0}},
    ]


def _pipeline_total_count() -> list[dict]:
    """Count total events."""
    return [{"$count": "total_events"}]


def _pipeline_host_event_breakdown(host: Optional[str] = None) -> list[dict]:
    """Count events per event_type, optionally filtered by host."""
    match_stage: dict = {}
    if host:
        match_stage["host"] = host
    pipeline = []
    if match_stage:
        pipeline.append({"$match": match_stage})
    pipeline += [
        {"$group": {"_id": {"host": "$host", "event_type": "$event_type"}, "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$project": {"host": "$_id.host", "event_type": "$_id.event_type", "count": 1, "_id": 0}},
    ]
    return pipeline


# ---------------------------------------------------------------------------
# Keyword matcher
# ---------------------------------------------------------------------------

def _detect_pipeline(query: str) -> tuple[str, list[dict], str]:
    """
    Map a natural language query to the best pre-built pipeline.

    Returns (pipeline_name, pipeline_stages, collection_name).
    """
    q = query.lower()

    # Check for raw JSON pipeline passed in
    stripped = query.strip()
    if stripped.startswith("["):
        try:
            raw = json.loads(stripped)
            return "raw_pipeline", raw, "xdr_events"
        except json.JSONDecodeError:
            pass

    # Severity distribution
    if re.search(r"\bseverity\b", q):
        return "severity_distribution", _pipeline_severity_distribution(), "xdr_events"

    # Today
    if re.search(r"\btoday\b", q):
        return "today", _pipeline_today(), "xdr_events"

    # Yesterday / last 24 hours
    if re.search(r"\byesterday\b|\blast\s+24\s+hours?\b", q):
        return "last_24h", _pipeline_last_24h(), "xdr_events"

    # Top hosts / most alerts
    if re.search(r"\btop\s+host|\bmost\s+alert|\bmost\s+active|\bhighest\s+alert", q):
        return "top_hosts", _pipeline_top_hosts(), "xdr_events"

    # Count / how many
    if re.search(r"\bhow\s+many\b|\bcount\b|\btotal\b", q):
        # Check if asking about total
        if re.search(r"\btotal\b.*\bevent|\bevent.*\btotal\b", q):
            return "total_count", _pipeline_total_count(), "xdr_events"
        return "count_by_type", _pipeline_count_by_event_type(), "xdr_events"

    # Specific host mentioned
    host_match = re.search(r"\b(pc-?\d+|server-?\d+|host-?\d+)\b", q, re.IGNORECASE)
    if host_match:
        host = host_match.group(0).upper()
        return "host_breakdown", _pipeline_host_event_breakdown(host), "xdr_events"

    # Default: count by event type
    return "count_by_type", _pipeline_count_by_event_type(), "xdr_events"


# ---------------------------------------------------------------------------
# Result formatter
# ---------------------------------------------------------------------------

def _format_aggregation_result(
    pipeline_name: str, results: list[dict[str, Any]]
) -> str:
    """Format aggregation results into a human-readable string."""
    if not results:
        return f"No results found for aggregation query: {pipeline_name}."

    label_map = {
        "count_by_type": ("Event Type", "Count"),
        "top_hosts": ("Host", "Alert Count"),
        "last_24h": ("Event Type (last 24h)", "Count"),
        "today": ("Event Type (today)", "Count"),
        "severity_distribution": ("Severity", "Count"),
        "total_count": ("Metric", "Value"),
        "host_breakdown": ("Host → Event Type", "Count"),
        "raw_pipeline": ("Result", "Value"),
    }
    col_a, col_b = label_map.get(pipeline_name, ("Key", "Value"))

    lines = [f"=== Aggregation: {pipeline_name.replace('_', ' ').title()} ===\n"]
    lines.append(f"{'#':<4} {col_a:<35} {col_b}\n")
    lines.append("-" * 60 + "\n")

    for i, row in enumerate(results[:50], 1):
        # Try to build a human-readable row
        if pipeline_name == "host_breakdown":
            key = f"{row.get('host', '?')} → {row.get('event_type', '?')}"
            val = row.get("count", "?")
        elif pipeline_name == "total_count":
            key = "Total Events"
            val = row.get("total_events", "?")
        else:
            # Generic: take the first non-count key as the label
            non_count_keys = [k for k in row if k != "count"]
            key = row.get(non_count_keys[0], "?") if non_count_keys else "?"
            val = row.get("count", row.get("total_events", str(row)))

        lines.append(f"{i:<4} {str(key):<35} {val}\n")

    return "".join(lines)


# ---------------------------------------------------------------------------
# Public tool function
# ---------------------------------------------------------------------------

def mongodb_aggregation(query: str) -> str:
    """
    Run a MongoDB aggregation pipeline based on a natural language query.

    Supports:
      - "how many" / "count" → count events by event_type
      - "top host" / "most alerts" → rank hosts by alert count
      - "yesterday" / "last 24 hours" → recent activity
      - "severity" → severity distribution
      - "today" → today's events
      - Raw JSON pipeline string → executed directly

    Args:
        query: Natural language query or raw JSON pipeline string.

    Returns:
        Formatted string with aggregation results.
    """
    try:
        pipeline_name, pipeline, collection_name = _detect_pipeline(query)

        log.info(
            "Running aggregation pipeline '%s' on collection '%s'.",
            pipeline_name,
            collection_name,
        )

        if collection_name == "xdr_events":
            col = _get_events_collection()
        else:
            col = _get_summaries_collection()

        results = list(col.aggregate(pipeline))
        return _format_aggregation_result(pipeline_name, results)

    except PyMongoError as exc:
        log.error("MongoDB aggregation error: %s", exc)
        return f"[Aggregation Error] MongoDB error: {exc}"
    except Exception as exc:  # noqa: BLE001
        log.error("Aggregation tool error: %s", exc)
        return f"[Aggregation Error] {exc}"
