"""
pipeline/tools/elasticsearch_tool.py

Elasticsearch Full-Text Search Tool for the XDR RAG Pipeline.

Performs multi_match queries across key XDR event fields:
  - source_ip, dest_ip, signature, host, event_type

Creates the xdr_logs index with proper mappings on first run if missing.
Returns the top-5 hits formatted as a readable string.
"""

import logging
import os
from typing import Any, Optional

from dotenv import load_dotenv
from elasticsearch import Elasticsearch, NotFoundError
from elasticsearch.exceptions import ConnectionError as ESConnectionError
from elasticsearch.exceptions import TransportError

load_dotenv()

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
ELASTICSEARCH_URL: str = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")
ELASTICSEARCH_USERNAME: Optional[str] = os.getenv("ELASTICSEARCH_USERNAME") or None
ELASTICSEARCH_PASSWORD: Optional[str] = os.getenv("ELASTICSEARCH_PASSWORD") or None
ELASTICSEARCH_INDEX: str = os.getenv("ELASTICSEARCH_INDEX", "xdr_logs")

# Fields to search across
SEARCH_FIELDS: list[str] = [
    "source_ip",
    "dest_ip",
    "signature",
    "host",
    "event_type",
    "payload",
    "username",
    "process_name",
    "mitre_technique",
    "container_name",
    "device_name",
]

# Index mappings — optimized for exact match and full-text search on XDR fields
INDEX_MAPPINGS: dict[str, Any] = {
    "mappings": {
        "properties": {
            "host": {"type": "keyword"},
            "event_type": {"type": "keyword"},
            "severity": {"type": "keyword"},
            "source_ip": {"type": "ip"},
            "dest_ip": {"type": "ip"},
            "signature": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
            "timestamp": {"type": "date"},
            "kafka_topic": {"type": "keyword"},
            "kafka_offset": {"type": "long"},
            "payload": {"type": "text"},
            "username": {"type": "keyword"},
            "process_name": {"type": "keyword"},
            "mitre_technique": {"type": "keyword"},
            "container_name": {"type": "keyword"},
            "device_name": {"type": "keyword"},
        }
    },
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
        "refresh_interval": "5s",
    },
}


# ---------------------------------------------------------------------------
# Lazy-initialized singleton
# ---------------------------------------------------------------------------
_es_client: Optional[Elasticsearch] = None
_index_ensured: bool = False


def _get_client() -> Elasticsearch:
    global _es_client
    if _es_client is None:
        kwargs: dict[str, Any] = {"hosts": [ELASTICSEARCH_URL]}
        if ELASTICSEARCH_USERNAME and ELASTICSEARCH_PASSWORD:
            kwargs["basic_auth"] = (ELASTICSEARCH_USERNAME, ELASTICSEARCH_PASSWORD)
        _es_client = Elasticsearch(**kwargs)
        log.info("Elasticsearch client initialized: %s", ELASTICSEARCH_URL)
    return _es_client


def _ensure_index() -> None:
    """Create the xdr_logs index with mappings if it doesn't already exist."""
    global _index_ensured
    if _index_ensured:
        return

    client = _get_client()
    try:
        if not client.indices.exists(index=ELASTICSEARCH_INDEX):
            client.indices.create(
                index=ELASTICSEARCH_INDEX,
                mappings=INDEX_MAPPINGS["mappings"],
                settings=INDEX_MAPPINGS["settings"],
            )
            log.info("Created Elasticsearch index '%s'.", ELASTICSEARCH_INDEX)
        else:
            log.debug("Elasticsearch index '%s' already exists.", ELASTICSEARCH_INDEX)
        _index_ensured = True
    except ESConnectionError as exc:
        log.error("Cannot connect to Elasticsearch at %s: %s", ELASTICSEARCH_URL, exc)
    except TransportError as exc:
        log.error("Elasticsearch transport error creating index: %s", exc)


# ---------------------------------------------------------------------------
# Result formatter
# ---------------------------------------------------------------------------

def _format_hits(hits: list[dict[str, Any]]) -> str:
    """Format Elasticsearch hits into a readable string."""
    if not hits:
        return "No results found in Elasticsearch."

    lines = ["=== Elasticsearch Full-Text Search Results ===\n"]
    for i, hit in enumerate(hits, 1):
        src = hit.get("_source", {})
        score = hit.get("_score", 0)
        lines.append(
            f"[{i}] Score: {score:.3f} | "
            f"Host: {src.get('host', 'N/A')} | "
            f"Type: {src.get('event_type', 'N/A')} | "
            f"Severity: {src.get('severity', 'N/A')}\n"
        )
        lines.append(
            f"    Source IP: {src.get('source_ip', 'N/A')} → "
            f"Dest IP: {src.get('dest_ip', 'N/A')}\n"
        )
        sig = src.get("signature", "N/A")
        lines.append(f"    Signature: {sig}\n")
        ts = src.get("timestamp", "N/A")
        lines.append(f"    Timestamp: {ts}\n")

        # Optional fields
        optionals = {}
        for field in ["username", "process_name", "mitre_technique", "container_name"]:
            val = src.get(field)
            if val:
                optionals[field] = val
        if optionals:
            lines.append(
                "    " + " | ".join(f"{k}={v}" for k, v in optionals.items()) + "\n"
            )

        lines.append("-" * 60 + "\n")

    return "".join(lines)


# ---------------------------------------------------------------------------
# Public tool function
# ---------------------------------------------------------------------------

def elasticsearch_search(query: str, size: int = 5) -> str:
    """
    Perform a full-text multi_match search across XDR event fields in Elasticsearch.

    Useful for:
      - Exact IP address lookups (source_ip / dest_ip)
      - Specific signature / IOC searches
      - Process name / username lookups
      - Hash, domain, or file name searches
      - MITRE technique lookups

    Args:
        query: Search string (IP, signature, domain, hash, username, etc.).
        size:  Number of results to return (default 5).

    Returns:
        Formatted string with matching XDR event hits.
    """
    try:
        _ensure_index()
        client = _get_client()

        log.info("Elasticsearch search | query='%s' | size=%d", query[:80], size)

        es_query: dict[str, Any] = {
            "query": {
                "bool": {
                    "should": [
                        # High-boost exact match on keyword sub-fields
                        {
                            "multi_match": {
                                "query": query,
                                "fields": [
                                    "host^3",
                                    "event_type^2",
                                    "source_ip^3",
                                    "dest_ip^3",
                                    "signature^4",
                                    "username^2",
                                    "process_name^2",
                                    "mitre_technique^2",
                                    "container_name",
                                    "device_name",
                                ],
                                "type": "best_fields",
                                "operator": "or",
                                "fuzziness": "AUTO",
                            }
                        },
                        # Full-text match on payload/signature text
                        {
                            "multi_match": {
                                "query": query,
                                "fields": ["signature", "payload"],
                                "type": "phrase_prefix",
                                "boost": 1.5,
                            }
                        },
                    ],
                    "minimum_should_match": 1,
                }
            },
            "size": size,
            "sort": [{"_score": {"order": "desc"}}],
        }

        response = client.search(index=ELASTICSEARCH_INDEX, query=es_query["query"], size=size, sort=es_query["sort"])
        hits = response["hits"]["hits"]
        total = response["hits"]["total"]["value"]
        log.info("Elasticsearch returned %d hits (total=%d).", len(hits), total)

        result = _format_hits(hits)
        return result + f"\nTotal matching documents: {total}\n"

    except ESConnectionError as exc:
        log.error("Elasticsearch connection error: %s", exc)
        return f"[Elasticsearch Error] Cannot connect to {ELASTICSEARCH_URL}: {exc}"
    except NotFoundError as exc:
        log.error("Elasticsearch index not found: %s", exc)
        return f"[Elasticsearch Error] Index '{ELASTICSEARCH_INDEX}' not found: {exc}"
    except TransportError as exc:
        log.error("Elasticsearch transport error: %s", exc)
        return f"[Elasticsearch Error] Transport error: {exc}"
    except Exception as exc:  # noqa: BLE001
        log.error("Elasticsearch search error: %s", exc)
        return f"[Elasticsearch Error] {exc}"
