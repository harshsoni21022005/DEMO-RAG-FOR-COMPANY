"""
workers/summarization_worker.py

Summarization Worker for the XDR RAG Pipeline.

Runs in a continuous loop every SUMMARIZATION_INTERVAL seconds.
Groups raw xdr_events documents into 5-minute time-window summaries
per (host, event_type) pair and upserts them into xdr_summaries.

Supports dynamic event schemas — any unknown fields are collected
automatically into dynamic_metadata without code changes.

Detects security-specific optional fields if present:
  mitre_technique, process_name, username, container_name, device_name
"""

import asyncio
import logging
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from math import floor
from typing import Any

import motor.motor_asyncio
from dotenv import load_dotenv
from pymongo import UpdateOne
from pymongo.errors import BulkWriteError, PyMongoError

load_dotenv()

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] summarization_worker — %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
MONGODB_URI: str = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
MONGODB_DB: str = os.getenv("MONGODB_DB", "xdr_db")
SUMMARIZATION_INTERVAL: int = int(os.getenv("SUMMARIZATION_INTERVAL", "60"))
WINDOW_SECONDS: int = 300  # 5-minute windows

# Known XDR event fields that get explicit handling
KNOWN_FIELDS: frozenset[str] = frozenset(
    {
        "_id",
        "host",
        "event_type",
        "severity",
        "source_ip",
        "dest_ip",
        "signature",
        "timestamp",
        "kafka_topic",
        "kafka_offset",
        "payload",
    }
)

# Optional security fields — collected into dedicated summary fields if present
SECURITY_FIELDS: dict[str, str] = {
    "mitre_technique": "mitre_techniques",
    "process_name": "process_names",
    "username": "usernames",
    "container_name": "container_names",
    "device_name": "device_names",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def floor_to_window(ts: datetime, window_seconds: int = WINDOW_SECONDS) -> datetime:
    """Floor a datetime to the nearest N-second boundary (UTC)."""
    epoch = ts.replace(tzinfo=timezone.utc).timestamp()
    floored = floor(epoch / window_seconds) * window_seconds
    return datetime.fromtimestamp(floored, tz=timezone.utc)


def build_summary_text(
    host: str,
    event_type: str,
    event_count: int,
    window_start: datetime,
    window_end: datetime,
    severity_distribution: dict[str, int],
    top_signatures: list[str],
    source_ip_count: int,
    destination_ip_count: int,
    dynamic_metadata: dict[str, list[str]],
) -> str:
    """Produce a human-readable summary string for the xdr_summary document."""
    ws = window_start.strftime("%H:%M")
    we = window_end.strftime("%H:%M")

    sev_lines = "\n".join(
        f"  {k}: {v}" for k, v in sorted(severity_distribution.items(), key=lambda x: -x[1])
    )
    sig_lines = "\n".join(f"  {s}" for s in top_signatures[:5]) if top_signatures else "  (none)"

    meta_lines = (
        "\n".join(f"  {k}={', '.join(sorted(set(v)))}" for k, v in sorted(dynamic_metadata.items()) if v)
        if dynamic_metadata
        else "  (none)"
    )

    return (
        f"Host {host} generated {event_count} {event_type} events "
        f"between {ws} and {we}.\n\n"
        f"Severity Distribution:\n{sev_lines}\n\n"
        f"Top Signatures:\n{sig_lines}\n\n"
        f"Source IP Count:\n  {source_ip_count}\n\n"
        f"Destination IP Count:\n  {destination_ip_count}\n\n"
        f"Additional Metadata:\n{meta_lines}"
    )


def aggregate_events(events: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Reduce a list of raw event documents into a summary dict.

    Returns a flat dict suitable for building an xdr_summary document.
    """
    event_count = len(events)
    severity_counter: Counter = Counter()
    signature_counter: Counter = Counter()
    source_ips: set[str] = set()
    dest_ips: set[str] = set()
    timestamps: list[datetime] = []

    # Security-specific field accumulators
    security_accumulators: dict[str, list[str]] = {v: [] for v in SECURITY_FIELDS.values()}

    # Dynamic (unknown) field accumulator → {field: [value, ...]}
    dynamic_metadata: dict[str, list[str]] = defaultdict(list)

    for event in events:
        # Severity
        sev = str(event.get("severity", "unknown")).strip()
        severity_counter[sev] += 1

        # Signature
        sig = event.get("signature")
        if sig:
            signature_counter[str(sig)] += 1

        # IPs
        src = event.get("source_ip")
        dst = event.get("dest_ip")
        if src:
            source_ips.add(str(src))
        if dst:
            dest_ips.add(str(dst))

        # Timestamps
        ts = event.get("timestamp")
        if isinstance(ts, datetime):
            timestamps.append(ts)

        # Security-specific optional fields
        for raw_field, agg_field in SECURITY_FIELDS.items():
            val = event.get(raw_field)
            if val is not None:
                security_accumulators[agg_field].append(str(val))

        # Dynamic metadata: any field NOT in KNOWN_FIELDS and NOT a security field
        for field, value in event.items():
            if field not in KNOWN_FIELDS and field not in SECURITY_FIELDS:
                if value is not None:
                    dynamic_metadata[field].append(str(value))

    top_signatures = [sig for sig, _ in signature_counter.most_common(10)]
    severity_distribution = dict(severity_counter)

    first_ts = min(timestamps) if timestamps else None
    last_ts = max(timestamps) if timestamps else None

    # Deduplicate and limit dynamic metadata lists
    clean_dynamic: dict[str, list[str]] = {}
    for k, vals in dynamic_metadata.items():
        unique_vals = list(dict.fromkeys(vals))[:20]  # preserve order, cap at 20
        clean_dynamic[k] = unique_vals

    # Deduplicate security fields
    clean_security: dict[str, list[str]] = {}
    for agg_field, vals in security_accumulators.items():
        unique_vals = list(dict.fromkeys(vals))[:20]
        if unique_vals:
            clean_security[agg_field] = unique_vals

    return {
        "event_count": event_count,
        "severity_distribution": severity_distribution,
        "top_signatures": top_signatures,
        "source_ip_count": len(source_ips),
        "destination_ip_count": len(dest_ips),
        "first_event_ts": first_ts,
        "last_event_ts": last_ts,
        "dynamic_metadata": clean_dynamic,
        **clean_security,
    }


# ---------------------------------------------------------------------------
# Core Worker
# ---------------------------------------------------------------------------

class SummarizationWorker:
    """
    Continuously reads xdr_events, groups them into 5-minute windows,
    and upserts xdr_summaries documents.
    """

    def __init__(self) -> None:
        self.client = motor.motor_asyncio.AsyncIOMotorClient(MONGODB_URI)
        self.db = self.client[MONGODB_DB]
        self.events_col = self.db["xdr_events"]
        self.summaries_col = self.db["xdr_summaries"]

    async def ensure_indexes(self) -> None:
        """Create indexes on xdr_summaries if they don't exist."""
        await self.summaries_col.create_index(
            [("host", 1), ("event_type", 1), ("window_start", 1)],
            unique=True,
            name="unique_host_type_window",
        )
        await self.summaries_col.create_index(
            [("embedding_status", 1)],
            name="idx_embedding_status",
        )
        await self.summaries_col.create_index(
            [("dirty", 1)],
            name="idx_dirty",
        )
        log.info("Indexes ensured on xdr_summaries.")

    async def fetch_events(self) -> list[dict[str, Any]]:
        """Fetch all events from xdr_events. In production this would be paginated."""
        cursor = self.events_col.find(
            {},
            projection={"_id": 0},  # _id not needed for grouping
        )
        return await cursor.to_list(length=None)

    def group_events(
        self, events: list[dict[str, Any]]
    ) -> dict[tuple[str, str, datetime], list[dict[str, Any]]]:
        """
        Group events by (host, event_type, window_start).

        Skips events missing required fields.
        """
        groups: dict[tuple[str, str, datetime], list[dict[str, Any]]] = defaultdict(list)

        for event in events:
            host = event.get("host")
            event_type = event.get("event_type")
            ts = event.get("timestamp")

            if not host or not event_type or not ts:
                continue

            if not isinstance(ts, datetime):
                # Try to parse ISO string timestamps
                try:
                    ts = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
                except (ValueError, TypeError):
                    log.warning("Skipping event with unparseable timestamp: %s", ts)
                    continue

            window_start = floor_to_window(ts)
            groups[(str(host), str(event_type), window_start)].append(event)

        return groups

    async def upsert_summaries(
        self, groups: dict[tuple[str, str, datetime], list[dict[str, Any]]]
    ) -> int:
        """Build and bulk-upsert summary documents. Returns count of upserted docs."""
        if not groups:
            return 0

        now = datetime.now(tz=timezone.utc)

        # Two-pass approach: first check which docs already exist (to set dirty flag),
        # then bulk-upsert with full document data.
        operations = await self._build_upsert_operations(groups, now)

        try:
            result = await self.summaries_col.bulk_write(operations, ordered=False)
            log.info(
                "Upserted %d summaries (inserted=%d, modified=%d)",
                len(operations),
                result.upserted_count,
                result.modified_count,
            )
            return result.upserted_count + result.modified_count
        except BulkWriteError as exc:
            log.error("Bulk write error: %s", exc.details)
            return 0

    async def _build_upsert_operations(
        self,
        groups: dict[tuple[str, str, datetime], list[dict[str, Any]]],
        now: datetime,
    ) -> list[UpdateOne]:
        """
        Build UpdateOne operations per group.
        Checks if each doc exists first to set dirty flag appropriately.
        """
        operations = []

        # Batch-fetch existing document status
        filter_keys = [
            {"host": h, "event_type": et, "window_start": ws}
            for (h, et, ws) in groups.keys()
        ]
        existing_docs: set[tuple[str, str, datetime]] = set()
        if filter_keys:
            cursor = self.summaries_col.find(
                {"$or": filter_keys},
                projection={"host": 1, "event_type": 1, "window_start": 1},
            )
            async for doc in cursor:
                existing_docs.add(
                    (doc["host"], doc["event_type"], doc["window_start"])
                )

        for (host, event_type, window_start), events in groups.items():
            window_end = datetime.fromtimestamp(
                window_start.timestamp() + WINDOW_SECONDS, tz=timezone.utc
            )
            is_existing = (host, event_type, window_start) in existing_docs
            agg = aggregate_events(events)
            summary_text = build_summary_text(
                host=host,
                event_type=event_type,
                event_count=agg["event_count"],
                window_start=window_start,
                window_end=window_end,
                severity_distribution=agg["severity_distribution"],
                top_signatures=agg["top_signatures"],
                source_ip_count=agg["source_ip_count"],
                destination_ip_count=agg["destination_ip_count"],
                dynamic_metadata=agg["dynamic_metadata"],
            )

            optional_security: dict[str, Any] = {}
            for sec_field in SECURITY_FIELDS.values():
                if sec_field in agg:
                    optional_security[sec_field] = agg[sec_field]

            event_sequence: list[str] = []
            if agg.get("first_event_ts") and agg.get("last_event_ts"):
                event_sequence = [
                    agg["first_event_ts"].isoformat(),
                    agg["last_event_ts"].isoformat(),
                ]

            update_fields: dict[str, Any] = {
                "event_count": agg["event_count"],
                "severity_distribution": agg["severity_distribution"],
                "top_signatures": agg["top_signatures"],
                "source_ip_count": agg["source_ip_count"],
                "destination_ip_count": agg["destination_ip_count"],
                "dynamic_metadata": agg["dynamic_metadata"],
                "summary_text": summary_text,
                "updated_at": now,
                "dirty": is_existing,
                "embedding_status": "pending",  # always reset so embedding refreshes
                **optional_security,
            }
            if event_sequence:
                update_fields["event_sequence"] = event_sequence

            set_on_insert: dict[str, Any] = {
                "host": host,
                "event_type": event_type,
                "window_start": window_start,
                "window_end": window_end,
                "created_at": now,
                "embedding": None,
            }

            operations.append(
                UpdateOne(
                    filter={"host": host, "event_type": event_type, "window_start": window_start},
                    update={
                        "$set": update_fields,
                        "$setOnInsert": set_on_insert,
                    },
                    upsert=True,
                )
            )

        return operations

    async def run_once(self) -> None:
        """Execute one summarization cycle."""
        log.info("Starting summarization cycle...")
        try:
            events = await self.fetch_events()
            log.info("Fetched %d raw events.", len(events))

            if not events:
                log.info("No events to process.")
                return

            groups = self.group_events(events)
            log.info("Grouped into %d (host, event_type, window) buckets.", len(groups))

            upserted = await self.upsert_summaries(groups)
            log.info("Cycle complete. %d summaries processed.", upserted)

        except PyMongoError as exc:
            log.error("MongoDB error during summarization cycle: %s", exc)
        except Exception as exc:  # noqa: BLE001
            log.exception("Unexpected error during summarization cycle: %s", exc)

    async def run(self) -> None:
        """Main loop — runs indefinitely with SUMMARIZATION_INTERVAL sleep."""
        log.info(
            "Summarization worker starting. Interval=%ds, Window=%ds",
            SUMMARIZATION_INTERVAL,
            WINDOW_SECONDS,
        )
        await self.ensure_indexes()

        while True:
            await self.run_once()
            log.info("Sleeping %d seconds until next cycle...", SUMMARIZATION_INTERVAL)
            await asyncio.sleep(SUMMARIZATION_INTERVAL)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    worker = SummarizationWorker()
    try:
        asyncio.run(worker.run())
    except KeyboardInterrupt:
        log.info("Summarization worker stopped by user.")
