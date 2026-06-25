"""
tests/test_summarization.py

Unit tests for the summarization worker logic.

Tests the pure Python functions (no MongoDB required):
  - floor_to_window
  - aggregate_events
  - build_summary_text
  - group_events (via SummarizationWorker)
"""

import pytest
from collections import Counter
from datetime import datetime, timezone

# We test the pure functions directly — no DB connection needed
from workers.summarization_worker import (
    WINDOW_SECONDS,
    aggregate_events,
    build_summary_text,
    floor_to_window,
    SummarizationWorker,
)


# ---------------------------------------------------------------------------
# Tests: floor_to_window
# ---------------------------------------------------------------------------

class TestFloorToWindow:
    def test_already_on_boundary(self):
        """A timestamp exactly on a 5-minute boundary should be unchanged."""
        ts = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        result = floor_to_window(ts)
        assert result == ts

    def test_floors_to_nearest_window(self):
        """3 minutes into a window should floor to the window start."""
        ts = datetime(2024, 1, 15, 10, 3, 47, tzinfo=timezone.utc)
        result = floor_to_window(ts)
        expected = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        assert result == expected

    def test_last_second_floors_to_window(self):
        """4:59 into a window should still floor to the window start."""
        ts = datetime(2024, 1, 15, 10, 4, 59, tzinfo=timezone.utc)
        result = floor_to_window(ts)
        expected = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        assert result == expected

    def test_next_window_boundary(self):
        """Exactly 5 minutes should be the next window start."""
        ts = datetime(2024, 1, 15, 10, 5, 0, tzinfo=timezone.utc)
        result = floor_to_window(ts)
        assert result == ts

    def test_returns_utc(self):
        """Result should always be in UTC."""
        ts = datetime(2024, 6, 1, 12, 2, 30, tzinfo=timezone.utc)
        result = floor_to_window(ts)
        assert result.tzinfo is not None

    def test_window_duration(self):
        """Consecutive windows should be exactly WINDOW_SECONDS apart."""
        ts1 = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        ts2 = datetime(2024, 1, 15, 10, 5, 0, tzinfo=timezone.utc)
        w1 = floor_to_window(ts1)
        w2 = floor_to_window(ts2)
        assert (w2 - w1).total_seconds() == WINDOW_SECONDS


# ---------------------------------------------------------------------------
# Tests: aggregate_events
# ---------------------------------------------------------------------------

def _make_event(
    severity="high",
    signature="ET TEST",
    source_ip="10.0.0.1",
    dest_ip="1.2.3.4",
    timestamp=None,
    **extra,
):
    ts = timestamp or datetime(2024, 1, 15, 10, 1, 0, tzinfo=timezone.utc)
    return {
        "host": "PC-101",
        "event_type": "Malware",
        "severity": severity,
        "source_ip": source_ip,
        "dest_ip": dest_ip,
        "signature": signature,
        "timestamp": ts,
        **extra,
    }


class TestAggregateEvents:
    def test_event_count(self):
        events = [_make_event() for _ in range(10)]
        result = aggregate_events(events)
        assert result["event_count"] == 10

    def test_severity_distribution(self):
        events = (
            [_make_event(severity="high")] * 5
            + [_make_event(severity="medium")] * 3
            + [_make_event(severity="low")] * 2
        )
        result = aggregate_events(events)
        assert result["severity_distribution"]["high"] == 5
        assert result["severity_distribution"]["medium"] == 3
        assert result["severity_distribution"]["low"] == 2

    def test_unique_source_ips(self):
        events = [
            _make_event(source_ip="10.0.0.1"),
            _make_event(source_ip="10.0.0.2"),
            _make_event(source_ip="10.0.0.1"),  # duplicate
        ]
        result = aggregate_events(events)
        assert result["source_ip_count"] == 2

    def test_unique_dest_ips(self):
        events = [
            _make_event(dest_ip="1.1.1.1"),
            _make_event(dest_ip="2.2.2.2"),
            _make_event(dest_ip="3.3.3.3"),
        ]
        result = aggregate_events(events)
        assert result["destination_ip_count"] == 3

    def test_top_signatures_ordered(self):
        events = (
            [_make_event(signature="SIG_A")] * 5
            + [_make_event(signature="SIG_B")] * 3
            + [_make_event(signature="SIG_C")] * 1
        )
        result = aggregate_events(events)
        assert result["top_signatures"][0] == "SIG_A"
        assert result["top_signatures"][1] == "SIG_B"

    def test_dynamic_metadata_captured(self):
        """Unknown fields should appear in dynamic_metadata."""
        events = [
            _make_event(custom_field="value_a"),
            _make_event(custom_field="value_b"),
            _make_event(another_field="xyz"),
        ]
        result = aggregate_events(events)
        assert "custom_field" in result["dynamic_metadata"]
        assert "another_field" in result["dynamic_metadata"]

    def test_known_fields_not_in_metadata(self):
        """Known fields like host, severity should NOT appear in dynamic_metadata."""
        events = [_make_event()]
        result = aggregate_events(events)
        assert "host" not in result["dynamic_metadata"]
        assert "severity" not in result["dynamic_metadata"]
        assert "source_ip" not in result["dynamic_metadata"]

    def test_security_fields_aggregated(self):
        """Security-specific fields should go into dedicated summary fields."""
        events = [
            _make_event(mitre_technique="T1055"),
            _make_event(mitre_technique="T1027"),
            _make_event(process_name="powershell.exe"),
            _make_event(username="admin"),
        ]
        result = aggregate_events(events)
        assert "mitre_techniques" in result
        assert "T1055" in result["mitre_techniques"]
        assert "T1027" in result["mitre_techniques"]
        assert "process_names" in result
        assert "usernames" in result

    def test_security_fields_deduplicated(self):
        """Duplicate security field values should appear only once."""
        events = [_make_event(mitre_technique="T1055")] * 5
        result = aggregate_events(events)
        assert result["mitre_techniques"].count("T1055") == 1

    def test_timestamp_range(self):
        """first_event_ts and last_event_ts should be the min and max timestamps."""
        ts1 = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        ts2 = datetime(2024, 1, 15, 10, 4, 0, tzinfo=timezone.utc)
        events = [_make_event(timestamp=ts2), _make_event(timestamp=ts1)]
        result = aggregate_events(events)
        assert result["first_event_ts"] == ts1
        assert result["last_event_ts"] == ts2

    def test_empty_events(self):
        """Empty event list should produce zero counts."""
        result = aggregate_events([])
        assert result["event_count"] == 0
        assert result["source_ip_count"] == 0
        assert result["destination_ip_count"] == 0

    def test_missing_optional_fields(self):
        """Events without optional fields should not crash."""
        events = [
            {"host": "PC-101", "event_type": "Malware", "severity": "high"}
        ]
        result = aggregate_events(events)
        assert result["event_count"] == 1
        assert result["source_ip_count"] == 0


# ---------------------------------------------------------------------------
# Tests: build_summary_text
# ---------------------------------------------------------------------------

class TestBuildSummaryText:
    def test_contains_host_and_type(self):
        text = build_summary_text(
            host="PC-101",
            event_type="Malware",
            event_count=30,
            window_start=datetime(2024, 1, 15, 10, 0, tzinfo=timezone.utc),
            window_end=datetime(2024, 1, 15, 10, 5, tzinfo=timezone.utc),
            severity_distribution={"high": 20, "medium": 8, "low": 2},
            top_signatures=["ET MALWARE CnC Beacon", "ET Trojan Downloader"],
            source_ip_count=5,
            destination_ip_count=12,
            dynamic_metadata={"process_name": ["powershell.exe"]},
        )
        assert "PC-101" in text
        assert "Malware" in text
        assert "30" in text
        assert "10:00" in text
        assert "10:05" in text

    def test_severity_distribution_in_text(self):
        text = build_summary_text(
            host="PC-102",
            event_type="Scan",
            event_count=10,
            window_start=datetime(2024, 1, 15, 10, 0, tzinfo=timezone.utc),
            window_end=datetime(2024, 1, 15, 10, 5, tzinfo=timezone.utc),
            severity_distribution={"high": 5, "low": 5},
            top_signatures=[],
            source_ip_count=2,
            destination_ip_count=3,
            dynamic_metadata={},
        )
        assert "high: 5" in text.lower() or "High: 5" in text

    def test_dynamic_metadata_shown(self):
        text = build_summary_text(
            host="PC-103",
            event_type="Exfil",
            event_count=5,
            window_start=datetime(2024, 1, 15, 10, 0, tzinfo=timezone.utc),
            window_end=datetime(2024, 1, 15, 10, 5, tzinfo=timezone.utc),
            severity_distribution={"medium": 5},
            top_signatures=["ET EXFIL DNS Tunneling"],
            source_ip_count=1,
            destination_ip_count=1,
            dynamic_metadata={"custom_tag": ["value1", "value2"]},
        )
        assert "custom_tag" in text


# ---------------------------------------------------------------------------
# Tests: SummarizationWorker.group_events (no DB)
# ---------------------------------------------------------------------------

class TestGroupEvents:
    def setup_method(self):
        # Patch MONGODB_URI to avoid actual connection
        import unittest.mock as mock
        with mock.patch("workers.summarization_worker.motor.motor_asyncio.AsyncIOMotorClient"):
            self.worker = SummarizationWorker.__new__(SummarizationWorker)

    def test_groups_by_host_and_type(self):
        ts = datetime(2024, 1, 15, 10, 2, 0, tzinfo=timezone.utc)
        events = [
            {"host": "PC-101", "event_type": "Malware", "timestamp": ts},
            {"host": "PC-101", "event_type": "Malware", "timestamp": ts},
            {"host": "PC-102", "event_type": "Scan", "timestamp": ts},
        ]
        groups = SummarizationWorker.group_events(self.worker, events)
        # Should have 2 groups
        assert len(groups) == 2
        # PC-101/Malware group has 2 events
        mal_key = [k for k in groups if k[0] == "PC-101" and k[1] == "Malware"][0]
        assert len(groups[mal_key]) == 2

    def test_skips_events_without_required_fields(self):
        events = [
            {"host": "PC-101", "timestamp": datetime(2024, 1, 15, 10, 0, tzinfo=timezone.utc)},
            # Missing event_type
            {"event_type": "Malware", "timestamp": datetime(2024, 1, 15, 10, 0, tzinfo=timezone.utc)},
            # Missing host
        ]
        groups = SummarizationWorker.group_events(self.worker, events)
        assert len(groups) == 0

    def test_different_windows_create_different_groups(self):
        """Events 10 minutes apart should be in different 5-min windows."""
        ts1 = datetime(2024, 1, 15, 10, 1, 0, tzinfo=timezone.utc)  # window: 10:00
        ts2 = datetime(2024, 1, 15, 10, 7, 0, tzinfo=timezone.utc)  # window: 10:05
        events = [
            {"host": "PC-101", "event_type": "Malware", "timestamp": ts1},
            {"host": "PC-101", "event_type": "Malware", "timestamp": ts2},
        ]
        groups = SummarizationWorker.group_events(self.worker, events)
        assert len(groups) == 2

    def test_same_window_groups_together(self):
        """Events within the same 5-min window should be in the same group."""
        ts1 = datetime(2024, 1, 15, 10, 0, 30, tzinfo=timezone.utc)
        ts2 = datetime(2024, 1, 15, 10, 4, 59, tzinfo=timezone.utc)
        events = [
            {"host": "PC-101", "event_type": "Malware", "timestamp": ts1},
            {"host": "PC-101", "event_type": "Malware", "timestamp": ts2},
        ]
        groups = SummarizationWorker.group_events(self.worker, events)
        assert len(groups) == 1
