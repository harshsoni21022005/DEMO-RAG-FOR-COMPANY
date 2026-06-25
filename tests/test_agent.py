"""
tests/test_agent.py

Unit tests for the LangGraph agent and pipeline tools.

Tests:
  - Aggregation tool keyword matching
  - Aggregation result formatting
  - Elasticsearch tool result formatting
  - RAG tool pre-filter builder
  - Agent tool selection logic (mocked LLM)
"""

import pytest
import unittest.mock as mock
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Tests: aggregation_tool keyword matching
# ---------------------------------------------------------------------------

class TestAggregationToolKeywordMatching:
    """Test that the keyword matcher selects the correct pipeline."""

    def test_how_many_maps_to_count(self):
        from pipeline.tools.aggregation_tool import _detect_pipeline
        name, pipeline, col = _detect_pipeline("how many events are there?")
        assert name in ("count_by_type", "total_count")

    def test_count_maps_to_count(self):
        from pipeline.tools.aggregation_tool import _detect_pipeline
        name, pipeline, col = _detect_pipeline("count events by type")
        assert "count" in name

    def test_top_host_maps_to_top_hosts(self):
        from pipeline.tools.aggregation_tool import _detect_pipeline
        name, pipeline, col = _detect_pipeline("show me the top host by alerts")
        assert name == "top_hosts"

    def test_most_alerts_maps_to_top_hosts(self):
        from pipeline.tools.aggregation_tool import _detect_pipeline
        name, pipeline, col = _detect_pipeline("which host has the most alerts?")
        assert name == "top_hosts"

    def test_yesterday_maps_to_last_24h(self):
        from pipeline.tools.aggregation_tool import _detect_pipeline
        name, pipeline, col = _detect_pipeline("events from yesterday")
        assert name == "last_24h"

    def test_last_24_hours_maps_to_last_24h(self):
        from pipeline.tools.aggregation_tool import _detect_pipeline
        name, pipeline, col = _detect_pipeline("show me events from the last 24 hours")
        assert name == "last_24h"

    def test_severity_maps_to_severity(self):
        from pipeline.tools.aggregation_tool import _detect_pipeline
        name, pipeline, col = _detect_pipeline("what is the severity distribution?")
        assert name == "severity_distribution"

    def test_today_maps_to_today(self):
        from pipeline.tools.aggregation_tool import _detect_pipeline
        name, pipeline, col = _detect_pipeline("how many alerts today?")
        assert name == "today"

    def test_raw_json_pipeline(self):
        from pipeline.tools.aggregation_tool import _detect_pipeline
        raw = '[{"$count": "total"}]'
        name, pipeline, col = _detect_pipeline(raw)
        assert name == "raw_pipeline"
        assert isinstance(pipeline, list)

    def test_default_falls_back_to_count_by_type(self):
        from pipeline.tools.aggregation_tool import _detect_pipeline
        name, pipeline, col = _detect_pipeline("tell me about events")
        assert name == "count_by_type"


# ---------------------------------------------------------------------------
# Tests: aggregation result formatting
# ---------------------------------------------------------------------------

class TestAggregationFormatting:
    def test_formats_count_by_type(self):
        from pipeline.tools.aggregation_tool import _format_aggregation_result
        results = [
            {"event_type": "Malware", "count": 50},
            {"event_type": "Scan", "count": 30},
        ]
        output = _format_aggregation_result("count_by_type", results)
        assert "Malware" in output
        assert "50" in output
        assert "Scan" in output

    def test_formats_top_hosts(self):
        from pipeline.tools.aggregation_tool import _format_aggregation_result
        results = [
            {"host": "PC-101", "count": 100},
            {"host": "PC-102", "count": 75},
        ]
        output = _format_aggregation_result("top_hosts", results)
        assert "PC-101" in output
        assert "100" in output

    def test_empty_results_message(self):
        from pipeline.tools.aggregation_tool import _format_aggregation_result
        output = _format_aggregation_result("count_by_type", [])
        assert "No results" in output

    def test_formats_severity_distribution(self):
        from pipeline.tools.aggregation_tool import _format_aggregation_result
        results = [
            {"severity": "high", "count": 200},
            {"severity": "medium", "count": 150},
            {"severity": "low", "count": 50},
        ]
        output = _format_aggregation_result("severity_distribution", results)
        assert "high" in output.lower()
        assert "200" in output


# ---------------------------------------------------------------------------
# Tests: aggregation tool with mocked MongoDB
# ---------------------------------------------------------------------------

class TestAggregationToolWithMock:
    def test_returns_formatted_string(self):
        from pipeline.tools.aggregation_tool import mongodb_aggregation

        mock_results = [{"event_type": "Malware", "count": 42}]
        with patch("pipeline.tools.aggregation_tool._get_events_collection") as mock_get_col:
            mock_col = MagicMock()
            mock_col.aggregate.return_value = iter(mock_results)
            mock_get_col.return_value = mock_col

            result = mongodb_aggregation("how many events by type")

        assert isinstance(result, str)
        assert "Malware" in result or "42" in result

    def test_returns_error_string_on_exception(self):
        from pipeline.tools.aggregation_tool import mongodb_aggregation

        with patch("pipeline.tools.aggregation_tool._get_events_collection") as mock_get_col:
            mock_col = MagicMock()
            mock_col.aggregate.side_effect = Exception("DB connection failed")
            mock_get_col.return_value = mock_col

            result = mongodb_aggregation("count events")

        assert "[Aggregation Error]" in result
        assert "DB connection failed" in result


# ---------------------------------------------------------------------------
# Tests: RAG tool pre-filter builder
# ---------------------------------------------------------------------------

class TestRagPrefilter:
    def test_empty_filter_when_no_args(self):
        from pipeline.tools.rag_tool import _build_prefilter
        # Always includes embedding_status filter
        result = _build_prefilter()
        # Should at minimum contain the embedding_status filter
        assert result  # Not empty

    def test_host_filter_added(self):
        from pipeline.tools.rag_tool import _build_prefilter
        result = _build_prefilter(host="PC-101")
        result_str = str(result)
        assert "PC-101" in result_str

    def test_event_type_filter_added(self):
        from pipeline.tools.rag_tool import _build_prefilter
        result = _build_prefilter(event_type="Malware")
        result_str = str(result)
        assert "Malware" in result_str

    def test_timestamp_filter_added(self):
        from pipeline.tools.rag_tool import _build_prefilter
        result = _build_prefilter(after="2024-01-15T10:00:00+00:00")
        result_str = str(result)
        assert "window_start" in result_str

    def test_invalid_timestamp_ignored(self):
        from pipeline.tools.rag_tool import _build_prefilter
        # Should not raise — just skips invalid timestamps
        result = _build_prefilter(after="not-a-date")
        assert result is not None

    def test_multiple_filters_combined_with_and(self):
        from pipeline.tools.rag_tool import _build_prefilter
        result = _build_prefilter(host="PC-101", event_type="Malware")
        # Should have $and with multiple conditions
        result_str = str(result)
        assert "PC-101" in result_str
        assert "Malware" in result_str


# ---------------------------------------------------------------------------
# Tests: RAG tool with mocked vector store
# ---------------------------------------------------------------------------

class TestRagToolWithMock:
    def test_returns_formatted_string_on_success(self):
        from pipeline.tools.rag_tool import rag_search

        mock_doc = MagicMock()
        mock_doc.metadata = {
            "host": "PC-101",
            "event_type": "Malware",
            "window_start": "2024-01-15T10:00:00",
            "window_end": "2024-01-15T10:05:00",
        }
        mock_doc.page_content = "Host PC-101 generated 30 Malware events..."

        with patch("pipeline.tools.rag_tool._get_vector_store") as mock_vs:
            mock_store = MagicMock()
            mock_store.similarity_search.return_value = [mock_doc]
            mock_vs.return_value = mock_store

            result = rag_search(query="malware on PC-101", host="PC-101")

        assert "PC-101" in result
        assert "RAG Search Results" in result

    def test_returns_error_string_on_exception(self):
        from pipeline.tools.rag_tool import rag_search

        with patch("pipeline.tools.rag_tool._get_vector_store") as mock_vs:
            mock_vs.side_effect = Exception("Vector store connection failed")
            result = rag_search(query="test query")

        assert "[RAG Error]" in result

    def test_no_results_message(self):
        from pipeline.tools.rag_tool import rag_search, _format_results
        result = _format_results([])
        assert "No matching" in result


# ---------------------------------------------------------------------------
# Tests: Elasticsearch tool result formatter
# ---------------------------------------------------------------------------

class TestElasticsearchFormatter:
    def test_format_single_hit(self):
        from pipeline.tools.elasticsearch_tool import _format_hits
        hits = [
            {
                "_score": 1.5,
                "_source": {
                    "host": "PC-101",
                    "event_type": "Malware",
                    "severity": "high",
                    "source_ip": "10.0.0.1",
                    "dest_ip": "5.6.7.8",
                    "signature": "ET MALWARE CnC Beacon",
                    "timestamp": "2024-01-15T10:02:00+00:00",
                },
            }
        ]
        result = _format_hits(hits)
        assert "PC-101" in result
        assert "ET MALWARE CnC Beacon" in result
        assert "10.0.0.1" in result

    def test_format_empty_hits(self):
        from pipeline.tools.elasticsearch_tool import _format_hits
        result = _format_hits([])
        assert "No results" in result

    def test_format_optional_fields(self):
        from pipeline.tools.elasticsearch_tool import _format_hits
        hits = [
            {
                "_score": 1.0,
                "_source": {
                    "host": "PC-101",
                    "event_type": "LateralMovement",
                    "severity": "high",
                    "source_ip": "10.0.0.1",
                    "dest_ip": "10.0.0.2",
                    "signature": "ET POLICY PsExec",
                    "timestamp": "2024-01-15T10:02:00+00:00",
                    "process_name": "psexec.exe",
                    "username": "admin",
                    "mitre_technique": "T1021.002",
                },
            }
        ]
        result = _format_hits(hits)
        assert "psexec.exe" in result
        assert "admin" in result
        assert "T1021.002" in result


# ---------------------------------------------------------------------------
# Tests: Elasticsearch tool with mocked client
# ---------------------------------------------------------------------------

class TestElasticsearchToolWithMock:
    def test_returns_formatted_string_on_success(self):
        from pipeline.tools.elasticsearch_tool import elasticsearch_search

        mock_hit = {
            "_score": 2.0,
            "_source": {
                "host": "PC-101",
                "event_type": "Malware",
                "severity": "high",
                "source_ip": "10.0.0.50",
                "dest_ip": "8.8.8.8",
                "signature": "ET MALWARE Beacon",
                "timestamp": "2024-01-15T10:02:00+00:00",
            },
        }

        with (
            patch("pipeline.tools.elasticsearch_tool._get_client") as mock_client_fn,
            patch("pipeline.tools.elasticsearch_tool._ensure_index"),
        ):
            mock_es = MagicMock()
            mock_es.search.return_value = {
                "hits": {"hits": [mock_hit], "total": {"value": 1}}
            }
            mock_client_fn.return_value = mock_es

            result = elasticsearch_search("10.0.0.50")

        assert "10.0.0.50" in result
        assert "Elasticsearch" in result

    def test_returns_error_string_on_connection_failure(self):
        from pipeline.tools.elasticsearch_tool import elasticsearch_search
        from elasticsearch.exceptions import ConnectionError as ESConnError

        with patch("pipeline.tools.elasticsearch_tool._get_client") as mock_client_fn:
            mock_client_fn.side_effect = ESConnError("Connection refused")
            result = elasticsearch_search("test query")

        assert "[Elasticsearch Error]" in result


# ---------------------------------------------------------------------------
# Tests: Agent run_agent (mocked)
# ---------------------------------------------------------------------------

class TestAgent:
    def test_run_agent_returns_dict(self):
        from pipeline.agent import run_agent

        mock_answer = "Found 30 Malware events on PC-101."
        mock_ai_msg = MagicMock()
        mock_ai_msg.__class__.__name__ = "AIMessage"
        mock_ai_msg.content = mock_answer
        mock_ai_msg.tool_calls = []

        mock_tool_msg = MagicMock()
        mock_tool_msg.__class__.__name__ = "ToolMessage"
        mock_tool_msg.content = "Tool result"
        mock_tool_msg.tool_calls = []

        with patch("pipeline.agent._get_agent") as mock_get_agent:
            mock_agent = MagicMock()
            mock_agent.invoke.return_value = {
                "messages": [mock_tool_msg, mock_ai_msg]
            }
            mock_get_agent.return_value = mock_agent

            result = run_agent("What malware events occurred on PC-101?")

        assert isinstance(result, dict)
        assert "answer" in result
        assert "tools_used" in result
        assert "messages" in result

    def test_run_agent_handles_exception(self):
        from pipeline.agent import run_agent

        with patch("pipeline.agent._get_agent") as mock_get_agent:
            mock_get_agent.side_effect = Exception("LLM connection failed")
            result = run_agent("test question")

        assert "[Agent Error]" in result["answer"]
        assert result["tools_used"] == []

    def test_run_agent_extracts_tools_used(self):
        from pipeline.agent import run_agent

        mock_ai_msg = MagicMock()
        mock_ai_msg.__class__.__name__ = "AIMessage"
        mock_ai_msg.content = "Result"
        mock_ai_msg.tool_calls = [{"name": "rag_search"}, {"name": "mongodb_aggregation"}]

        with patch("pipeline.agent._get_agent") as mock_get_agent:
            mock_agent = MagicMock()
            mock_agent.invoke.return_value = {"messages": [mock_ai_msg]}
            mock_get_agent.return_value = mock_agent

            result = run_agent("Find malware and count events")

        assert "rag_search" in result["tools_used"]
        assert "mongodb_aggregation" in result["tools_used"]
