# tests/conftest.py
"""
Pytest configuration and shared fixtures for the XDR RAG Pipeline test suite.
"""

import os
import sys
import pytest

# Ensure the project root is on the Python path so tests can import workers/ and pipeline/
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


# ---------------------------------------------------------------------------
# Environment setup
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def mock_env_vars(monkeypatch):
    """
    Patch environment variables to safe test values so that importing
    modules doesn't try to connect to real external services.
    """
    monkeypatch.setenv("MONGODB_URI", "mongodb://localhost:27017")
    monkeypatch.setenv("MONGODB_DB", "xdr_test_db")
    monkeypatch.setenv("GROQ_API_KEY", "gsk-test-key")
    monkeypatch.setenv("EMBED_API_KEY", "sk-test-embed-key")
    monkeypatch.setenv("EMBED_MODEL", "nomic-embed-text-v1.5")
    monkeypatch.setenv("LLM_MODEL", "llama3-70b-8192")
    monkeypatch.setenv("VECTOR_INDEX_NAME", "xdr_vector_index")
    monkeypatch.setenv("ELASTICSEARCH_URL", "http://localhost:9200")
    monkeypatch.setenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")


# ---------------------------------------------------------------------------
# Asyncio mode
# ---------------------------------------------------------------------------

# Configure pytest-asyncio for async tests
pytest_plugins = ["pytest_asyncio"]
