"""
ui/app.py

Streamlit Chat Interface for the XDR RAG Pipeline.

Features:
  - Chat history with security analyst Q&A
  - Sidebar with live stats (events, summaries, embedded count)
  - Toggle between Agent mode and Simple RAG mode
  - Tool usage badges shown per answer
  - Auto-refresh stats
"""

import os
import time
from datetime import datetime
from typing import Any, Optional

import httpx
import streamlit as st
from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
API_BASE_URL: str = os.getenv("API_BASE_URL", "http://localhost:8000").rstrip("/")
REQUEST_TIMEOUT: float = 120.0  # seconds — LLM can take time

# ---------------------------------------------------------------------------
# Page configuration
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="XDR Security Analyst — RAG Pipeline",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Custom CSS
# ---------------------------------------------------------------------------
st.markdown(
    """
    <style>
    /* Main background */
    .stApp {
        background: linear-gradient(135deg, #0a0e1a 0%, #0d1426 50%, #0a0e1a 100%);
    }

    /* Sidebar styling */
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0d1426 0%, #111827 100%);
        border-right: 1px solid #1e3a5f;
    }

    /* Sidebar text color */
    [data-testid="stSidebar"] * {
        color: #a8c7f0 !important;
    }

    /* Chat message containers */
    .chat-message {
        padding: 1rem 1.25rem;
        border-radius: 12px;
        margin-bottom: 1rem;
        line-height: 1.6;
        font-size: 0.95rem;
    }

    .chat-user {
        background: rgba(59, 130, 246, 0.12);
        border-left: 3px solid #3b82f6;
        color: #e2e8f0;
    }

    .chat-assistant {
        background: rgba(16, 185, 129, 0.08);
        border-left: 3px solid #10b981;
        color: #e2e8f0;
    }

    /* Tool badge */
    .tool-badge {
        display: inline-block;
        padding: 2px 10px;
        border-radius: 12px;
        font-size: 0.75rem;
        font-weight: 600;
        margin-right: 6px;
        margin-top: 6px;
    }
    .badge-rag { background: rgba(139, 92, 246, 0.3); color: #c4b5fd; border: 1px solid #7c3aed; }
    .badge-mongo { background: rgba(16, 185, 129, 0.3); color: #6ee7b7; border: 1px solid #059669; }
    .badge-es { background: rgba(245, 158, 11, 0.3); color: #fcd34d; border: 1px solid #d97706; }

    /* Metric cards in sidebar */
    .metric-card {
        background: rgba(30, 58, 95, 0.4);
        border: 1px solid #1e3a5f;
        border-radius: 8px;
        padding: 0.75rem;
        margin-bottom: 0.5rem;
        text-align: center;
    }

    /* Status indicators */
    .status-up { color: #10b981; font-weight: bold; }
    .status-down { color: #ef4444; font-weight: bold; }

    /* Main title */
    .main-title {
        font-size: 2rem;
        font-weight: 700;
        background: linear-gradient(90deg, #3b82f6, #10b981);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        margin-bottom: 0.25rem;
    }

    /* Input styling */
    .stTextInput input, .stTextArea textarea {
        background: rgba(30, 58, 95, 0.3) !important;
        border: 1px solid #1e3a5f !important;
        color: #e2e8f0 !important;
        border-radius: 8px !important;
    }

    /* Button styling */
    .stButton > button {
        background: linear-gradient(90deg, #1d4ed8, #1e40af) !important;
        color: white !important;
        border: none !important;
        border-radius: 8px !important;
        padding: 0.5rem 1.5rem !important;
        font-weight: 600 !important;
        transition: all 0.2s !important;
    }
    .stButton > button:hover {
        background: linear-gradient(90deg, #2563eb, #1d4ed8) !important;
        transform: translateY(-1px) !important;
        box-shadow: 0 4px 12px rgba(59, 130, 246, 0.4) !important;
    }

    /* Example query chips */
    .example-chip {
        display: inline-block;
        padding: 4px 12px;
        border-radius: 16px;
        background: rgba(59, 130, 246, 0.15);
        border: 1px solid rgba(59, 130, 246, 0.4);
        color: #93c5fd;
        font-size: 0.8rem;
        margin: 3px;
        cursor: pointer;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# ---------------------------------------------------------------------------
# State initialization
# ---------------------------------------------------------------------------
if "messages" not in st.session_state:
    st.session_state.messages = []

if "use_agent" not in st.session_state:
    st.session_state.use_agent = True

if "stats" not in st.session_state:
    st.session_state.stats = None

if "health" not in st.session_state:
    st.session_state.health = None

if "stats_loaded_at" not in st.session_state:
    st.session_state.stats_loaded_at = 0


# ---------------------------------------------------------------------------
# API helpers
# ---------------------------------------------------------------------------

def fetch_stats() -> Optional[dict[str, Any]]:
    try:
        resp = httpx.get(f"{API_BASE_URL}/stats", timeout=5.0)
        resp.raise_for_status()
        return resp.json()
    except Exception:
        return None


def fetch_health() -> Optional[dict[str, Any]]:
    try:
        resp = httpx.get(f"{API_BASE_URL}/health", timeout=5.0)
        resp.raise_for_status()
        return resp.json()
    except Exception:
        return None


def query_api(question: str, use_agent: bool) -> dict[str, Any]:
    try:
        resp = httpx.post(
            f"{API_BASE_URL}/query",
            json={"question": question, "use_agent": use_agent},
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()
    except httpx.TimeoutException:
        return {"answer": "⚠️ Request timed out. The LLM is taking too long.", "tools_used": [], "elapsed_ms": 0}
    except httpx.ConnectError:
        return {
            "answer": f"⚠️ Cannot connect to API at {API_BASE_URL}. Is the FastAPI server running?",
            "tools_used": [],
            "elapsed_ms": 0,
        }
    except Exception as exc:
        return {"answer": f"⚠️ API Error: {exc}", "tools_used": [], "elapsed_ms": 0}


def tool_badge(tool_name: str) -> str:
    mapping = {
        "rag_search": ("🔍 RAG Search", "badge-rag"),
        "mongodb_aggregation": ("📊 Mongo Aggregation", "badge-mongo"),
        "elasticsearch_search": ("⚡ Elasticsearch", "badge-es"),
    }
    label, cls = mapping.get(tool_name, (tool_name, "badge-rag"))
    return f'<span class="tool-badge {cls}">{label}</span>'


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

with st.sidebar:
    # Logo / Title
    st.markdown(
        """
        <div style="text-align:center; padding: 1rem 0 0.5rem 0;">
            <div style="font-size:2.5rem;">🛡️</div>
            <div style="font-size:1.1rem; font-weight:700; color:#3b82f6; letter-spacing:0.05em;">
                XDR Security Analyst
            </div>
            <div style="font-size:0.75rem; color:#64748b; margin-top:0.25rem;">
                RAG Pipeline Console
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.divider()

    # --- Mode Toggle ---
    st.markdown("### ⚙️ Query Mode")
    use_agent = st.toggle(
        "Agent Mode (recommended)",
        value=st.session_state.use_agent,
        help="Agent mode uses LangGraph to intelligently route between 3 tools. Simple RAG uses vector search only.",
    )
    st.session_state.use_agent = use_agent

    if use_agent:
        st.caption("🤖 **Agent**: Routes between RAG, MongoDB, and Elasticsearch")
    else:
        st.caption("🔍 **Simple RAG**: Vector search only")

    st.divider()

    # --- Stats ---
    st.markdown("### 📈 Pipeline Stats")

    col_refresh, col_auto = st.columns([2, 1])
    with col_refresh:
        if st.button("🔄 Refresh Stats", use_container_width=True):
            st.session_state.stats = fetch_stats()
            st.session_state.health = fetch_health()
            st.session_state.stats_loaded_at = time.time()

    # Auto-load stats on first render
    if st.session_state.stats is None or (time.time() - st.session_state.stats_loaded_at > 60):
        st.session_state.stats = fetch_stats()
        st.session_state.health = fetch_health()
        st.session_state.stats_loaded_at = time.time()

    stats = st.session_state.stats
    if stats:
        st.metric("📥 Raw Events", f"{stats.get('total_events', 0):,}")
        st.metric("📋 Summaries", f"{stats.get('total_summaries', 0):,}")

        embedded = stats.get("embedded_summaries", 0)
        total = stats.get("total_summaries", 1)
        pct = int((embedded / total * 100) if total > 0 else 0)
        st.metric("🧬 Embedded", f"{embedded:,}", delta=f"{pct}% done")

        pending = stats.get("pending_summaries", 0)
        error = stats.get("error_summaries", 0)
        if pending > 0:
            st.caption(f"⏳ {pending} pending embedding")
        if error > 0:
            st.caption(f"❌ {error} embedding errors")
    else:
        st.caption("⚠️ Could not reach API server")

    st.divider()

    # --- Health Status ---
    st.markdown("### 🩺 Service Health")
    health = st.session_state.health
    if health:
        services = health.get("services", {})
        for svc_name, svc_info in services.items():
            status = svc_info.get("status", "unknown")
            icon = "🟢" if status == "up" else "🔴"
            st.markdown(f"{icon} **{svc_name.title()}**: {status.upper()}")
        overall = health.get("status", "unknown")
        st.caption(f"Overall: {overall.upper()}")
    else:
        st.caption("⚠️ Health check unavailable")

    st.divider()

    # --- Clear Chat ---
    if st.button("🗑️ Clear Chat", use_container_width=True):
        st.session_state.messages = []
        st.rerun()

    st.markdown(
        "<div style='text-align:center; font-size:0.7rem; color:#374151; padding-top:1rem;'>"
        "XDR RAG Pipeline v1.0"
        "</div>",
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Main content area
# ---------------------------------------------------------------------------

# Header
st.markdown(
    """
    <div class="main-title">🛡️ XDR Security Analyst</div>
    <p style="color:#64748b; margin-bottom:1.5rem; font-size:0.9rem;">
        Ask security questions about your XDR telemetry — attack patterns, IOC lookups, event statistics, and more.
    </p>
    """,
    unsafe_allow_html=True,
)

# Example queries (clickable)
EXAMPLE_QUERIES = [
    "What malware events occurred on PC-101?",
    "How many events by type today?",
    "Find events with source IP 10.0.0.50",
    "Which hosts had the most alerts?",
    "Summarize phishing activity in the last hour",
    "Show events with ET SCAN Nmap signature",
    "What are the top 5 hosts by severity?",
    "Find events similar to CnC beacon activity",
]

with st.expander("💡 Example queries — click to try", expanded=False):
    cols = st.columns(2)
    for i, q in enumerate(EXAMPLE_QUERIES):
        if cols[i % 2].button(q, key=f"example_{i}", use_container_width=True):
            # Add to chat and trigger a query
            st.session_state.messages.append({"role": "user", "content": q, "tools": []})
            with st.spinner(f"Thinking... (mode: {'Agent' if st.session_state.use_agent else 'Simple RAG'})"):
                result = query_api(q, st.session_state.use_agent)
            st.session_state.messages.append(
                {
                    "role": "assistant",
                    "content": result.get("answer", "No answer."),
                    "tools": result.get("tools_used", []),
                    "elapsed_ms": result.get("elapsed_ms", 0),
                    "mode": result.get("mode", "unknown"),
                }
            )
            st.rerun()

st.divider()

# ---------------------------------------------------------------------------
# Chat history display
# ---------------------------------------------------------------------------
for msg in st.session_state.messages:
    role = msg["role"]
    content = msg["content"]

    if role == "user":
        st.markdown(
            f'<div class="chat-message chat-user">'
            f'<strong>🔐 You</strong><br>{content}'
            f"</div>",
            unsafe_allow_html=True,
        )
    else:
        tools_html = ""
        tools = msg.get("tools", [])
        if tools:
            tools_html = "".join(tool_badge(t) for t in tools)
            tools_html = f"<div style='margin-top:8px;'>{tools_html}</div>"

        elapsed = msg.get("elapsed_ms", 0)
        mode = msg.get("mode", "")
        meta = f"<div style='font-size:0.72rem; color:#475569; margin-top:6px;'>⏱ {elapsed:.0f}ms | Mode: {mode}</div>"

        st.markdown(
            f'<div class="chat-message chat-assistant">'
            f"<strong>🤖 XDR Analyst</strong><br>{content}"
            f"{tools_html}{meta}"
            f"</div>",
            unsafe_allow_html=True,
        )

# ---------------------------------------------------------------------------
# Chat input
# ---------------------------------------------------------------------------
st.markdown("<br>", unsafe_allow_html=True)

with st.form(key="chat_form", clear_on_submit=True):
    col_input, col_btn = st.columns([6, 1])
    with col_input:
        user_input = st.text_area(
            "Ask a security question...",
            placeholder="e.g., What malware attacks happened on PC-101 in the last hour?",
            height=80,
            label_visibility="collapsed",
            key="user_input",
        )
    with col_btn:
        submitted = st.form_submit_button(
            "Send 🚀",
            use_container_width=True,
        )

if submitted and user_input and user_input.strip():
    question = user_input.strip()

    # Add user message
    st.session_state.messages.append({"role": "user", "content": question, "tools": []})

    # Query API
    with st.spinner(f"🤔 Analyzing... ({'Agent' if st.session_state.use_agent else 'Simple RAG'} mode)"):
        result = query_api(question, st.session_state.use_agent)

    # Add assistant message
    st.session_state.messages.append(
        {
            "role": "assistant",
            "content": result.get("answer", "No answer generated."),
            "tools": result.get("tools_used", []),
            "elapsed_ms": result.get("elapsed_ms", 0),
            "mode": result.get("mode", "unknown"),
        }
    )

    # Refresh stats after query
    st.session_state.stats = fetch_stats()
    st.rerun()
