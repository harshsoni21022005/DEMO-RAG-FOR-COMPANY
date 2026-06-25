"""
pipeline/agent.py

LangGraph ReAct Agent for the XDR RAG Pipeline.

Orchestrates 3 tools based on question type:
  1. rag_search        — vector similarity for attack patterns, summaries, behavior
  2. mongodb_aggregation — counts, trends, statistics, time-based reporting
  3. elasticsearch_search — exact IP/signature/IOC/process name lookups

The agent automatically selects the right tool (or combination) based on
the query and the system prompt routing rules.
"""

import logging
import os
from typing import Any, Optional

from dotenv import load_dotenv
from langchain_core.messages import HumanMessage
from langchain_core.tools import tool
from langchain_groq import ChatGroq
from langgraph.prebuilt.chat_agent_executor import create_react_agent

from pipeline.tools.rag_tool import rag_search as _rag_search_fn
from pipeline.tools.aggregation_tool import mongodb_aggregation as _agg_fn
from pipeline.tools.elasticsearch_tool import elasticsearch_search as _es_search_fn

load_dotenv()

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
LLM_MODEL: str = os.getenv("LLM_MODEL", "llama3-70b-8192")
LLM_BASE_URL: Optional[str] = os.getenv("LLM_BASE_URL") or None
LLM_TEMPERATURE: float = float(os.getenv("LLM_TEMPERATURE", "0.0"))

# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------
AGENT_SYSTEM_PROMPT = """You are an expert XDR (Extended Detection and Response) security analyst assistant.

You have access to three specialized tools. Choose the BEST tool for each question:

## Tool Selection Rules

### Use `rag_search` when the question involves:
- Similar attacks or attack patterns
- Incident summaries or behavior analysis
- Semantic security questions
- "What attacks are similar to X?"
- "Summarize activity on host Y"
- "Find incidents related to Z"
- Understanding the nature of threats
- Threat hunting based on behavior

### Use `mongodb_aggregation` when the question involves:
- Counts, totals, or numbers ("how many", "count", "total")
- Trends over time
- Top hosts or most active hosts ("top host", "most alerts")
- Severity statistics or distributions
- Time-based reporting ("yesterday", "today", "last 24 hours")
- Statistical summaries

### Use `elasticsearch_search` when the question involves:
- Exact IP addresses (source or destination)
- Exact signatures or rule names
- Exact process names
- IOC (Indicators of Compromise) lookups
- File hashes, domains, or file names
- Usernames or specific identifiers
- MITRE ATT&CK technique codes (e.g., T1055)

## Important Guidelines

1. **Prefer `mongodb_aggregation` over `rag_search`** for any question asking for
   numerical data, counts, statistics, or trend analysis.

2. **Prefer `elasticsearch_search`** when the user provides a specific identifier
   (IP, hash, username, signature string) to look up.

3. **Combine tools** when a question has multiple aspects:
   - First get counts (aggregation), then get context (RAG) for the top result
   - First find specific event (Elasticsearch), then look for similar patterns (RAG)

4. **Always cite** the specific hosts, time windows, and event types from your findings.

5. **Format responses** as a professional security analyst report with:
   - Critical findings first
   - Bullet points for clarity  
   - Specific data points (counts, IPs, timestamps)
   - Actionable insights or recommendations

You MUST use at least one tool before answering. Do not answer from memory alone."""


# ---------------------------------------------------------------------------
# LangChain tool wrappers
# (using @tool decorator so LangGraph can introspect schemas)
# ---------------------------------------------------------------------------

@tool
def rag_search(
    query: str,
    host: Optional[str] = None,
    event_type: Optional[str] = None,
) -> str:
    """
    Search XDR event summaries using semantic vector similarity.

    Use for: attack patterns, similar incidents, behavior analysis, threat hunting,
    incident summaries, understanding the nature of security events.

    Args:
        query: Natural language description of what you're looking for.
        host: Optional host name to filter results (e.g., "PC-101").
        event_type: Optional event type to filter (e.g., "Malware", "Phishing").
    """
    return _rag_search_fn(query=query, host=host, event_type=event_type)


@tool
def mongodb_aggregation(query: str) -> str:
    """
    Run statistical aggregation queries against XDR event data.

    Use for: counts, totals, top hosts, severity distributions, time-based
    reporting, trends, "how many", "most active", "yesterday", "today".

    Args:
        query: Natural language aggregation question, or a raw JSON pipeline string.
               Examples:
                 - "how many events by type"
                 - "top 10 hosts by alert count"
                 - "severity distribution today"
                 - "events from yesterday"
    """
    return _agg_fn(query=query)


@tool
def elasticsearch_search(query: str) -> str:
    """
    Perform exact full-text search across XDR event fields in Elasticsearch.

    Use for: exact IP lookups, specific signatures, IOCs, file hashes, domains,
    usernames, process names, MITRE technique codes.

    Args:
        query: Exact value or search string to find.
               Examples:
                 - "192.168.1.50"
                 - "ET MALWARE CnC Beacon"
                 - "powershell.exe"
                 - "T1055"
    """
    return _es_search_fn(query=query)


# ---------------------------------------------------------------------------
# LLM & Agent factory
# ---------------------------------------------------------------------------

def _build_llm() -> ChatGroq:
    """Build the ChatGroq model instance using environment config."""
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


_agent = None


def _get_agent():
    global _agent
    if _agent is None:
        llm = _build_llm()
        tools = [rag_search, mongodb_aggregation, elasticsearch_search]
        _agent = create_react_agent(
            model=llm,
            tools=tools,
            prompt=AGENT_SYSTEM_PROMPT,
        )
        log.info("LangGraph ReAct agent initialized with %d tools.", len(tools))
    return _agent


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def run_agent(question: str) -> dict[str, Any]:
    """
    Run the LangGraph ReAct agent for a given security question.

    The agent will:
      1. Analyze the question to select the best tool(s)
      2. Call the selected tool(s) with appropriate parameters
      3. Synthesize the results into a final answer

    Args:
        question: Natural language security question.

    Returns:
        Dict with keys:
          - "answer": str — the final synthesized answer
          - "tools_used": list[str] — names of tools invoked
          - "messages": list — full message history (for debugging)
    """
    try:
        agent = _get_agent()
        log.info("Running agent for question: '%s'", question[:100])

        result = agent.invoke({"messages": [HumanMessage(content=question)]})
        messages = result.get("messages", [])

        # Extract the final answer (last AI message)
        answer = ""
        for msg in reversed(messages):
            msg_type = type(msg).__name__
            if "AI" in msg_type and hasattr(msg, "content") and msg.content:
                answer = msg.content
                break

        # Identify which tools were used
        tools_used: list[str] = []
        for msg in messages:
            if hasattr(msg, "tool_calls") and msg.tool_calls:
                for tc in msg.tool_calls:
                    tool_name = tc.get("name", "") if isinstance(tc, dict) else getattr(tc, "name", "")
                    if tool_name and tool_name not in tools_used:
                        tools_used.append(tool_name)

        return {
            "answer": answer or "No answer generated.",
            "tools_used": tools_used,
            "messages": messages,
        }

    except Exception as exc:  # noqa: BLE001
        log.error("Agent error: %s", exc)
        return {
            "answer": f"[Agent Error] {exc}",
            "tools_used": [],
            "messages": [],
        }
