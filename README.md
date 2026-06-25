# 🛡️ XDR RAG Pipeline

A production-grade **Extended Detection and Response (XDR)** system that combines **Kafka**, **MongoDB Atlas Vector Search**, **LangChain**, and **LangGraph** to build an intelligent security analyst pipeline.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         XDR RAG PIPELINE                                │
│                                                                          │
│  ┌──────────┐    ┌──────────────────┐    ┌───────────────────────────┐  │
│  │  Kafka   │───▶│  Kafka Connect   │───▶│   MongoDB xdr_events      │  │
│  │ Producer │    │  MongoDB Sink    │    │   (raw events)            │  │
│  └──────────┘    └──────────────────┘    └───────────┬───────────────┘  │
│                                                       │                  │
│                                         ┌─────────────▼───────────────┐ │
│                                         │  Summarization Worker       │ │
│                                         │  (5-min windows per host)   │ │
│                                         └─────────────┬───────────────┘ │
│                                                       │                  │
│                                         ┌─────────────▼───────────────┐ │
│                                         │  MongoDB xdr_summaries      │ │
│                                         │  (pending embedding)        │ │
│                                         └─────────────┬───────────────┘ │
│                                                       │                  │
│                                         ┌─────────────▼───────────────┐ │
│                                         │  Embedding Worker           │ │
│                                         │  (OpenAI / LM Studio)       │ │
│                                         └─────────────┬───────────────┘ │
│                                                       │                  │
│                                         ┌─────────────▼───────────────┐ │
│                                         │  xdr_summaries              │ │
│                                         │  (with embeddings ✅)        │ │
│                                         └─────────────────────────────┘ │
│                                                       │                  │
│  ┌─────────────┐    ┌──────────────────┐    ┌────────▼───────────────┐  │
│  │  Streamlit  │───▶│   FastAPI /query │───▶│  LangGraph Agent       │  │
│  │  Chat UI    │    │   /health /stats │    │  ┌─────────────────┐   │  │
│  └─────────────┘    └──────────────────┘    │  │  rag_search     │   │  │
│                                             │  │  mongo_agg      │   │  │
│  ┌───────────────────────────────────────┐  │  │  es_search      │   │  │
│  │         Elasticsearch                 │◀─│  └─────────────────┘   │  │
│  │         (full-text / IOC search)      │  └────────────────────────┘  │
│  └───────────────────────────────────────┘                               │
└─────────────────────────────────────────────────────────────────────────┘
```

### Data Flow

1. **Ingest**: Security events flow from Kafka → MongoDB via Kafka Connect
2. **Summarize**: Worker groups raw events into 5-minute windows per host + event type
3. **Embed**: Worker calls embedding API to vectorize summary text
4. **Query**: User asks a question → FastAPI → LangGraph agent selects the best tool:
   - **RAG**: Vector similarity search for attack patterns and summaries
   - **Aggregation**: MongoDB pipeline for counts, trends, statistics
   - **Elasticsearch**: Full-text search for exact IPs, signatures, IOCs

---

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | 3.11+ | |
| Docker + Docker Compose | Latest | For Kafka, Elasticsearch |
| MongoDB Atlas | M10+ | Required for Vector Search |
| OpenAI API key | — | Or LM Studio for local models |

---

## Step-by-Step Setup

### 1. Clone and Install

```bash
cd xdr-rag-pipeline
pip install -r requirements.txt
```

### 2. Configure Environment

```bash
cp .env.example .env
```

Edit `.env` and fill in:

| Variable | Description |
|----------|-------------|
| `MONGODB_URI` | MongoDB Atlas connection string |
| `OPENAI_API_KEY` | OpenAI API key (or leave blank for LM Studio) |
| `LLM_BASE_URL` | LM Studio URL e.g. `http://localhost:1234/v1` |
| `EMBED_BASE_URL` | Same as above for embeddings |
| `ELASTICSEARCH_URL` | Usually `http://localhost:9200` |
| `KAFKA_BOOTSTRAP_SERVERS` | Usually `localhost:9092` |

### 3. Start Docker Services

```bash
docker compose up -d
```

This starts:
- **Zookeeper** (port 2181)
- **Kafka** (port 9092)
- **Kafka Connect** (port 8083) — auto-installs MongoDB connector
- **Elasticsearch** (port 9200)

Wait ~60 seconds for all services to be healthy:

```bash
docker compose ps
```

### 4. Create Atlas Vector Search Index

In MongoDB Atlas:

1. Navigate to your cluster → **Search** → **Create Search Index**
2. Select **JSON Editor** and paste the contents of `config/vector_search_index.json`
3. Set the database to `xdr_db` and collection to `xdr_summaries`
4. Name the index: `xdr_vector_index`
5. Click **Create**

> ⚠️ **IMPORTANT**: The Atlas free tier (M0) does **not** support Vector Search.
> You need at least **M10** or use Atlas Search on a Serverless instance.

### 5. Deploy the Kafka Connector

```bash
python scripts/deploy_connector.py
```

This waits for Kafka Connect to be ready, then deploys the MongoDB Sink Connector
that routes `xdr.events` topic messages into the `xdr_events` collection.

Verify the connector is running:

```bash
curl http://localhost:8083/connectors/xdr-mongodb-sink/status
```

---

## Running the Pipeline

### Send Test Events to Kafka

```bash
# Send 100 events (default)
python scripts/seed_kafka.py

# Send custom count to a specific topic
python scripts/seed_kafka.py --count 500 --topic xdr.events
```

### Start the Summarization Worker

```bash
python workers/summarization_worker.py
```

Runs every 60 seconds (configurable via `SUMMARIZATION_INTERVAL`).
Creates `xdr_summaries` documents grouped by (host, event_type, 5-min window).

### Start the Embedding Worker

```bash
python workers/embedding_worker.py
```

Reads `embedding_status=pending` summaries in batches of 50 and calls the
embedding API. Runs continuously with 10-second sleep between batches.

### Start the FastAPI Server

```bash
uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
```

API docs available at: http://localhost:8000/docs

### Start the Streamlit UI

```bash
streamlit run ui/app.py
```

Opens at: http://localhost:8501

---

## Running Tests

```bash
# All tests
pytest

# Specific test files
pytest tests/test_summarization.py -v
pytest tests/test_embedding.py -v
pytest tests/test_agent.py -v

# With coverage
pip install pytest-cov
pytest --cov=workers --cov=pipeline --cov-report=term-missing
```

> 📝 Tests use mocked external dependencies — no real MongoDB, Elasticsearch, or LLM calls.

---

## Using LM Studio (Local Models)

To run fully offline with local models:

1. Download and install [LM Studio](https://lmstudio.ai/)
2. Load a model (recommended: `mistral-7b-instruct`, `phi-3-mini`)
3. Start the local server (default port 1234)
4. In `.env`:
   ```
   LLM_BASE_URL=http://localhost:1234/v1
   EMBED_BASE_URL=http://localhost:1234/v1
   LLM_MODEL=<your-model-identifier>
   EMBED_MODEL=<your-embedding-model>
   OPENAI_API_KEY=lm-studio   # any non-empty string
   ```

---

## API Reference

### `POST /query`

```json
{
  "question": "What malware events occurred on PC-101?",
  "use_agent": true
}
```

**Response:**
```json
{
  "question": "What malware events occurred on PC-101?",
  "answer": "PC-101 generated 45 malware events...",
  "tools_used": ["rag_search"],
  "mode": "agent",
  "elapsed_ms": 1842.5
}
```

### `GET /health`

Returns MongoDB + Elasticsearch connectivity status.

### `GET /stats`

Returns document counts: events, summaries, embedded, pending, error.

---

## Example Queries to Try

### Vector Search (RAG)
```
"What attack patterns are similar to CnC beacon activity?"
"Summarize the security activity on PC-101"
"Find incidents related to lateral movement"
"What malware behavior was detected this morning?"
```

### Statistical Aggregation (MongoDB)
```
"How many events occurred by event type?"
"Which hosts had the most alerts today?"
"Show the severity distribution"
"What events happened yesterday?"
"Count events from the last 24 hours"
```

### Exact Lookups (Elasticsearch)
```
"Find events with source IP 10.0.0.50"
"Search for ET SCAN Nmap signature"
"Who logged in as admin?"
"Find events involving powershell.exe"
"Show me events with MITRE technique T1055"
```

### Combined (Agent handles automatically)
```
"How many malware events on PC-101, and what do they look like?"
"Which host has the most alerts, and what kind of attacks are they?"
```

---

## MongoDB Collections Reference

### `xdr_events`
Raw events ingested from Kafka. Schema supports dynamic fields.

### `xdr_summaries`
Aggregated 5-minute window summaries with:
- Statistics (counts, severities, signatures)
- Dynamic metadata (auto-captured unknown fields)
- Optional security fields (MITRE, process names, usernames)
- Vector embedding (`embedding_status: pending → done`)

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Kafka Connect unhealthy | Wait 60-90s for connector JAR installation; check `docker logs xdr-kafka-connect` |
| No embeddings appearing | Check `OPENAI_API_KEY` or `EMBED_BASE_URL`; check embedding worker logs |
| Vector search returns nothing | Verify Atlas index exists with correct name (`xdr_vector_index`); check `embedding_status: done` docs exist |
| LM Studio connection refused | Ensure LM Studio local server is running and model is loaded |
| Streamlit can't reach API | Ensure FastAPI is running on port 8000; check `API_BASE_URL` in `.env` |

---

## Project Structure

```
xdr-rag-pipeline/
├── config/
│   ├── kafka_sink_connector.json     # Kafka Connect MongoDB Sink config
│   └── vector_search_index.json      # Atlas Vector Search index definition
├── workers/
│   ├── summarization_worker.py       # Groups events into 5-min summaries
│   └── embedding_worker.py           # Embeds summaries via OpenAI/LM Studio
├── pipeline/
│   ├── rag_chain.py                  # Simple LangChain RAG chain
│   ├── agent.py                      # LangGraph ReAct agent
│   └── tools/
│       ├── rag_tool.py               # Vector similarity search
│       ├── aggregation_tool.py       # MongoDB aggregation pipelines
│       └── elasticsearch_tool.py     # Elasticsearch full-text search
├── api/
│   └── main.py                       # FastAPI app (/query, /health, /stats)
├── ui/
│   └── app.py                        # Streamlit chat interface
├── scripts/
│   ├── seed_kafka.py                 # Send 100 fake XDR events to Kafka
│   └── deploy_connector.py           # Deploy Kafka Connect MongoDB Sink
├── tests/
│   ├── conftest.py                   # Shared fixtures and path setup
│   ├── test_summarization.py         # Tests for summarization logic
│   ├── test_embedding.py             # Tests for embedding worker
│   └── test_agent.py                 # Tests for agent + tools
├── .env.example                      # Environment variable template
├── requirements.txt                  # Python dependencies
├── docker-compose.yml                # Infrastructure services
├── pytest.ini                        # Test configuration
└── README.md
```

---

## License

MIT — see LICENSE file.
