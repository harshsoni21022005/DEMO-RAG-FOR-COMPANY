"""
One-shot script: fetch ground truth for PC-101 Malware from MongoDB,
then query the RAG API and compare the two answers.
"""
import os, json, httpx
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()

MONGODB_URI = os.getenv("MONGODB_URI")
MONGODB_DB  = os.getenv("MONGODB_DB", "xdr_db")
API_URL     = "http://localhost:8000/query"
QUESTION    = "Which malware events occurred on PC-101?"

# ── 1. GROUND TRUTH ────────────────────────────────────────────────
client = MongoClient(MONGODB_URI)
db     = client[MONGODB_DB]

docs = list(db["xdr_summaries"].find(
    {"host": "PC-101", "event_type": "Malware"},
    {"_id": 0, "host": 1, "event_type": 1, "summary_text": 1,
     "event_count": 1, "severity_distribution": 1,
     "top_signatures": 1, "window_start": 1, "window_end": 1,
     "source_ip_count": 1, "destination_ip_count": 1}
))

print("=" * 60)
print("STEP 1 — GROUND TRUTH FROM MONGODB ATLAS")
print("=" * 60)
print(f"Total Malware summary windows found for PC-101: {len(docs)}")

total_events      = 0
all_signatures    = []
all_severities    = {}

for i, d in enumerate(docs, 1):
    ec   = d.get("event_count", 0)
    sev  = d.get("severity_distribution", {})
    sigs = d.get("top_signatures", [])
    total_events += ec
    all_signatures.extend(sigs)
    for k, v in sev.items():
        all_severities[k] = all_severities.get(k, 0) + v

    print(f"\n  -- Window {i} --")
    print(f"     Time   : {d.get('window_start')} -> {d.get('window_end')}")
    print(f"     Events : {ec}")
    print(f"     Sev    : {sev}")
    print(f"     Sigs   : {sigs}")
    print(f"     SrcIPs : {d.get('source_ip_count')}")
    print(f"     DstIPs : {d.get('destination_ip_count')}")
    txt = str(d.get("summary_text", ""))
    print(f"     Text   : {txt[:350]}")

print(f"\n  TOTAL across all windows:")
print(f"    Events            : {total_events}")
print(f"    Combined Severity : {all_severities}")
print(f"    Unique Signatures : {list(dict.fromkeys(all_signatures))}")

# ── 2. RAG PIPELINE ANSWER ─────────────────────────────────────────
print()
print("=" * 60)
print("STEP 2 — RAG PIPELINE ANSWER")
print("=" * 60)
print(f"Question : {QUESTION}")

with httpx.Client() as http:
    resp = http.post(API_URL,
                     json={"question": QUESTION, "use_agent": True},
                     timeout=30.0)

if resp.status_code != 200:
    print(f"[ERROR] API returned {resp.status_code}: {resp.text}")
    raise SystemExit(1)

data         = resp.json()
rag_answer   = data.get("answer", "")
tools_used   = data.get("tools_used", [])
elapsed_ms   = data.get("elapsed_ms", 0)

print(f"Tools Used : {tools_used}")
print(f"Elapsed    : {elapsed_ms:.0f} ms")
print(f"\nAnswer:\n{rag_answer}")

# ── 3. COMPARISON ──────────────────────────────────────────────────
print()
print("=" * 60)
print("STEP 3 — ACCURACY COMPARISON")
print("=" * 60)

rag_lower = rag_answer.lower()
checks = {
    "Mentions host PC-101"            : "pc-101" in rag_lower,
    "Mentions event type Malware"     : "malware" in rag_lower,
    "Mentions at least one signature" : any(s.lower() in rag_lower for s in all_signatures),
    "Agent used at least one tool"    : len(tools_used) > 0,
}

all_pass = True
for label, result in checks.items():
    status = "[PASS]" if result else "[FAIL]"
    if not result:
        all_pass = False
    print(f"  {status}  {label}")

print()
if all_pass:
    print("[SUCCESS] Pipeline answer is consistent with the database ground truth.")
else:
    print("[WARNING] Some checks failed — review the comparison above.")
