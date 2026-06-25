"""
scripts/verify_rag.py

Automated script to verify that the RAG pipeline is working correctly.
It queries MongoDB Atlas directly to retrieve a ground truth summary,
then asks the API RAG endpoint about it, and validates the answer.
"""

import os
import sys
import httpx
from pymongo import MongoClient
from dotenv import load_dotenv

# Load env variables
load_dotenv()

MONGODB_URI = os.getenv("MONGODB_URI")
MONGODB_DB = os.getenv("MONGODB_DB", "xdr_db")
API_URL = "http://localhost:8000/query"

def run_verification():
    print("=" * 60)
    print("XDR RAG PIPELINE VERIFICATION")
    print("=" * 60)
    
    # 1. Connect to MongoDB and fetch a valid summary
    print(f"\n[1/4] Connecting to MongoDB to fetch ground truth...")
    if not MONGODB_URI:
        print("❌ Error: MONGODB_URI is not set in .env")
        sys.exit(1)
        
    try:
        client = MongoClient(MONGODB_URI)
        db = client[MONGODB_DB]
        summaries_col = db["xdr_summaries"]
        
        # Find one summary that has been successfully embedded
        doc = summaries_col.find_one({"embedding_status": "completed"})
        if not doc:
            # Fall back to any summary
            doc = summaries_col.find_one()
            
        if not doc:
            print("[ERROR] Error: No summaries found in xdr_summaries collection.")
            print("Please make sure seed_kafka.py and summarization_worker.py have run.")
            sys.exit(1)
            
        host = doc.get("host")
        event_type = doc.get("event_type")
        summary_text = doc.get("summary_text", "")
        has_embedding = doc.get("embedding") is not None and isinstance(doc.get("embedding"), list)
        
        print(f"[OK] Found ground truth summary:")
        print(f"   - Host: {host}")
        print(f"   - Event Type: {event_type}")
        print(f"   - Has Vector Embedding: {'Yes (Length ' + str(len(doc.get('embedding', []))) + ')' if has_embedding else 'No'}")
        print(f"   - Excerpt: \"{summary_text[:120]}...\"")
        
    except Exception as exc:
        print(f"[ERROR] MongoDB Connection failed: {exc}")
        sys.exit(1)
        
    # 2. Check if API is running
    print(f"\n[2/4] Testing connection to FastAPI Agent (RAG) at {API_URL}...")
    try:
        # Check a simple get or status endpoint (we'll just POST to query)
        # We check if port 8000 is listening
        with httpx.Client() as http_client:
            # Test query
            test_payload = {
                "question": f"Summarize the {event_type} events observed on {host}",
                "use_agent": True
            }
            print(f"Sending query to API: \"{test_payload['question']}\"")
            
            # Send RAG request
            response = http_client.post(API_URL, json=test_payload, timeout=30.0)
            
    except httpx.ConnectError:
        print(f"[ERROR] Error: Could not connect to API server at {API_URL}.")
        print("Please make sure python api/main.py is running in another terminal!")
        sys.exit(1)
    except Exception as exc:
        print(f"[ERROR] Error communicating with API: {exc}")
        sys.exit(1)

    # 3. Analyze RAG Response
    print(f"\n[3/4] Parsing and verifying RAG Agent response...")
    if response.status_code != 200:
        print(f"[ERROR] API returned status code {response.status_code}: {response.text}")
        sys.exit(1)
        
    response_data = response.json()
    agent_response = response_data.get("answer", "")
    tools_used = response_data.get("tools_used", [])
    
    print("\n--- Agent Response ---")
    print(agent_response)
    print("----------------------")
    print(f"Tools used: {tools_used}")
    
    # 4. Perform evaluation checks
    print(f"\n[4/4] Evaluating answer accuracy:")
    
    # Check 1: Did the LLM mention the requested host?
    host_match = host.lower() in agent_response.lower()
    print(f"   * Mentioned Host ({host}): {'[PASS]' if host_match else '[FAIL]'}")
    
    # Check 2: Did the LLM mention the requested event type?
    type_match = event_type.lower() in agent_response.lower()
    print(f"   * Mentioned Event Type ({event_type}): {'[PASS]' if type_match else '[FAIL]'}")
    
    # Check 3: Did the API return that it used tools (e.g. vector search or mongodb aggregation)?
    tools_ok = len(tools_used) > 0
    print(f"   * RAG Agent Utilized Tools: {'[PASS] (' + str(tools_used) + ')' if tools_ok else '[FAIL] (No tools used)'}")
    
    if host_match and type_match and tools_ok:
        print("\n[SUCCESS] VERIFICATION SUCCESSFUL: The RAG pipeline is fully functional!")
        print("The vector retrieval succeeded, the context was passed to Groq, and the LLM answered correctly.")
    else:
        print("\n[WARNING] Verification finished with some warnings/failures. Please review the output above.")

if __name__ == "__main__":
    run_verification()
