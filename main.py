import json
import time
import asyncio
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
import uvicorn
from langgraph.graph import StateGraph, END
from core.state import ThreatDossier

# Import our autonomous agents
from agents.sentinel import run_sentinel_triage
from agents.forensics import run_forensics_investigation
from agents.responder import run_responder_mitigation
from data.mock_siem import simulate_stream

# --- 1. Node Wrappers ---
def sentinel_node(state: ThreatDossier) -> ThreatDossier:
    raw_dict = json.loads(state.raw_log)
    updated_dossier = run_sentinel_triage(raw_dict)
    if not updated_dossier:
        state.resolution_status = "FAILED_PARSING"
        return state
    return updated_dossier

def forensics_node(state: ThreatDossier) -> ThreatDossier:
    return run_forensics_investigation(state)

def responder_node(state: ThreatDossier) -> ThreatDossier:
    return run_responder_mitigation(state)

# --- 2. Conditional Routing Logic ---
def route_after_sentinel(state: ThreatDossier) -> str:
    if state.threat_classification == "MALICIOUS":
        return "forensics_node"
    return END

def route_after_forensics(state: ThreatDossier) -> str:
    if state.is_compromise_confirmed:
        return "responder_node"
    return END

# --- 3. Build the StateGraph ---
print("[*] Compiling the VIGIL-SOAR LangGraph Architecture...")
workflow = StateGraph(ThreatDossier)
workflow.add_node("sentinel_node", sentinel_node)
workflow.add_node("forensics_node", forensics_node)
workflow.add_node("responder_node", responder_node)
workflow.set_entry_point("sentinel_node")
workflow.add_conditional_edges("sentinel_node", route_after_sentinel)
workflow.add_conditional_edges("forensics_node", route_after_forensics)
workflow.add_edge("responder_node", END)
app_workflow = workflow.compile()

# --- 4. FastAPI & WebSockets ---
app = FastAPI()

@app.get("/")
async def serve_dashboard():
    # Serve the HTML file directly from the root URL
    with open("index.html", "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    print("[+] Dashboard connected via WebSocket.")
    try:
        while True:
            # 1. Generate a single log from our mock SIEM
            log_dict = simulate_stream(1)[0]
            await websocket.send_json({"type": "ingest", "log": log_dict})
            
            # 2. Setup initial state
            initial_state = ThreatDossier(
                event_id=log_dict["event_id"],
                raw_log=json.dumps(log_dict)
            )
            
            # 3. Stream LangGraph execution node-by-node
            # This is the magic. It yields the state after EVERY agent acts.
            for output in app_workflow.stream(initial_state):
                node_name = list(output.keys())[0]
                state_obj = output[node_name]
                
                # Safely convert Pydantic model to dictionary for JSON transmission
                if hasattr(state_obj, "model_dump"):
                    state_dict = state_obj.model_dump()
                else:
                    state_dict = state_obj
                
                await websocket.send_json({
                    "type": "update",
                    "node": node_name,
                    "state": state_dict
                })
                
                # Visual delay so you can see the nodes light up in the UI
                await asyncio.sleep(1.5)
                
            await websocket.send_json({"type": "complete"})
            
            # Wait a few seconds before firing the next network event
            await asyncio.sleep(3)
            
    except WebSocketDisconnect:
        print("[-] Dashboard disconnected.")
    except Exception as e:
        print(f"[!] WebSocket Error: {e}")

if __name__ == "__main__":
    print("\n" + "="*50)
    print("🛡️  VIGIL-SOAR FASTAPI SERVER ACTIVATED 🛡️")
    print("Dashboard running at: http://localhost:8000")
    print("="*50 + "\n")
    uvicorn.run(app, host="0.0.0.0", port=8000)
