import json
import time
from langgraph.graph import StateGraph, END
from core.state import ThreatDossier

# Import our autonomous agents
from agents.sentinel import run_sentinel_triage
from agents.forensics import run_forensics_investigation
from agents.responder import run_responder_mitigation

# Import the mock SIEM generator
from data.mock_siem import simulate_stream

# --- 1. Node Wrappers ---
# LangGraph passes the State object between nodes. We wrap our existing functions
# to ensure they cleanly accept and return the ThreatDossier.

def sentinel_node(state: ThreatDossier) -> ThreatDossier:
    # The graph initializes with a bare dossier containing just the raw_log
    raw_dict = json.loads(state.raw_log)
    updated_dossier = run_sentinel_triage(raw_dict)
    
    # Fallback in case the LLM completely fails
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
    """Decides if the dossier needs forensic investigation."""
    if state.threat_classification == "MALICIOUS":
        return "forensics_node"
    return END # If it's BENIGN, drop the alert and end the graph.

def route_after_forensics(state: ThreatDossier) -> str:
    """Decides if the dossier requires automated mitigation."""
    if state.is_compromise_confirmed:
        return "responder_node"
    return END # If forensics cleared the user, end the graph.

# --- 3. Build the StateGraph ---

print("[*] Compiling the VIGIL-SOAR LangGraph Architecture...")
workflow = StateGraph(ThreatDossier)

# Add our three agent nodes
workflow.add_node("sentinel_node", sentinel_node)
workflow.add_node("forensics_node", forensics_node)
workflow.add_node("responder_node", responder_node)

# Set the entry point
workflow.set_entry_point("sentinel_node")

# Add the conditional edges (The AI's decision pathways)
workflow.add_conditional_edges("sentinel_node", route_after_sentinel)
workflow.add_conditional_edges("forensics_node", route_after_forensics)

# The responder is the end of the line
workflow.add_edge("responder_node", END)

# Compile the graph into an executable application
app = workflow.compile()


# --- 4. The Live Execution Loop ---

if __name__ == "__main__":
    print("\n" + "="*50)
    print("🛡️  VIGIL-SOAR PIPELINE ACTIVATED 🛡️")
    print("="*50 + "\n")
    
    # Generate 20 random logs to guarantee we catch an active attack
    incoming_logs = simulate_stream(20)
    
    for log_dict in incoming_logs:
        print(f"\n[->] INGESTING NEW SIEM EVENT: {log_dict['event_id']}")
        
        # Initialize the state for this specific incident
        initial_state = ThreatDossier(
            event_id=log_dict["event_id"],
            raw_log=json.dumps(log_dict)
        )
        
        # Execute the LangGraph pipeline
        try:
            final_state = app.invoke(initial_state)
            
            print(f"\n[✓] PIPELINE COMPLETE FOR {log_dict['event_id']}")
            print(f"    Final Status: {final_state['resolution_status']}")
            
            if final_state['resolution_status'] == "MITIGATED":
                print(f"    Actions Taken: {final_state['executed_actions']}")
        except Exception as e:
            print(f"[!] Graph Execution Failed: {e}")
            
        print("-" * 60)
        time.sleep(1) # Breathe before the next alert
