import json
from langchain_core.tools import tool
from langchain_groq import ChatGroq
from langchain_core.messages import HumanMessage, SystemMessage
from core.state import ThreatDossier
from dotenv import load_dotenv

load_dotenv()

# --- 1. Define the Tools (The AI's Database Queries) ---

@tool
def query_active_directory(username: str) -> str:
    """
    Queries the Active Directory database to retrieve a user's security profile.
    Always use this tool if a target_user is identified in the threat.
    """
    # In a real enterprise, this executes a SQL query or API call to Azure AD.
    # Here, we mock the database response.
    mock_db = {
        "admin_kushal": {"department": "IT", "mfa_enabled": False, "role": "SuperAdmin", "recent_travel": "None"},
        "hr_manager": {"department": "HR", "mfa_enabled": True, "role": "User", "recent_travel": "US"}
    }
    
    user_data = mock_db.get(username)
    if user_data:
        return json.dumps(user_data)
    return json.dumps({"error": "User not found in Active Directory"})

@tool
def check_threat_intel(ip_address: str) -> str:
    """
    Checks an external Threat Intelligence database to see if an IP is known to be malicious.
    Always use this tool if a target_ip is identified.
    """
    # Mocking a Threat Intel feed (like VirusTotal or CrowdStrike)
    known_bad_ips = ["185.15.59.224", "45.133.1.2"]
    
    if ip_address in known_bad_ips:
        return json.dumps({"status": "MALICIOUS", "threat_actor": "APT-29", "confidence": "High"})
    return json.dumps({"status": "CLEAN", "notes": "No known threat associations"})


# --- 2. The Forensics Logic ---

def run_forensics_investigation(dossier: ThreatDossier) -> ThreatDossier:
    """
    Takes the initial dossier, uses tools to gather evidence, and updates the state.
    """
    print(f"\n[*] Forensics Agent initiating investigation on User: {dossier.target_user}, IP: {dossier.target_ip}")
    
    # If the Sentinel said it was benign, the Forensics agent does nothing.
    if dossier.threat_classification == "BENIGN":
        print("[*] Alert is BENIGN. Bypassing forensics.")
        return dossier

    llm = ChatGroq(temperature=0, model_name="llama-3.1-8b-instant")
    
    # Bind the tools to the LLM so it knows it can execute these functions
    tools = [query_active_directory, check_threat_intel]
    llm_with_tools = llm.bind_tools(tools)
    
    sys_msg = SystemMessage(content="""You are an elite Digital Forensics Investigator.
    You have been given a Threat Dossier. 
    You MUST use the provided tools to investigate the target_user and target_ip.
    Do not guess. Execute the tools to gather evidence.""")
    
    # We pass the data to the LLM and wait for it to decide which tools to call
    user_msg = HumanMessage(content=f"Investigate this incident: User={dossier.target_user}, IP={dossier.target_ip}. Alert Detail: {dossier.raw_log}")
    
    # 1. The LLM decides what to do
    ai_response = llm_with_tools.invoke([sys_msg, user_msg])
    
    evidence_collected = []
    
    # 2. Execute the tools the AI requested
    if ai_response.tool_calls:
        for tool_call in ai_response.tool_calls:
            print(f"    [+] Executing Tool: {tool_call['name']} with args {tool_call['args']}")
            
            # Match the requested tool name to the actual Python function
            if tool_call['name'] == "query_active_directory":
                result = query_active_directory.invoke(tool_call['args'])
            elif tool_call['name'] == "check_threat_intel":
                result = check_threat_intel.invoke(tool_call['args'])
            else:
                result = "Error: Unknown tool."
                
            evidence_collected.append({
                "tool": tool_call['name'],
                "result": json.loads(result)
            })
    else:
        print("    [-] AI decided not to use any tools.")

    # 3. Update the Dossier
    dossier.forensic_evidence = evidence_collected
    
    # Simple deterministic logic to confirm compromise based on the evidence
    # If the IP is confirmed malicious AND the user has no MFA, it's a confirmed breach.
    is_breached = False
    for ev in evidence_collected:
        res = ev.get('result', {})
        if ev['tool'] == 'check_threat_intel' and res.get('status') == 'MALICIOUS':
            is_breached = True
    
    dossier.is_compromise_confirmed = is_breached
    
    print(f"[*] Forensics Complete. Compromise Confirmed: {dossier.is_compromise_confirmed}")
    return dossier

if __name__ == "__main__":
    # Simulate a dossier handed over from the Sentinel Agent
    mock_dossier = ThreatDossier(
        event_id="test-999",
        raw_log="Mock log data",
        threat_classification="MALICIOUS",
        severity_score=90,
        target_user="admin_kushal",
        target_ip="185.15.59.224"
    )
    
    updated_dossier = run_forensics_investigation(mock_dossier)
    print("\n--- Forensics Updated Dossier ---")
    print(updated_dossier.model_dump_json(indent=2))
