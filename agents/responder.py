import json
from langchain_core.tools import tool
from langchain_groq import ChatGroq
from langchain_core.messages import HumanMessage, SystemMessage
from core.state import ThreatDossier
from dotenv import load_dotenv

load_dotenv()

# --- 1. Define the Mitigation Tools ---

@tool
def block_ip_on_firewall(ip_address: str) -> str:
    """
    Adds a malicious IP address to the edge firewall's global blocklist.
    """
    # Mocking an API call to a firewall (e.g., Palo Alto or Fortinet)
    print(f"      [FIREWALL COMMAND] DROP ALL TRAFFIC FROM -> {ip_address}")
    return json.dumps({"action": "success", "mitigation": f"IP {ip_address} blocked at network edge."})

@tool
def disable_user_account(username: str) -> str:
    """
    Instantly revokes all access tokens and suspends an Active Directory user account.
    """
    # Mocking an Azure AD suspension command
    print(f"      [AD COMMAND] SUSPEND ACCOUNT -> {username}")
    return json.dumps({"action": "success", "mitigation": f"User {username} credentials revoked and sessions terminated."})


# --- 2. The Responder Logic ---

def run_responder_mitigation(dossier: ThreatDossier) -> ThreatDossier:
    """
    Evaluates the forensic evidence and executes defensive countermeasures.
    """
    print(f"\n[*] Responder Agent evaluating Dossier for Event: {dossier.event_id}")
    
    # If there is no confirmed breach, the Responder stands down.
    if not dossier.is_compromise_confirmed:
        print("[*] No compromise confirmed. Responder standing down. Closing incident.")
        dossier.resolution_status = "CLOSED_FALSE_POSITIVE"
        return dossier

    print("[!] COMPROMISE CONFIRMED. Initiating automated response protocols.")

    llm = ChatGroq(temperature=0, model_name="llama-3.1-8b-instant")
    
    # Arm the AI with defensive tools
    tools = [block_ip_on_firewall, disable_user_account]
    llm_with_tools = llm.bind_tools(tools)
    
    sys_msg = SystemMessage(content="""You are an elite Incident Response Automation Engine.
    A breach has been confirmed. You MUST use your tools to neutralize the threat.
    If there is a malicious IP, block it. 
    If a user account is compromised, disable it.
    Execute the necessary tools immediately.""")
    
    user_msg = HumanMessage(content=f"Neutralize this threat. Target User: {dossier.target_user}, Malicious IP: {dossier.target_ip}. Evidence: {json.dumps(dossier.forensic_evidence)}")
    
    # 1. The AI decides which defensive tools to trigger
    ai_response = llm_with_tools.invoke([sys_msg, user_msg])
    
    actions_taken = []
    
    # 2. Execute the mitigation tools
    if ai_response.tool_calls:
        for tool_call in ai_response.tool_calls:
            print(f"    [+] Executing Countermeasure: {tool_call['name']}")
            
            if tool_call['name'] == "block_ip_on_firewall":
                result = block_ip_on_firewall.invoke(tool_call['args'])
            elif tool_call['name'] == "disable_user_account":
                result = disable_user_account.invoke(tool_call['args'])
            else:
                result = '{"error": "Unknown mitigation tool."}'
                
            actions_taken.append(tool_call['name'])
    else:
        print("    [-] CRITICAL FAILURE: AI failed to execute countermeasures.")

    # 3. Finalize the State
    dossier.executed_actions = actions_taken
    if actions_taken:
        dossier.resolution_status = "MITIGATED"
    else:
        dossier.resolution_status = "ESCALATED_TO_HUMAN"
        
    print(f"[*] Response Complete. Incident Status: {dossier.resolution_status}")
    return dossier

if __name__ == "__main__":
    # Simulating the exact dossier output from the Forensics step
    mock_dossier = ThreatDossier(
        event_id="test-999",
        raw_log="Mock log data",
        threat_classification="MALICIOUS",
        severity_score=90,
        target_user="admin_kushal",
        target_ip="185.15.59.224",
        forensic_evidence=[
            {"tool": "check_threat_intel", "result": {"status": "MALICIOUS"}}
        ],
        is_compromise_confirmed=True
    )
    
    final_dossier = run_responder_mitigation(mock_dossier)
    print("\n--- Final Mitigated Dossier ---")
    print(final_dossier.model_dump_json(indent=2))
