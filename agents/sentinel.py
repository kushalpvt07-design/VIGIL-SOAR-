import os
import json
from dotenv import load_dotenv
from langchain_groq import ChatGroq
from langchain_core.prompts import ChatPromptTemplate
from core.state import ThreatDossier

# Load the .env file containing your GROQ_API_KEY
load_dotenv()

def run_sentinel_triage(raw_log_dict: dict) -> ThreatDossier:
    """
    Ingests a raw SIEM log, passes it to Llama 3, and returns a structured ThreatDossier.
    """
    raw_log_str = json.dumps(raw_log_dict)
    event_id = raw_log_dict.get("event_id", "UNKNOWN")

    try:
        llm = ChatGroq(
            temperature=0, 
            model_name="llama-3.1-8b-instant" 
        )
    except Exception as e:
        print(f"CRITICAL: Failed to initialize Groq LLM. Error: {e}")
        return None

    # Force the LLM to output exactly our Pydantic schema
    structured_llm = llm.with_structured_output(ThreatDossier)
    
    # NEW SYSTEM PROMPT: Much more aggressive and explicit to prevent hallucinations
    system_msg = """You are an elite autonomous Tier 1 SOC Analyst. 
    Analyze the following raw SIEM log and extract the data into the exact JSON schema requested.
    
    CRITICAL RULES:
    1. READ THE DESCRIPTION CAREFULLY. Do not be fooled by 'action': 'LOGIN_SUCCESS'. 
    2. If the description mentions "foreign IP", "Impossible Travel", or "failed login attempts", you MUST set threat_classification to 'MALICIOUS'.
    3. If it is standard traffic from a known internal IP, set threat_classification to 'BENIGN'.
    4. severity_score: Assign 80-100 for MALICIOUS events, and 0 for BENIGN events.
    5. Extract target_user and target_ip directly from the log.
    """
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", system_msg),
        ("human", "Analyze this log: {log}")
    ])
    
    chain = prompt | structured_llm
    
    print(f"[*] Sentinel Agent analyzing Event: {event_id}...")
    
    try:
        dossier = chain.invoke({"log": raw_log_str})
        dossier.event_id = event_id
        dossier.raw_log = raw_log_str
        return dossier
    except Exception as e:
        print(f"CRITICAL: LLM Parsing failed. {e}")
        return None

if __name__ == "__main__":
    test_log = {
        "event_id": "test-999",
        "source_ip": "185.15.59.224",
        "user": "admin_kushal",
        "action": "LOGIN_SUCCESS",
        "resource": "Active_Directory",
        "description": "User logged in from foreign IP address 5 minutes after a local login."
    }
    
    result = run_sentinel_triage(test_log)
    if result:
        print("\n--- Sentinel Triage Output ---")
        print(result.model_dump_json(indent=2))
