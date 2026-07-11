import json
import random
import time
import uuid
from datetime import datetime, timezone

# Mock Data Pools
USERS = ["admin_kushal", "svc_account", "hr_manager", "dev_intern", "finance_lead"]
BENIGN_IPS = ["192.168.1.15", "192.168.1.22", "10.0.0.5", "10.0.0.12"]
MALICIOUS_IPS = ["185.15.59.224", "194.58.112.11", "45.133.1.2"]

def generate_benign_log():
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": random.choice(BENIGN_IPS),
        "user": random.choice(USERS),
        "action": "LOGIN_SUCCESS",
        "resource": "VPN_Gateway",
        "description": "Standard user login from known internal IP."
    }

def generate_impossible_travel():
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": random.choice(MALICIOUS_IPS),
        "user": "admin_kushal", # Hardcoded your username as the compromised target
        "action": "LOGIN_SUCCESS",
        "resource": "Active_Directory",
        "description": "User logged in from foreign IP address 5 minutes after a local login."
    }

def generate_brute_force():
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": random.choice(MALICIOUS_IPS),
        "user": random.choice(USERS),
        "action": "LOGIN_FAILED",
        "resource": "SSH_Server",
        "description": "45 failed login attempts in 30 seconds."
    }

def simulate_stream(num_events=5):
    """Generates a list of SIEM logs with injected anomalies."""
    logs = []
    for _ in range(num_events):
        # 80% chance of normal traffic, 20% chance of an attack
        roll = random.random()
        if roll > 0.9:
            logs.append(generate_impossible_travel())
        elif roll > 0.8:
            logs.append(generate_brute_force())
        else:
            logs.append(generate_benign_log())
    
    return logs

if __name__ == "__main__":
    print("--- Booting Mock SIEM Generator ---")
    live_logs = simulate_stream(5)
    for log in live_logs:
        print(json.dumps(log, indent=2))
        time.sleep(0.5) # Simulate network delay
