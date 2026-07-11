import sqlite3
import json
import os
from core.state import ThreatDossier

# Ensure the data directory exists
DB_PATH = "data/vigil_soar.db"
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

def init_db():
    """Initializes the SQLite database and creates the incidents table if it doesn't exist."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS incidents (
            event_id TEXT PRIMARY KEY,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            threat_classification TEXT,
            severity_score INTEGER,
            target_user TEXT,
            target_ip TEXT,
            is_compromise_confirmed BOOLEAN,
            resolution_status TEXT,
            full_dossier JSON
        )
    ''')
    conn.commit()
    conn.close()
    print("[*] Database initialized at data/vigil_soar.db")

def save_dossier(dossier: ThreatDossier):
    """Saves a completed ThreatDossier to the database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            INSERT OR REPLACE INTO incidents 
            (event_id, threat_classification, severity_score, target_user, target_ip, is_compromise_confirmed, resolution_status, full_dossier)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            dossier.event_id,
            dossier.threat_classification,
            dossier.severity_score,
            dossier.target_user,
            dossier.target_ip,
            dossier.is_compromise_confirmed,
            dossier.resolution_status,
            dossier.model_dump_json() # Save the entire Pydantic object as a JSON string
        ))
        conn.commit()
    except Exception as e:
        print(f"[!] Database save failed: {e}")
    finally:
        conn.close()

def get_recent_incidents(limit=10):
    """Retrieves the most recent incidents from the database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT event_id, timestamp, threat_classification, severity_score, target_user, resolution_status 
        FROM incidents 
        ORDER BY timestamp DESC LIMIT ?
    ''', (limit,))
    
    rows = cursor.fetchall()
    conn.close()
    
    # Format for the frontend
    results = []
    for row in rows:
        results.append({
            "event_id": row[0],
            "timestamp": row[1],
            "classification": row[2],
            "severity": row[3],
            "user": row[4],
            "status": row[5]
        })
    return results
