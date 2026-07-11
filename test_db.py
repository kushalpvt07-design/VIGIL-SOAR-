from core.db import get_recent_incidents
recent_alerts = get_recent_incidents(limit=5)
for a in recent_alerts:
    print(f"[{a['timestamp']}] {a['classification']} - User: {a['user']} - Status: {a['status']}")
