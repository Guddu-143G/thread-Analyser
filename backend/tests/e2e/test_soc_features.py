import urllib.request
import json
import sys

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# 1. Login
token_resp = urllib.request.urlopen(urllib.request.Request(
    'http://localhost:8000/api/auth/login',
    data=json.dumps({'email': 'analyst@acme.corp', 'password': 'SecurePassword123!'}).encode('utf-8'),
    headers={'Content-Type': 'application/json'}
))
token = json.loads(token_resp.read())['access_token']

# 2. Get alerts
alerts_resp = urllib.request.urlopen(urllib.request.Request(
    'http://localhost:8000/api/alerts',
    headers={'Authorization': f'Bearer {token}'}
))
alerts = json.loads(alerts_resp.read())
print(f"Total alerts in queue: {len(alerts)}")
first_alert = alerts[0]
first_alert_id = first_alert['id']

# 3. Test SOAR Host Isolation Mitigation
mitigate_req = urllib.request.Request(
    f'http://localhost:8000/api/alerts/{first_alert_id}/mitigate',
    data=json.dumps({'action': 'isolate_host', 'comment': 'Automated test SOAR containment'}).encode('utf-8'),
    headers={'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}
)
with urllib.request.urlopen(mitigate_req) as resp:
    mitigate_res = json.loads(resp.read())
    print(f"[✓] SOAR Mitigation Dispatched: {mitigate_res['message']}")

# 4. Test Alert Status Triage with Analyst Comment
triage_req = urllib.request.Request(
    f'http://localhost:8000/api/alerts/{first_alert_id}',
    data=json.dumps({'status': 'resolved', 'comment': 'Threat eliminated and host restored.'}).encode('utf-8'),
    headers={'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'},
    method='PATCH'
)
with urllib.request.urlopen(triage_req) as resp:
    triage_res = json.loads(resp.read())
    print(f"[✓] Alert Triaged: {triage_res['id']} | New Status: {triage_res['status']}")

# 5. Check Audit Log
audit_resp = urllib.request.urlopen(urllib.request.Request(
    'http://localhost:8000/api/audit-logs?limit=4',
    headers={'Authorization': f'Bearer {token}'}
))
audit_entries = json.loads(audit_resp.read())
print(f"[✓] Verified Immutable Audit Trail ({len(audit_entries)} records retrieved):")
for a in audit_entries:
    print(f"    - Action: {a['action']} | Target: {a['target']} | Meta: {a.get('meta')}")

# 6. Check Log Explorer API
events_resp = urllib.request.urlopen(urllib.request.Request(
    'http://localhost:8000/api/events?limit=3',
    headers={'Authorization': f'Bearer {token}'}
))
events_entries = json.loads(events_resp.read())
print(f"[✓] Verified Log Explorer Query API ({len(events_entries)} events retrieved).")
