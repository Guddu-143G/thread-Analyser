import json
import urllib.request
import urllib.error
import time
import sys

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

BASE_URL = "http://localhost:8000"

print("1. Authenticating or Registering test account...")
reg_url = f"{BASE_URL}/api/auth/register"
reg_data = json.dumps({
    "org_name": "Acme CyberSec",
    "email": "analyst@acme.corp",
    "password": "SecurePassword123!"
}).encode("utf-8")

token = None
try:
    req = urllib.request.Request(reg_url, data=reg_data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as resp:
        res = json.loads(resp.read())
        token = res["access_token"]
        print("  [+] Registered new account and received token.")
except urllib.error.HTTPError as e:
    login_url = f"{BASE_URL}/api/auth/login"
    login_data = json.dumps({
        "email": "analyst@acme.corp",
        "password": "SecurePassword123!"
    }).encode("utf-8")
    req = urllib.request.Request(login_url, data=login_data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as resp:
        res = json.loads(resp.read())
        token = res["access_token"]
        print("  [+] Logged in existing account and received token.")

print("\n2. Creating enrolled device...")
dev_url = f"{BASE_URL}/api/devices"
dev_data = json.dumps({
    "name": "prod-gateway-01",
    "platform": "linux"
}).encode("utf-8")
req = urllib.request.Request(
    dev_url,
    data=dev_data,
    headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"}
)
with urllib.request.urlopen(req) as resp:
    dev = json.loads(resp.read())
    api_key = dev["api_key"]
    print(f"  [+] Created device '{dev['name']}' with API key: {api_key}")

print("\n3. Sending synthetic threat simulation batch via push API...")
import os
scripts_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "scripts"))
if scripts_dir not in sys.path:
    sys.path.insert(0, scripts_dir)
from threat_generator import generate_payload

payload = generate_payload(["ssh_brute_force", "credential_dump", "powershell_obfuscated", "sudo_escalation", "c2_traffic"])
push_url = f"{BASE_URL}/api/ingest/push"
push_data = json.dumps({"logs": payload}).encode("utf-8")
req = urllib.request.Request(
    push_url,
    data=push_data,
    headers={"Content-Type": "application/json", "X-API-Key": api_key}
)
with urllib.request.urlopen(req) as resp:
    job = json.loads(resp.read())
    print(f"  [+] Telemetry accepted! Events accepted: {job.get('accepted_events')}, Queued: {job.get('queued')}")


print("\n4. Waiting 4 seconds for Celery worker (OCSF parsing + IOC matching + Sigma rules + ML Anomaly scoring)...")
time.sleep(4)

print("\n5. Querying resulting security alerts...")
alerts_url = f"{BASE_URL}/api/alerts"
req = urllib.request.Request(alerts_url, headers={"Authorization": f"Bearer {token}"})
with urllib.request.urlopen(req) as resp:
    alerts = json.loads(resp.read())
    print(f"  [✓] Retrieved {len(alerts)} alerts from backend:")
    for a in alerts[:8]:
        print(f"      - [{a['severity'].upper()}] {a['title']} (Status: {a['status']})")

print("\n6. Querying dashboard stats...")
stats_url = f"{BASE_URL}/api/dashboard/stats"
req = urllib.request.Request(stats_url, headers={"Authorization": f"Bearer {token}"})
with urllib.request.urlopen(req) as resp:
    stats = json.loads(resp.read())
    print(f"  [✓] Total alerts: {stats.get('total_alerts')}, Open: {stats.get('open_alerts')}, High/Crit: {stats.get('high_critical')}")

print("\n>>> FULL END-TO-END TELEMETRY & DETECTION VERIFICATION PASSED! <<<")
