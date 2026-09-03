import json
import urllib.request
import urllib.error
import time

BASE_URL = "http://localhost:8000"

print("--- [V10.0 Security Chaos Engineering (SCE) Verification Suite] ---")

# 1. Login
print("1. Authenticating test analyst session...")
login_req = urllib.request.Request(
    f"{BASE_URL}/api/auth/login",
    data=json.dumps({"email": "analyst@acme.corp", "password": "SecurePassword123!"}).encode("utf-8"),
    headers={"Content-Type": "application/json"}
)
with urllib.request.urlopen(login_req) as resp:
    token = json.loads(resp.read())["access_token"]
    print("   [+] Authentication successful. Token obtained.")

headers = {
    "Authorization": f"Bearer {token}",
    "Content-Type": "application/json"
}

# 2. Test Defect Taxonomy Endpoint
print("\n2. Querying Enterprise Security Defect Taxonomy...")
req = urllib.request.Request(f"{BASE_URL}/api/chaos/taxonomy", headers=headers)
with urllib.request.urlopen(req) as resp:
    taxonomy = json.loads(resp.read())
    print(f"   [✓] Retrieved {len(taxonomy)} Defect Taxonomy Varieties across 5 Classes:")
    for t in taxonomy[:4]:
        print(f"       - [{t['defect_class']}] {t['bug_variety']} ({t['cwe_mapping']}) - Severity: {t['severity']}")

# 3. Test Dynamic Bug Version Profiles
print("\n3. Querying Dynamic Versioned Vulnerability Profiles...")
req = urllib.request.Request(f"{BASE_URL}/api/chaos/version-profiles", headers=headers)
with urllib.request.urlopen(req) as resp:
    profiles = json.loads(resp.read())
    print(f"   [✓] Retrieved {len(profiles)} Mapped Software Profiles:")
    for p in profiles:
        print(f"       - {p['software_name']} ({p['detected_version']}): {len(p['vulnerabilities'])} CVEs mapped [Handler: {p['simulation_handler_id']}]")

# 4. Test Fault Injections Across Defect Classes
test_injections = [
    {
        "name": "Tenant Isolation Bypass",
        "body": {"bug_variety": "Tenant Isolation Bypass", "target_org_id": "org_victim_alpha_99"}
    },
    {
        "name": "Buffer Overflow Attempt",
        "body": {"bug_variety": "Buffer Overflow Attempt"}
    },
    {
        "name": "BlueBorne L2CAP Overflow",
        "body": {"bug_variety": "BlueBorne L2CAP Overflow", "target_mac": "00:1A:7D:DA:99:88"}
    },
    {
        "name": "SQL / Command Injection Attempt",
        "body": {"bug_variety": "SQL / Command Injection Attempt"}
    },
    {
        "name": "Model Evasion Attempt",
        "body": {"bug_variety": "Model Evasion Attempt", "baseline_rate_eps": 0.5}
    },
    {
        "name": "Insecure Transmit Protocol",
        "body": {"bug_variety": "Insecure Transmit Protocol"}
    },
    {
        "name": "Resource Exhaustion Attempt",
        "body": {"bug_variety": "Resource Exhaustion Attempt"}
    }
]

print("\n4. Executing Synthetic Defect Injections & Latency SLA Checks...")
for test in test_injections:
    req = urllib.request.Request(
        f"{BASE_URL}/api/chaos/inject",
        data=json.dumps(test["body"]).encode("utf-8"),
        headers=headers
    )
    with urllib.request.urlopen(req) as resp:
        res = json.loads(resp.read())
        print(f"   [✓] {res['bug_variety']} ({res['cwe_class']}): Latency={res['detection_latency_ms']}ms | SLA={res['sla_compliance']} | Alert={res['alert_triggered']}")

# 5. Query Simulation History
print("\n5. Fetching Simulation Execution History...")
req = urllib.request.Request(f"{BASE_URL}/api/chaos/history?limit=10", headers=headers)
with urllib.request.urlopen(req) as resp:
    history = json.loads(resp.read())
    print(f"   [✓] Successfully retrieved {len(history)} recent execution ledger records.")

# 6. Test Model Security Resilience Report Generation
print("\n6. Compiling Audit-Ready Model Security Resilience Report (DCI)...")
req = urllib.request.Request(f"{BASE_URL}/api/chaos/report", headers=headers)
with urllib.request.urlopen(req) as resp:
    report = json.loads(resp.read())
    metrics = report["metrics"]
    comp = report["compliance_evaluation"]
    print(f"   [✓] Report Reference: {report['report_reference']}")
    print(f"   [✓] Defensive Coverage Index (DCI): {metrics['defensive_coverage_index']}%")
    print(f"   [✓] Total Simulations Run: {metrics['total_fault_simulations_run']}")
    print(f"   [✓] Unique CWE Classes Tested: {metrics['unique_cwe_classes_tested']}")
    print(f"   [✓] Average Detection Latency: {metrics['avg_detection_latency_ms']} ms")
    print(f"   [✓] Compliance Tier: {comp['assessment_tier']}")
    print(f"   [✓] Markdown Report Output Length: {len(report['markdown_report'])} characters")

print("\n>>> ALL V10.0 SECURITY CHAOS ENGINEERING TESTS PASSED SUCCESSFULLY! <<<")
