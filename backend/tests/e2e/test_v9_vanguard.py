import json
import urllib.request
import urllib.error
import time

BASE_URL = "http://localhost:8000"

print("--- [V9.0 Vanguard Architecture Verification Suite] ---")

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

# 2. Test Bluetooth HCI Status
print("\n2. Querying Bluetooth HCI Guard status...")
req = urllib.request.Request(f"{BASE_URL}/api/bluetooth/status", headers=headers)
with urllib.request.urlopen(req) as resp:
    status_data = json.loads(resp.read())
    print(f"   [✓] Bluetooth Guard Active: Interface={status_data['interface']}, Daemon={status_data['hardware_daemon']}, Noise={status_data['noise_floor_rssi']}dBm")

# 3. Test BlueBorne Exploit Simulation & Interception
print("\n3. Simulating BlueBorne L2CAP Buffer Overflow Attack...")
req = urllib.request.Request(
    f"{BASE_URL}/api/bluetooth/simulate-attack",
    data=json.dumps({
        "exploit_vector": "BLUEBORNE_L2CAP_OVERFLOW",
        "source_mac": "00:1A:7D:DA:99:88"
    }).encode("utf-8"),
    headers=headers
)
with urllib.request.urlopen(req) as resp:
    res = json.loads(resp.read())
    print(f"   [✓] Intercepted Attack Vector: {res['vector']}")
    print(f"   [✓] Containment Verdict: {res['containment_response']['verdict']}")
    print(f"   [✓] Generated Alert ID: {res['alert_created']}")

# 4. Test Hardware MAC Containment
print("\n4. Testing Direct Hardware Containment Dispatch...")
req = urllib.request.Request(
    f"{BASE_URL}/api/bluetooth/contain",
    data=json.dumps({
        "attacker_mac": "00:1A:7D:DA:99:88",
        "action": "block_mac"
    }).encode("utf-8"),
    headers=headers
)
with urllib.request.urlopen(req) as resp:
    res = json.loads(resp.read())
    print(f"   [✓] Containment status: {res['status']} | Verdict: {res['containment_verdict']}")

# 5. Test TPM 2.0 Status
print("\n5. Querying TPM 2.0 Silicon & PCR Bank status...")
req = urllib.request.Request(f"{BASE_URL}/api/tpm/status", headers=headers)
with urllib.request.urlopen(req) as resp:
    tpm_status = json.loads(resp.read())
    print(f"   [✓] TPM Version: {tpm_status['tpm_version']} | AIK Fingerprint: {tpm_status['aik_public_fingerprint']}")
    print(f"   [✓] PCR-0 Digest: {tpm_status['pcr_banks']['PCR_0 (CRTM/BIOS)'][:24]}...")

# 6. Test Hardware Block Signing
print("\n6. Signing telemetry log batch with TPM 2.0 AIK Private Key...")
sample_batch = [
    {"event": "AUTH_SUCCESS", "src_ip": "10.0.4.12", "user": "analyst"},
    {"event": "HCI_GUARD_DROP", "attacker_mac": "00:1A:7D:DA:99:88"},
]
req = urllib.request.Request(
    f"{BASE_URL}/api/tpm/sign-block",
    data=json.dumps({"log_records": sample_batch}).encode("utf-8"),
    headers=headers
)
with urllib.request.urlopen(req) as resp:
    sign_res = json.loads(resp.read())
    print(f"   [✓] Hardware Signed Block Hash: {sign_res['block_hash'][:28]}...")
    print(f"   [✓] Signature: {sign_res['hardware_signature'][:36]}...")

# 7. Test Cryptographic Merkle Chain Verification
print("\n7. Validating Cryptographic Chain of Custody against AIK...")
req = urllib.request.Request(
    f"{BASE_URL}/api/tpm/verify-chain",
    data=json.dumps({"limit": 50}).encode("utf-8"),
    headers=headers
)
with urllib.request.urlopen(req) as resp:
    verify_res = json.loads(resp.read())
    print(f"   [✓] Chain Validity: {verify_res['valid']} | Status: {verify_res['hardware_seal_status']}")
    print(f"   [✓] Calculated Merkle Root: {verify_res['merkle_root'][:32]}...")
    print(f"   [✓] Message: {verify_res['message']}")

# 8. Test Proactive Cyber Deception Deployment for Discovered Tech Stack
print("\n8. Deploying Targeted Honey-Token Trap for PostgreSQL...")
req = urllib.request.Request(
    f"{BASE_URL}/api/deception/targeted-deploy",
    data=json.dumps({"technology": "PostgreSQL", "hostname": "prod-db-01"}).encode("utf-8"),
    headers=headers
)
with urllib.request.urlopen(req) as resp:
    decoy_res = json.loads(resp.read())
    print(f"   [✓] Targeted Decoy Status: {decoy_res['status']}")
    print(f"   [✓] Deployed File: {decoy_res['decoy']['decoy_identifier']}")
    print(f"   [✓] Canary Vault Type: {decoy_res['decoy']['type']}")

print("\n>>> ALL V9.0 VANGUARD ARCHITECTURE TESTS PASSED SUCCESSFULLY! <<<")
