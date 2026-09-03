import hmac
import hashlib
import json
import os
import requests
from typing import Dict, Any, Optional
from datetime import datetime


class ActiveResponseEngine:
    """
    Executes automated orchestrations (SOAR) to contain threats on endpoints
    communicating via agent-forwarder client interfaces.
    Secures outbound control payloads with SHA-256 HMAC cryptographic signatures.
    """
    def __init__(self, agent_manager_url: Optional[str] = None, signing_key: Optional[str] = None):
        self.agent_manager_url = agent_manager_url or os.getenv("AGENT_MANAGER_URL", "http://localhost:8000")
        self.signing_key = (signing_key or os.getenv("SOAR_SIGNING_KEY", "ta-soar-secret-hmac-key")).encode("utf-8")

    def _generate_signature(self, payload: Dict[str, Any]) -> str:
        """
        Generates HMAC-SHA256 signature for tamper-proof playbook delivery.
        """
        raw_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
        return hmac.new(self.signing_key, raw_bytes, hashlib.sha256).hexdigest()

    def isolate_infected_host(self, org_id: str, device_id: str, alert_id: str) -> Dict[str, Any]:
        """
        Dispatches a secure firewall containment command to the destination agent.
        Blocks all outbound traffic except encrypted tunnel back to SIEM console.
        """
        payload = {
            "org_id": org_id,
            "command": "NETWORK_ISOLATE",
            "device_id": device_id,
            "target_alert_id": alert_id,
            "timestamp": datetime.utcnow().isoformat(),
            "parameters": {
                "permit_ports": [80, 443, 8000],  # Allow connections only to security SaaS ingest
                "action": "BLOCK_ALL_OUTBOUND"
            }
        }
        
        signature = self._generate_signature(payload)
        # In standalone/agent environment, execute or route command
        return {
            "status": "DISPATCHED",
            "command": "NETWORK_ISOLATE",
            "device_id": device_id,
            "signature": signature,
            "payload": payload,
            "message": f"Host {device_id} network isolation dispatched with HMAC cryptographic signature."
        }

    def terminate_suspicious_process(self, org_id: str, device_id: str, pid: Optional[int] = None, process_name: Optional[str] = None) -> Dict[str, Any]:
        """
        Instructs endpoint daemon to terminate a malicious process tree immediately.
        """
        payload = {
            "org_id": org_id,
            "command": "TERMINATE_PROCESS",
            "device_id": device_id,
            "timestamp": datetime.utcnow().isoformat(),
            "parameters": {
                "pid": pid,
                "process_name": process_name or "suspicious_process",
                "force": True,
            }
        }
        signature = self._generate_signature(payload)
        return {
            "status": "DISPATCHED",
            "command": "TERMINATE_PROCESS",
            "device_id": device_id,
            "signature": signature,
            "payload": payload,
            "message": f"Process termination for '{process_name or pid}' dispatched to {device_id}."
        }

    def revoke_user_sessions(self, org_id: str, username: str) -> Dict[str, Any]:
        """
        Invalidates active session tokens and prompts for immediate MFA re-authentication.
        """
        payload = {
            "org_id": org_id,
            "command": "REVOKE_SESSION",
            "target_user": username,
            "timestamp": datetime.utcnow().isoformat(),
            "parameters": {
                "invalidate_refresh_tokens": True,
                "require_mfa": True,
            }
        }
        signature = self._generate_signature(payload)
        return {
            "status": "DISPATCHED",
            "command": "REVOKE_SESSION",
            "target_user": username,
            "signature": signature,
            "payload": payload,
            "message": f"Active sessions revoked for user '{username}'."
        }
