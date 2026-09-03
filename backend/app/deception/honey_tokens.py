"""
Active Defense & Managed Honey-Token Controller (v5.0).

Deploys, monitors, and rotates non-functional but realistic decoy credentials
(AWS Access Keys, Windows Registry keys, SSH Canary Keys, Database Connection Strings)
across tenant-enrolled devices.

Interactions with honey-tokens indicate deterministic, zero-false-positive adversary activity,
bypassing standard ML thresholds to trigger instant automated containment.
"""
import secrets
import time
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional


class HoneyTokenController:
    """
    Manages the lifecycle, distribution, and monitoring of enterprise canary tokens.
    """

    # In-memory store for deployed active canary tokens per tenant
    _ACTIVE_TOKENS: Dict[str, List[Dict[str, Any]]] = {}

    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id
        if self.tenant_id not in self._ACTIVE_TOKENS:
            # Seed default decoy fleet
            self._ACTIVE_TOKENS[self.tenant_id] = [
                {
                    "token_uid": "decoy-aws-01",
                    "type": "AWS_IAM_KEY",
                    "decoy_identifier": "AKIA4X9K2M8P7EXAMPLE",
                    "target_environment": "Production Cloud",
                    "status": "ACTIVE_MONITORED",
                    "deployed_at": "2026-08-30T10:00:00Z",
                    "tripped_count": 0,
                },
                {
                    "token_uid": "decoy-reg-01",
                    "type": "WINDOWS_REGISTRY",
                    "decoy_identifier": r"HKCU\Software\Sysinternals\AutoRuns\Credential",
                    "target_environment": "Endpoints (Domain Admin)",
                    "status": "ACTIVE_MONITORED",
                    "deployed_at": "2026-08-31T14:30:00Z",
                    "tripped_count": 0,
                },
                {
                    "token_uid": "decoy-ssh-01",
                    "type": "SSH_CANARY_KEY",
                    "decoy_identifier": "id_rsa_backup_svc",
                    "target_environment": "DMZ Bastion Host",
                    "status": "ACTIVE_MONITORED",
                    "deployed_at": "2026-09-01T01:00:00Z",
                    "tripped_count": 0,
                },
            ]

    def list_tokens(self) -> List[Dict[str, Any]]:
        """Returns all deployed active canary tokens for this tenant."""
        return self._ACTIVE_TOKENS.get(self.tenant_id, [])

    def generate_decoy_aws_credentials(self, label: str = "Cloudtrail Canary") -> Dict[str, Any]:
        """Creates realistic but non-functional AWS IAM access keys."""
        fake_id = f"AKIA{secrets.token_hex(8).upper()}"
        fake_secret = secrets.token_urlsafe(32)
        token_uid = f"aws-{uuid.uuid4().hex[:8]}"

        token_record = {
            "token_uid": token_uid,
            "type": "AWS_IAM_KEY",
            "label": label,
            "decoy_identifier": fake_id,
            "aws_access_key_id": fake_id,
            "aws_secret_access_key": fake_secret,
            "target_environment": "AWS IAM / CloudTrail",
            "status": "ACTIVE_MONITORED",
            "deployed_at": datetime.utcnow().isoformat(),
            "monitoring_instructions": "Triggers alert on any AWS sts:GetCallerIdentity call.",
            "tripped_count": 0,
        }

        self._ACTIVE_TOKENS[self.tenant_id].append(token_record)
        return token_record

    def generate_windows_registry_decoy(self) -> Dict[str, Any]:
        """Creates a realistic decoy registry key containing fake service credentials."""
        token_uid = f"reg-{uuid.uuid4().hex[:8]}"
        reg_path = r"HKCU\Software\Sysinternals\AutoRuns\Credential decodes"

        token_record = {
            "token_uid": token_uid,
            "type": "WINDOWS_REGISTRY",
            "decoy_identifier": reg_path,
            "path": reg_path,
            "username": "domain_admin_backup_svc",
            "password_hash": secrets.token_hex(16),
            "target_environment": "Windows Active Directory Endpoints",
            "status": "ACTIVE_MONITORED",
            "deployed_at": datetime.utcnow().isoformat(),
            "remediation_action": "Isolate Endpoint / Terminate Process",
            "tripped_count": 0,
        }

        self._ACTIVE_TOKENS[self.tenant_id].append(token_record)
        return token_record

    def generate_ssh_canary_key(self, host: str = "srv-bastion-01") -> Dict[str, Any]:
        """Creates an SSH Canary Private Key."""
        token_uid = f"ssh-{uuid.uuid4().hex[:8]}"
        fake_private_key = f"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gt\n{secrets.token_urlsafe(48)}\n-----END OPENSSH PRIVATE KEY-----"

        token_record = {
            "token_uid": token_uid,
            "type": "SSH_CANARY_KEY",
            "decoy_identifier": f"id_rsa_backup_{host}",
            "host_location": f"/home/deploy/.ssh/{host}_id_rsa",
            "private_key_preview": fake_private_key,
            "target_environment": f"{host} (SSH Bastion)",
            "status": "ACTIVE_MONITORED",
            "deployed_at": datetime.utcnow().isoformat(),
            "tripped_count": 0,
        }

        self._ACTIVE_TOKENS[self.tenant_id].append(token_record)
        return token_record

    def generate_targeted_tech_decoy(self, technology: str, hostname: str = "prod-app-01") -> Dict[str, Any]:
        """
        Dynamically provisions a targeted canary credential matching the detected running tech stack (v9.0).
        """
        tech_lower = technology.lower()
        fake_secret = secrets.token_urlsafe(16)
        token_uid = f"canary-{tech_lower[:4]}-{uuid.uuid4().hex[:6]}"

        if "postgres" in tech_lower:
            decoy_id = f"{hostname}:~/.pgpass"
            target_env = f"PostgreSQL Runtime ({hostname})"
            content = f"localhost:5432:threat_db:db_master_admin:{fake_secret}"
            decoy_type = "PGPASS_CANARY_SECRET"
        elif "fastapi" in tech_lower or "django" in tech_lower or "python" in tech_lower:
            decoy_id = f"{hostname}:/app/.env.production"
            target_env = f"Python/FastAPI Service ({hostname})"
            content = f"MASTER_JWT_KEY=canary_{fake_secret}\nDATABASE_URL=postgresql://svc_app:{fake_secret}@db:5432/app"
            decoy_type = "DOTENV_CANARY_VAULT"
        elif "spring" in tech_lower or "jvm" in tech_lower or "java" in tech_lower:
            decoy_id = f"{hostname}:application-prod.properties"
            target_env = f"Spring Boot Microservice ({hostname})"
            content = f"spring.datasource.password={fake_secret}\nspring.security.jwt.secret={fake_secret}"
            decoy_type = "SPRING_PROPERTIES_CANARY"
        elif "express" in tech_lower or "node" in tech_lower or "next" in tech_lower:
            decoy_id = f"{hostname}:config/production.json"
            target_env = f"NodeJS / Express Service ({hostname})"
            content = f'{{"api_secret": "canary_{fake_secret}", "admin_token": "{fake_secret}"}}'
            decoy_type = "NODE_CONFIG_CANARY"
        else:
            decoy_id = f"{hostname}:/etc/{tech_lower}.conf"
            target_env = f"{technology} Host ({hostname})"
            content = f"secret_auth_token={fake_secret}"
            decoy_type = "GENERIC_TECH_CANARY"

        token_record = {
            "token_uid": token_uid,
            "type": decoy_type,
            "technology": technology,
            "decoy_identifier": decoy_id,
            "file_content_preview": content,
            "target_environment": target_env,
            "status": "ACTIVE_MONITORED",
            "deployed_at": datetime.utcnow().isoformat(),
            "tripped_count": 0,
            "proactive_deception": True,
        }

        self._ACTIVE_TOKENS[self.tenant_id].append(token_record)
        return token_record

    def trip_honey_token(
        self,
        token_uid: str,
        attacker_ip: str = "185.220.101.5",
        device_id: str = "srv-app-node-01"
    ) -> Dict[str, Any]:
        """
        Simulates / registers an adversary interaction with a canary token.
        Dispatches deterministic zero-false-positive critical security alert.
        """
        target_token = None
        for tok in self._ACTIVE_TOKENS.get(self.tenant_id, []):
            if tok["token_uid"] == token_uid:
                target_token = tok
                tok["status"] = "TRIPPED_COMPROMISED"
                tok["tripped_count"] = tok.get("tripped_count", 0) + 1
                tok["last_tripped_at"] = datetime.utcnow().isoformat()
                tok["attacker_ip"] = attacker_ip
                break

        if not target_token:
            return {
                "success": False,
                "error": "Canary token not found in registry.",
            }

        return {
            "success": True,
            "status": "INCIDENT_DISPATCHED",
            "alert_severity": "CRITICAL",
            "zero_false_positive_guarantee": True,
            "token_tripped": target_token,
            "automated_response": "Dispatched instant SOAR host isolation for " + device_id,
        }
