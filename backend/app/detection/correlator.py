import datetime
from typing import List, Dict, Any, Optional


class SecurityCorrelationEngine:
    """
    Correlates individual OCSF security alerts and telemetry into multi-stage threat cases
    mapped directly to the MITRE ATT&CK enterprise matrix.
    Computes time-decayed asset risk scores across sliding 60-minute windows.
    """
    SEVERITY_WEIGHTS = {
        "low": 10,
        "medium": 25,
        "high": 50,
        "critical": 90,
    }

    def __init__(self, tenant_id: str, sliding_window_minutes: int = 60, decay_factor: float = 0.95):
        self.tenant_id = tenant_id
        self.window_size = datetime.timedelta(minutes=sliding_window_minutes)
        self.decay_factor = decay_factor
        # Entity graph tracking alerts mapped by asset: { asset_key: [alert_dict] }
        self.active_entities: Dict[str, List[Dict[str, Any]]] = {}

    def ingest_alert(self, alert: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Processes a single security alert, maps it to affected assets,
        and generates correlated parent alerts if multi-stage threshold patterns are identified.
        """
        evidence = alert.get("evidence") or {}
        ocsf = evidence.get("ocsf") or {}
        
        # Determine primary asset key (hostname, device_id, or src_ip)
        affected_host = (
            alert.get("device_id")
            or ocsf.get("device", {}).get("hostname")
            or evidence.get("src_ip")
            or "global-asset"
        )
        
        now = datetime.datetime.utcnow()
        if affected_host not in self.active_entities:
            self.active_entities[affected_host] = []

        # Prune expired alerts from sliding window
        self.active_entities[affected_host] = [
            a for a in self.active_entities[affected_host]
            if (now - a.get("detected_at", now)) < self.window_size
        ]

        # Register alert with normalized metadata
        alert_record = {
            "id": alert.get("id"),
            "title": alert.get("title", ""),
            "severity": alert.get("severity", "medium"),
            "description": alert.get("description", ""),
            "class_uid": ocsf.get("class_uid") or alert.get("class_uid"),
            "device_id": alert.get("device_id"),
            "evidence": evidence,
            "detected_at": now,
        }
        self.active_entities[affected_host].append(alert_record)

        # Evaluate correlation relationships
        return self._evaluate_relationships(affected_host)

    def compute_asset_risk_score(self, hostname: str) -> float:
        """
        Calculates time-decayed compound asset risk score:
        Asset Risk = min(100, sum(severity_weight * time_decay))
        """
        alerts = self.active_entities.get(hostname, [])
        if not alerts:
            return 0.0

        now = datetime.datetime.utcnow()
        total_score = 0.0

        for a in alerts:
            sev = str(a.get("severity", "medium")).lower()
            weight = self.SEVERITY_WEIGHTS.get(sev, 25)
            dt_hours = (now - a["detected_at"]).total_seconds() / 3600.0
            decay = self.decay_factor ** max(0.0, dt_hours)
            total_score += weight * decay

        return min(100.0, round(total_score, 1))

    def _evaluate_relationships(self, hostname: str) -> List[Dict[str, Any]]:
        """
        Identifies multi-stage kill chain patterns across the asset's active alerts:
        - Pattern 1: Auth Failure (3002) -> Process Execution (1007) [Lateral Movement / Privilege Escalation]
        - Pattern 2: Process Execution (1007) -> Network C2 Egress (4001) [Command & Control]
        - Pattern 3: Sudo Privilege Escalation (3001) -> Sensitive File Access [Privilege Abuse]
        - Pattern 4: High Density of Critical Anomalies [Compromise Critical Incident]
        """
        alerts = self.active_entities.get(hostname, [])
        if len(alerts) < 2:
            return []

        classes_present = {a.get("class_uid") for a in alerts if a.get("class_uid")}
        correlated_cases = []
        asset_risk = self.compute_asset_risk_score(hostname)

        # Pattern 1: SSH Brute Force -> Process Execution (Lateral Movement)
        if 3002 in classes_present and 1007 in classes_present:
            auth_alerts = [a for a in alerts if a.get("class_uid") == 3002]
            proc_alerts = [a for a in alerts if a.get("class_uid") == 1007]

            if auth_alerts and proc_alerts:
                correlated_cases.append({
                    "org_id": self.tenant_id,
                    "title": f"Compound Incident: Lateral Movement & Compromise Sequence ({hostname})",
                    "severity": "critical",
                    "mitre_tactic": "TA0008 - Lateral Movement",
                    "mitre_technique": "T1078 - Valid Accounts / T1059 - Command and Scripting Interpreter",
                    "description": f"Multiple authentication failures on host {hostname} were immediately followed by process execution.",
                    "evidence": {
                        "compound_risk_score": asset_risk,
                        "correlated_asset": hostname,
                        "auth_alerts_count": len(auth_alerts),
                        "process_alerts_count": len(proc_alerts),
                        "child_alert_ids": [a.get("id") for a in alerts if a.get("id")],
                        "mitre_mapping": {
                            "tactic": "TA0008 - Lateral Movement",
                            "phases": ["Initial Access / Credential Spray", "Execution"],
                        }
                    }
                })

        # Pattern 2: Process Activity (1007) -> C2 Network Activity (4001)
        if 1007 in classes_present and 4001 in classes_present:
            proc_alerts = [a for a in alerts if a.get("class_uid") == 1007]
            net_alerts = [a for a in alerts if a.get("class_uid") == 4001]

            if proc_alerts and net_alerts:
                correlated_cases.append({
                    "org_id": self.tenant_id,
                    "title": f"Compound Incident: Multi-Stage C2 Beaconing & Payload Execution ({hostname})",
                    "severity": "critical",
                    "mitre_tactic": "TA0011 - Command and Control",
                    "mitre_technique": "T1071 - Application Layer Protocol / T1059 - PowerShell Execution",
                    "description": f"Process execution coincided with outbound Command & Control network egress on {hostname}.",
                    "evidence": {
                        "compound_risk_score": asset_risk,
                        "correlated_asset": hostname,
                        "process_alerts_count": len(proc_alerts),
                        "network_alerts_count": len(net_alerts),
                        "child_alert_ids": [a.get("id") for a in alerts if a.get("id")],
                        "mitre_mapping": {
                            "tactic": "TA0011 - Command and Control",
                            "phases": ["Execution", "Command & Control Egress"],
                        }
                    }
                })

        # Pattern 3: High Compound Asset Risk Threshold (> 80 score)
        if asset_risk >= 80 and not correlated_cases:
            correlated_cases.append({
                "org_id": self.tenant_id,
                "title": f"High Compound Threat Density on Asset ({hostname})",
                "severity": "critical",
                "mitre_tactic": "TA0004 - Privilege Escalation",
                "mitre_technique": "T1068 - Exploitation for Privilege Escalation",
                "description": f"Cumulative asset risk score ({asset_risk}/100) exceeded containment threshold within sliding window.",
                "evidence": {
                    "compound_risk_score": asset_risk,
                    "correlated_asset": hostname,
                    "incident_count": len(alerts),
                    "child_alert_ids": [a.get("id") for a in alerts if a.get("id")],
                }
            })

        return correlated_cases
