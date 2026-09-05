"""
Version 25: Real-Time MITRE ATT&CK Matrix Mapping & Heatmap Engine
Maps OCSF Class IDs (3002, 1007, 4001, 1001) and raw telemetry indicators
to MITRE ATT&CK Tactics and Techniques, and aggregates real-time heatmaps.
"""

from typing import Dict, Any, List, Optional
import re
from datetime import datetime

MITRE_TACTICS = {
    "TA0001": {"id": "TA0001", "name": "Initial Access", "order": 1},
    "TA0002": {"id": "TA0002", "name": "Execution", "order": 2},
    "TA0003": {"id": "TA0003", "name": "Persistence", "order": 3},
    "TA0004": {"id": "TA0004", "name": "Privilege Escalation", "order": 4},
    "TA0005": {"id": "TA0005", "name": "Defense Evasion", "order": 5},
    "TA0006": {"id": "TA0006", "name": "Credential Access", "order": 6},
    "TA0007": {"id": "TA0007", "name": "Discovery", "order": 7},
    "TA0008": {"id": "TA0008", "name": "Lateral Movement", "order": 8},
    "TA0009": {"id": "TA0009", "name": "Collection", "order": 9},
    "TA0010": {"id": "TA0010", "name": "Exfiltration", "order": 10},
    "TA0011": {"id": "TA0011", "name": "Command and Control", "order": 11},
    "TA0040": {"id": "TA0040", "name": "Impact", "order": 12},
}

MITRE_TECHNIQUES = {
    "T1190": {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic_id": "TA0001",
        "ocsf_class_id": 4001,
        "severity_weight": 85.0,
        "keywords": ["sql injection", "cve-", "exploit", "path traversal", "rce", "/etc/passwd", "' or 1=1"]
    },
    "T1566": {
        "id": "T1566",
        "name": "Phishing",
        "tactic_id": "TA0001",
        "ocsf_class_id": 4001,
        "severity_weight": 70.0,
        "keywords": ["phish", "invoice.zip", "dmarc_fail", "spoofed", "suspicious_domain"]
    },
    "T1078": {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic_id": "TA0001",
        "ocsf_class_id": 3002,
        "severity_weight": 65.0,
        "keywords": ["unusual_login", "geo_improbable", "vpn_anomalous", "root_login"]
    },
    "T1059": {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic_id": "TA0002",
        "ocsf_class_id": 1007,
        "severity_weight": 75.0,
        "keywords": ["powershell", "cmd.exe", "bash -i", "sh -c", "wscript", "python -c"]
    },
    "T1055": {
        "id": "T1055",
        "name": "Process Injection",
        "tactic_id": "TA0004",
        "ocsf_class_id": 1007,
        "severity_weight": 85.0,
        "keywords": ["virtualallocex", "createremotethread", "ptrace", "process_hollow", "reflective_dll"]
    },
    "T1003": {
        "id": "T1003",
        "name": "OS Credential Dumping",
        "tactic_id": "TA0006",
        "ocsf_class_id": 3002,
        "severity_weight": 90.0,
        "keywords": ["lsass.exe", "mimikatz", "sekurlsa", "sam_dump", "/etc/shadow", "ntds.dit"]
    },
    "T1083": {
        "id": "T1083",
        "name": "File and Directory Discovery",
        "tactic_id": "TA0007",
        "ocsf_class_id": 1001,
        "severity_weight": 45.0,
        "keywords": ["dir /s", "find /", "ls -la /root", "tree", "enum_shares"]
    },
    "T1041": {
        "id": "T1041",
        "name": "Exfiltration Over C2 Channel",
        "tactic_id": "TA0010",
        "ocsf_class_id": 4001,
        "severity_weight": 80.0,
        "keywords": ["large_egress", "c2_upload", "mega.nz", "dropbox_sync", "pastebin_post", "dns_tunnel"]
    },
    "T1071": {
        "id": "T1071",
        "name": "Application Layer Protocol",
        "tactic_id": "TA0011",
        "ocsf_class_id": 4001,
        "severity_weight": 60.0,
        "keywords": ["beacon", "heartbeat_c2", "tor_traffic", "unusual_user_agent", "doh_tunnel"]
    },
    "T1486": {
        "id": "T1486",
        "name": "Data Encrypted for Impact",
        "tactic_id": "TA0040",
        "ocsf_class_id": 1001,
        "severity_weight": 95.0,
        "keywords": ["ransom", "encrypt_batch", ".locked", "vssadmin delete shadows", "wbadmin delete"]
    }
}


class MitreMapper:
    @classmethod
    def map_event(cls, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluates event attributes, OCSF class ID, and payload to map to MITRE ATT&CK.
        """
        ocsf_class = event.get("ocsf_class_id") or event.get("class_id") or 4001
        try:
            ocsf_class = int(ocsf_class)
        except (ValueError, TypeError):
            ocsf_class = 4001

        raw_text = (
            str(event.get("message", "")) + " " +
            str(event.get("command", "")) + " " +
            str(event.get("process_name", "")) + " " +
            str(event.get("payload", "")) + " " +
            str(event.get("uri", "")) + " " +
            str(event.get("technique_id", ""))
        ).lower()

        explicit_tech = event.get("technique_id")
        if explicit_tech and explicit_tech.upper() in MITRE_TECHNIQUES:
            tech = MITRE_TECHNIQUES[explicit_tech.upper()]
            tactic = MITRE_TACTICS.get(tech["tactic_id"], {"id": tech["tactic_id"], "name": "General"})
            return {
                "technique_id": tech["id"],
                "technique_name": tech["name"],
                "tactic_id": tactic["id"],
                "tactic_name": tactic["name"],
                "ocsf_class_id": tech["ocsf_class_id"],
                "severity_weight": tech["severity_weight"],
                "match_reason": f"Explicit technique identifier {explicit_tech.upper()}"
            }

        # Match by keywords and OCSF class
        best_match = None
        highest_score = 0.0

        for tech_id, tech_info in MITRE_TECHNIQUES.items():
            score = 0.0
            if tech_info["ocsf_class_id"] == ocsf_class:
                score += 20.0
            
            for kw in tech_info["keywords"]:
                if kw in raw_text:
                    score += 40.0
            
            if score > highest_score:
                highest_score = score
                best_match = tech_info

        # Default fallback based on OCSF class
        if not best_match:
            if ocsf_class == 3002:
                best_match = MITRE_TECHNIQUES["T1003"]
            elif ocsf_class == 1007:
                best_match = MITRE_TECHNIQUES["T1059"]
            elif ocsf_class == 1001:
                best_match = MITRE_TECHNIQUES["T1083"]
            else:
                best_match = MITRE_TECHNIQUES["T1190"]

        tactic = MITRE_TACTICS.get(best_match["tactic_id"], {"id": best_match["tactic_id"], "name": "General"})

        return {
            "technique_id": best_match["id"],
            "technique_name": best_match["name"],
            "tactic_id": tactic["id"],
            "tactic_name": tactic["name"],
            "ocsf_class_id": best_match["ocsf_class_id"],
            "severity_weight": best_match["severity_weight"],
            "match_reason": f"Heuristic match on OCSF class {ocsf_class} and telemetry indicators"
        }

    @classmethod
    def generate_matrix_heatmap(cls, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Builds matrix heatmap data grouped by MITRE Tactics and Techniques.
        """
        tactics_summary = {
            t_id: {
                "tactic_id": t_id,
                "tactic_name": t_data["name"],
                "order": t_data["order"],
                "alert_count": 0,
                "critical_count": 0,
                "high_count": 0,
                "avg_priority_score": 0.0,
                "techniques": {}
            }
            for t_id, t_data in MITRE_TACTICS.items()
        }

        # Initialize techniques in tactic summaries
        for tech_id, tech in MITRE_TECHNIQUES.items():
            t_id = tech["tactic_id"]
            if t_id in tactics_summary:
                tactics_summary[t_id]["techniques"][tech_id] = {
                    "technique_id": tech_id,
                    "technique_name": tech["name"],
                    "ocsf_class_id": tech["ocsf_class_id"],
                    "severity_weight": tech["severity_weight"],
                    "count": 0,
                    "max_priority_score": 0.0,
                    "latest_alert_timestamp": None
                }

        total_alerts = len(alerts)
        total_score_sum = 0.0

        for a in alerts:
            t_id = a.get("tactic_id", "TA0001")
            tech_id = a.get("technique_id", "T1190")
            score = float(a.get("priority_score", 0.0))
            level = a.get("priority_level", "LOW")
            created_at = a.get("created_at")

            total_score_sum += score

            if t_id in tactics_summary:
                tac = tactics_summary[t_id]
                tac["alert_count"] += 1
                if level == "CRITICAL":
                    tac["critical_count"] += 1
                elif level == "HIGH":
                    tac["high_count"] += 1

                if tech_id in tac["techniques"]:
                    tech_node = tac["techniques"][tech_id]
                    tech_node["count"] += 1
                    tech_node["max_priority_score"] = max(tech_node["max_priority_score"], score)
                    tech_node["latest_alert_timestamp"] = created_at or datetime.utcnow().isoformat()

        # Compute averages and format matrix list
        sorted_tactics = sorted(tactics_summary.values(), key=lambda x: x["order"])
        for tac in sorted_tactics:
            if tac["alert_count"] > 0:
                # Calculate average across techniques
                tech_scores = [t["max_priority_score"] for t in tac["techniques"].values() if t["count"] > 0]
                tac["avg_priority_score"] = round(sum(tech_scores) / len(tech_scores), 2) if tech_scores else 0.0
            tac["techniques_list"] = list(tac["techniques"].values())

        return {
            "total_alerts": total_alerts,
            "overall_avg_priority": round(total_score_sum / total_alerts, 2) if total_alerts > 0 else 0.0,
            "matrix": sorted_tactics,
            "generated_at": datetime.utcnow().isoformat()
        }
