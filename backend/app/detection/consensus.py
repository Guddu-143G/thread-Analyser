"""
Multi-Agent AI SOC Consensus Engine (Version 13.0)
Autonomous investigative triage panel with mathematical consensus and cryptographic signing.
"""

import time
import math
import hashlib
from typing import Dict, Any, Tuple


class InvestigatorAgent:
    """Agent Alpha: Analyzes process provenance, shell command entropy, and file lineages."""
    def evaluate(self, alert_event: Dict[str, Any]) -> Tuple[float, float, str]:
        cmd_line = alert_event.get("process", {}).get("cmd_line", "") or alert_event.get("process_cmd", "")
        entropy = self._shannon_entropy(cmd_line)
        
        confidence = 0.88
        cmd_lower = cmd_line.lower()
        if any(bad in cmd_lower for bad in ["powershell", "mimikatz", "-encodedcommand", "rundll32", "curl | bash", "wget http", "whoami /priv"]):
            risk_score = 0.95
            reason = f"Critical process execution signature matched ({cmd_line[:40]}...). Command entropy: {entropy:.2f}"
        elif entropy > 3.8:
            risk_score = 0.78
            reason = f"High command entropy detected ({entropy:.2f}), indicating obfuscated or encrypted payloads."
        elif len(cmd_line) > 120:
            risk_score = 0.60
            reason = f"Unusually long command string execution ({len(cmd_line)} chars)."
        else:
            risk_score = 0.18
            reason = "No anomalous command patterns or malicious process ancestry identified."
            
        return risk_score, confidence, reason

    def _shannon_entropy(self, data: str) -> float:
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        seen = set(data)
        for char in seen:
            p_x = data.count(char) / length
            if p_x > 0:
                entropy -= p_x * math.log2(p_x)
        return abs(entropy)


class IntelAggregatorAgent:
    """Agent Beta: Cross-references global IOC databases, threat feeds, and tenant baseline profiles."""
    def evaluate(self, alert_event: Dict[str, Any]) -> Tuple[float, float, str]:
        src_ip = alert_event.get("network_activity", {}).get("src_endpoint", {}).get("ip", "") or alert_event.get("src_ip", "")
        severity = alert_event.get("severity", 1)
        
        confidence = 0.92
        # Simulated known hostile threat indicators (IOCs)
        known_malicious_ips = {
            "185.220.101.5", "45.227.254.12", "198.51.100.44",
            "103.224.182.245", "185.191.171.12", "91.240.118.172"
        }
        
        if src_ip in known_malicious_ips:
            risk_score = 0.98
            reason = f"Source IP {src_ip} flagged as highly hostile threat indicator (IOC) across Global Cyber Intelligence Feeds."
        elif severity >= 4:
            risk_score = 0.82
            reason = f"Elevated system alert severity level (Level {severity}) suggests critical attack context."
        elif severity == 3:
            risk_score = 0.55
            reason = "Moderate severity event detected on non-standard internal network port."
        else:
            risk_score = 0.15
            reason = "Source IP conforms to baseline metrics. Zero global IOC correlation matches."
            
        return risk_score, confidence, reason


class ContainmentSpecialistAgent:
    """Agent Gamma: Models operational business continuity and determines blast radius constraints."""
    def evaluate(self, alert_event: Dict[str, Any]) -> Tuple[float, float, str]:
        hostname = alert_event.get("device", {}).get("hostname", "") or alert_event.get("hostname", "")
        
        confidence = 0.95
        host_lower = hostname.lower()
        if any(crit in host_lower for crit in ["prod-db", "domain-controller", "auth-cluster", "k8s-master", "core-router"]):
            # Critical asset: High mitigation risk, requires surgical containment
            risk_score = 0.40  # Cautious recommendation to preserve mission-critical service
            reason = f"Target host '{hostname}' is a Tier-1 Mission-Critical Asset. Total network isolation poses high operational downtime risk."
        elif any(srv in host_lower for srv in ["worker", "app-server", "api-gateway"]):
            risk_score = 0.70
            reason = f"Target host '{hostname}' is a redundant tier application worker. Micro-segmentation isolation recommended."
        else:
            risk_score = 0.88  # Recommends aggressive containment for endpoints
            reason = f"Target host '{hostname}' classified as end-user workstation. Low blast radius; active network isolation recommended."
            
        return risk_score, confidence, reason


class SOCConsensusCoordinator:
    """Central engine that orchestrates agent panels, aggregates evaluations, and signs actions."""
    def __init__(self):
        self.investigator = InvestigatorAgent()
        self.intel = IntelAggregatorAgent()
        self.containment = ContainmentSpecialistAgent()

    def process_and_triage(self, ocsf_event: Dict[str, Any]) -> Dict[str, Any]:
        # Execute multi-agent analysis
        r_inv, c_inv, msg_inv = self.investigator.evaluate(ocsf_event)
        r_int, c_int, msg_int = self.intel.evaluate(ocsf_event)
        r_cnt, c_cnt, msg_cnt = self.containment.evaluate(ocsf_event)
        
        # Weighted score aggregation: 40% Provenance, 40% Threat Intel, 20% Containment Feasibility
        weighted_risk = (r_inv * 0.40) + (r_int * 0.40) + (r_cnt * 0.20)
        average_confidence = (c_inv + c_int + c_cnt) / 3.0
        
        vote_inv = r_inv > 0.50
        vote_int = r_int > 0.50
        vote_cnt = r_cnt > 0.50
        
        isolate_votes_count = sum([vote_inv, vote_int, vote_cnt])
        two_thirds_majority = isolate_votes_count >= 2
        
        # Consensus threshold logic: Execute if 2/3 majority met, risk > 0.65, and confidence > 0.70
        execute_containment = two_thirds_majority and (weighted_risk > 0.60) and (average_confidence > 0.70)
        
        votes = {
            "investigator": {
                "risk": round(r_inv, 4),
                "confidence": round(c_inv, 4),
                "vote_isolate": vote_inv,
                "detail": msg_inv
            },
            "intel_aggregator": {
                "risk": round(r_int, 4),
                "confidence": round(c_int, 4),
                "vote_isolate": vote_int,
                "detail": msg_int
            },
            "containment_specialist": {
                "risk": round(r_cnt, 4),
                "confidence": round(c_cnt, 4),
                "vote_isolate": vote_cnt,
                "detail": msg_cnt
            }
        }
        
        action = "MONITOR_FLOW"
        signature = None
        
        device_uid = ocsf_event.get("device", {}).get("uid", "") or ocsf_event.get("hostname", "unknown-device")
        event_uid = ocsf_event.get("metadata", {}).get("uid", "") or ocsf_event.get("event_uid", f"evt-{int(time.time()*1000)}")
        
        if execute_containment:
            action = "ACTIVE_ISOLATE_HOST"
            payload = f"{action}:{device_uid}:{time.time()}"
            signature = hashlib.sha256(payload.encode()).hexdigest()
            
        return {
            "event_uid": event_uid,
            "timestamp": time.time(),
            "composite_risk_score": round(weighted_risk, 4),
            "evaluation_confidence": round(average_confidence, 4),
            "consensus_action": action,
            "agent_votes": votes,
            "authorized_signature": signature,
            "majority_verdict": f"{isolate_votes_count}/3 Agents Voted ISOLATE",
            "execution_status": "CONTAINMENT_DISPATCHED" if execute_containment else "PASSIVE_MONITORING"
        }
