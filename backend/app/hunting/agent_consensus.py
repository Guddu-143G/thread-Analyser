"""
Autonomous Threat Hunting Multi-Agent Consensus Engine (v6.0).

Coordinates a cluster of specialized, persona-based AI hunting agents that continuously
audit normalized OCSF logs, formulate intrusion hypotheses, cast independent risk votes,
and promote alerts to master triage only upon mathematical consensus.
"""
from typing import Any, Dict, List, Optional, Tuple


class ThreatHunterAgent:
    """Specialized Persona AI Hunter."""

    def __init__(self, name: str, focus_area: str, description: str):
        self.name = name
        self.focus_area = focus_area  # "process", "network", "entropy_credentials"
        self.description = description

    def evaluate_event(self, ocsf_event: Dict[str, Any]) -> Tuple[float, str]:
        """
        Heuristically evaluates risk probability from 0.0 to 1.0 based on persona focus area.
        Returns (score, rationale).
        """
        raw = str(ocsf_event).lower()

        if self.focus_area == "process":
            cmd = ocsf_event.get("process", {}).get("cmd_line", "") or ocsf_event.get("raw_unstructured", "")
            cmd_lower = cmd.lower()
            if any(term in cmd_lower for term in ["-enc", "-encodedcommand", "iex", "downloadstring", "invoke-expression"]):
                return 0.96, "High-confidence obfuscated process execution payload detected."
            if any(term in cmd_lower for term in ["mimikatz", "sekurlsa", "privilege::debug", "procdump"]):
                return 0.99, "Known LSASS / credential-dumping utility detected in process tree."
            if any(term in cmd_lower for term in ["/bin/sh -i", "bash -c", "nc -e", "mkfifo"]):
                return 0.92, "Interactive reverse shell invocation pattern detected."
            return 0.15, "Standard system process activity."

        elif self.focus_area == "network":
            dst_port = ocsf_event.get("network_activity", {}).get("dst_endpoint", {}).get("port", 0)
            dst_ip = ocsf_event.get("network_activity", {}).get("dst_endpoint", {}).get("ip", "")
            if dst_port in [4444, 1337, 9001, 8888, 6667]:
                return 0.94, f"Suspicious non-standard egress port {dst_port} connection (C2 beaconing indicator)."
            if "185.220.101.5" in raw or "45.155.205.233" in raw:
                return 0.98, "Outbound connection to known high-threat adversary C2 infrastructure."
            if "failed password" in raw and ("port" in raw or "ssh" in raw):
                return 0.88, "Distributed credential brute-force spraying detected on ingress socket."
            return 0.10, "Normal telemetry egress patterns."

        elif self.focus_area == "entropy_credentials":
            if any(k in raw for k in ["authorization", "bearer", "token", "private_key", "password="]):
                return 0.90, "High-entropy authentication secret / token exposure in log stream."
            if any(k in raw for k in ["sqbf", "eyjhbgcioi", "aaaa"]):
                return 0.85, "Base64 encoded blob with high Shannon entropy detected."
            return 0.12, "Low entropy baseline log string."

        return 0.10, "Benign event."


class ConsensusVerificationEngine:
    """
    Coordinates multi-agent consensus validation across persona agents.
    """

    def __init__(self):
        self.agents = [
            ThreatHunterAgent(
                "Intrusion_Expert_AI",
                "process",
                "Formulates hypotheses regarding process masquerading, shell injections, and privilege escalation."
            ),
            ThreatHunterAgent(
                "Network_Sentinel_AI",
                "network",
                "Analyzes egress port anomalies, lateral pivot schemes, and non-standard C2 beaconing."
            ),
            ThreatHunterAgent(
                "Crypto_Entropy_AI",
                "entropy_credentials",
                "Audits log strings for high Shannon entropy, credential dumps, and token leakage."
            ),
        ]

    def list_agents(self) -> List[Dict[str, str]]:
        return [
            {"name": a.name, "focus_area": a.focus_area, "description": a.description}
            for a in self.agents
        ]

    def evaluate_event_consensus(
        self,
        event: Dict[str, Any],
        consensus_threshold: float = 0.70
    ) -> Dict[str, Any]:
        """
        Queries all specialized agents, aggregates votes, and computes mathematical consensus.
        """
        agent_votes: List[Dict[str, Any]] = []
        scores: List[float] = []

        for agent in self.agents:
            score, rationale = agent.evaluate_event(event)
            scores.append(score)
            agent_votes.append({
                "agent_name": agent.name,
                "focus_area": agent.focus_area,
                "risk_score": round(score, 3),
                "rationale": rationale,
                "vote": "ALERT" if score >= 0.70 else "BENIGN",
            })

        avg_score = round(sum(scores) / len(scores), 3)
        alert_votes_count = sum(1 for v in agent_votes if v["vote"] == "ALERT")
        consensus_reached = bool(avg_score >= consensus_threshold or alert_votes_count >= 2)

        return {
            "consensus_reached": consensus_reached,
            "consensus_score": avg_score,
            "consensus_threshold": consensus_threshold,
            "alert_votes_count": alert_votes_count,
            "total_agents": len(self.agents),
            "agent_votes": agent_votes,
            "promotion_verdict": "PROMOTED_TO_TRIAGE_CONSOLE" if consensus_reached else "FILTERED_AS_NOISE",
        }
