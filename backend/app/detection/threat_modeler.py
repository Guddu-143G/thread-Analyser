from typing import List, Dict, Any, Optional
import math

class STRIDEThreatEngine:
    """
    Continuous Architecture-Aware Threat Modeling Engine (STRIDE-as-Code).
    Analyzes dynamic application topologies, socket states, and OCSF network telemetry
    to automatically identify active security architectural weaknesses.
    """

    def __init__(self):
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.edges: List[Dict[str, Any]] = []

    def rebuild_topology(
        self,
        connections: Optional[List[Dict[str, Any]]] = None,
        services: Optional[List[Dict[str, Any]]] = None,
    ):
        self.nodes = {}
        self.edges = []

        # Default enterprise topology baseline if none passed
        default_conns = [
            {
                "src": "10.0.0.12 (Ext-Ingress-Edge)",
                "dst": "10.0.1.5 (API-Gateway)",
                "port": 8000,
                "protocol": "HTTP",
                "service": "Ingest-API",
                "authenticated": False,
                "rate_limited": False,
            },
            {
                "src": "10.0.1.5 (API-Gateway)",
                "dst": "10.0.2.18 (Redis-Cache-Cluster)",
                "port": 6379,
                "protocol": "TCP-Plaintext",
                "service": "Redis-Session",
                "authenticated": True,
                "rate_limited": True,
            },
            {
                "src": "10.0.1.5 (API-Gateway)",
                "dst": "10.0.3.50 (PostgreSQL-Primary)",
                "port": 5432,
                "protocol": "PostgreSQL-Wire",
                "service": "PostgreSQL-DB",
                "authenticated": True,
                "rate_limited": True,
            },
            {
                "src": "192.168.1.104 (Admin-Workstation)",
                "dst": "10.0.3.50 (PostgreSQL-Primary)",
                "port": 22,
                "protocol": "SSH",
                "service": "SSH-Admin",
                "authenticated": True,
                "rate_limited": False,
            },
            {
                "src": "10.0.1.5 (API-Gateway)",
                "dst": "10.0.4.99 (Celery-Task-Worker)",
                "port": 5672,
                "protocol": "AMQP",
                "service": "Async-Worker",
                "authenticated": True,
                "rate_limited": True,
            },
        ]

        active_conns = connections if connections is not None and len(connections) > 0 else default_conns

        for conn in active_conns:
            src = conn.get("src") or conn.get("src_endpoint", {}).get("ip")
            dst = conn.get("dst") or conn.get("dst_endpoint", {}).get("ip")
            port = conn.get("port") or conn.get("dst_endpoint", {}).get("port", 80)
            protocol = conn.get("protocol", "TCP")
            service = conn.get("service", f"Port-{port}")
            auth = conn.get("authenticated", True)
            rate_lim = conn.get("rate_limited", True)

            if src and dst:
                if src not in self.nodes:
                    self.nodes[src] = {"id": src, "label": src, "type": "client" if "Ext" in src or "Admin" in src else "service"}
                if dst not in self.nodes:
                    self.nodes[dst] = {"id": dst, "label": dst, "type": "database" if "PostgreSQL" in dst or "Redis" in dst else "service"}

                self.edges.append({
                    "src": src,
                    "dst": dst,
                    "port": int(port),
                    "protocol": protocol,
                    "service": service,
                    "authenticated": auth,
                    "rate_limited": rate_lim,
                })

    def evaluate_stride_threats(self) -> List[Dict[str, Any]]:
        threats = []

        for edge in self.edges:
            src = edge["src"]
            dst = edge["dst"]
            port = edge["port"]
            protocol = edge["protocol"]
            service = edge["service"]
            auth = edge["authenticated"]
            rate_limited = edge["rate_limited"]

            # 1. Spoofing (S): Missing mTLS authentication on administrative/database ports
            if port in [22, 5432, 8000] and protocol not in ["mTLS", "SSH-v2-Cert"]:
                threats.append({
                    "threat_id": f"STRIDE-S-{port}-{abs(hash(src+dst)) % 10000}",
                    "threat_class": "Spoofing",
                    "element": f"Path: {src} ➔ {dst}",
                    "severity": "HIGH",
                    "cwe_id": "CWE-287",
                    "description": f"Service '{service}' on port {port} lacks cryptographic mTLS verification, exposing channel to caller identity spoofing.",
                    "mitigation": "Enforce mutual TLS (mTLS) with SPIFFE/SPIRE x509 hardware-rooted identity certificates.",
                })

            # 2. Tampering (T): Unauthenticated or unverified protocol conduits
            if not auth:
                threats.append({
                    "threat_id": f"STRIDE-T-{port}-{abs(hash(src+dst)) % 10000}",
                    "threat_class": "Tampering",
                    "element": f"Conduit: {src} ➔ {dst}",
                    "severity": "CRITICAL",
                    "cwe_id": "CWE-345",
                    "description": f"Connection on port {port} allows unauthenticated data ingestion without cryptographic payload integrity checksums.",
                    "mitigation": "Mandate ECDSA-signed payload tokens and HMAC-SHA256 frame integrity checking.",
                })

            # 3. Repudiation (R): Unsigned operational conduits without Merkle proofs
            if port == 22 or "Admin" in src:
                threats.append({
                    "threat_id": f"STRIDE-R-{port}-{abs(hash(src+dst)) % 10000}",
                    "threat_class": "Repudiation",
                    "element": f"Administrative Access: {src}",
                    "severity": "MEDIUM",
                    "cwe_id": "CWE-778",
                    "description": "Administrative sessions do not stream to an immutable Merkle Mountain Range (MMR) ledger in real time.",
                    "mitigation": "Route all administrative CLI sessions into the append-only Merkle Mountain Range audit stream.",
                })

            # 4. Information Disclosure (I): Unencrypted database/cache transit paths
            if port in [80, 6379, 8080] or protocol in ["HTTP", "TCP-Plaintext"]:
                threats.append({
                    "threat_id": f"STRIDE-I-{port}-{abs(hash(src+dst)) % 10000}",
                    "threat_class": "Information Disclosure",
                    "element": f"Data Pipeline: {src} ➔ {dst}",
                    "severity": "CRITICAL",
                    "cwe_id": "CWE-319",
                    "description": f"Sensitive telemetry or cache state is transmitted over unencrypted protocol '{protocol}' on port {port}.",
                    "mitigation": "Upgrade transport to TLS 1.3 with ChaCha20-Poly1305 / AES-256-GCM cipher suites.",
                })

            # 5. Denial of Service (D): Unbounded rate-limiting on core ingestion pipelines
            if not rate_limited or ("Ext" in src and port == 8000):
                threats.append({
                    "threat_id": f"STRIDE-D-{port}-{abs(hash(src+dst)) % 10000}",
                    "threat_class": "Denial of Service",
                    "element": f"Ingestion Gateway: {dst}",
                    "severity": "HIGH",
                    "cwe_id": "CWE-400",
                    "description": f"Ingress socket on {dst}:{port} lacks active token-bucket rate-limiting, risking worker queue exhaustion.",
                    "mitigation": "Configure hardware SmartNIC DPU or eBPF XDP token-bucket rate limiters at the edge.",
                })

            # 6. Elevation of Privilege (E): Direct administrative access to core database
            if "Admin" in src and port in [5432, 22]:
                threats.append({
                    "threat_id": f"STRIDE-E-{port}-{abs(hash(src+dst)) % 10000}",
                    "threat_class": "Elevation of Privilege",
                    "element": f"Database Ingress: {dst}",
                    "severity": "HIGH",
                    "cwe_id": "CWE-250",
                    "description": f"Direct administrative connection to database bypassing application bastion and Zero-Trust broker.",
                    "mitigation": "Enforce ephemeral Just-In-Time (JIT) access credentials brokered by Neon Auth RLS.",
                })

        return threats

    def get_model_summary(self) -> Dict[str, Any]:
        threats = self.evaluate_stride_threats()
        
        # Calculate Architecture Security Risk Score (0 - 100)
        severity_weights = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3}
        total_risk_penalty = sum(severity_weights.get(t["severity"], 5) for t in threats)
        architecture_health_score = max(5.0, round(100.0 - (total_risk_penalty * 0.7), 1))

        # Categorize threat counts
        stride_counts = {
            "Spoofing": len([t for t in threats if t["threat_class"] == "Spoofing"]),
            "Tampering": len([t for t in threats if t["threat_class"] == "Tampering"]),
            "Repudiation": len([t for t in threats if t["threat_class"] == "Repudiation"]),
            "Information Disclosure": len([t for t in threats if t["threat_class"] == "Information Disclosure"]),
            "Denial of Service": len([t for t in threats if t["threat_class"] == "Denial of Service"]),
            "Elevation of Privilege": len([t for t in threats if t["threat_class"] == "Elevation of Privilege"]),
        }

        return {
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "nodes": list(self.nodes.values()),
            "edges": self.edges,
            "threats": threats,
            "total_threats_identified": len(threats),
            "stride_breakdown": stride_counts,
            "architecture_health_score": architecture_health_score,
            "evaluation_standard": "STRIDE Continuous-as-Code (ISO/IEC 27005 / NIST SP 800-154)",
            "status": "EVALUATED_ACTIVE"
        }
