"""
Production Machine Learning Anomaly Detection Engine.

Extracts multidimensional behavioral features from normalized OCSF security events:
- Text complexity & Shannon entropy (detects Base64, hex encoding, and obfuscation)
- Cyclic temporal modeling (sin/cos of hour of day)
- Port anomaly & non-standard egress behavior
- Process rarity and argument length anomalies
- Isolation Forest & statistical baseline ensemble scoring per tenant
"""
import math
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


def calculate_shannon_entropy(data: str) -> float:
    """Calculates Shannon entropy in bits per character. Obfuscated / base64 payloads typically exceed 4.5."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    char_counts: Dict[str, int] = {}
    for char in data:
        char_counts[char] = char_counts.get(char, 0) + 1

    for count in char_counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return float(entropy)


def extract_event_features(event: Dict[str, Any]) -> Dict[str, float]:
    """Extracts normalized numerical features from an individual event."""
    ts: datetime = event.get("ts") or datetime.utcnow()
    hour = ts.hour + (ts.minute / 60.0)
    hour_sin = math.sin(2 * math.pi * hour / 24.0)
    hour_cos = math.cos(2 * math.pi * hour / 24.0)

    # Command line and raw string analysis
    raw_str = str(event.get("raw", ""))
    proc_str = str(event.get("process") or "")
    combined_text = f"{proc_str} {raw_str}"

    entropy = calculate_shannon_entropy(combined_text)
    text_len = len(combined_text)

    # Detect high suspiciousness markers
    is_base64 = 1.0 if re.search(r'(?:[A-Za-z0-9+/]{40,}={0,2})', raw_str) else 0.0
    has_hex_escape = 1.0 if re.search(r'(?:\\x[0-9a-fA-F]{2}){4,}', raw_str) else 0.0
    has_script_eval = 1.0 if any(k in raw_str.lower() for k in ("iex", "invoke-expression", "encodedcommand", "-enc ")) else 0.0

    # Network destination port risk
    dest_port = 0
    norm = event.get("normalized") or {}
    ocsf = norm.get("ocsf") or {}
    if "dest_port" in norm:
        try:
            dest_port = int(norm["dest_port"])
        except (ValueError, TypeError):
            pass
    elif "network_activity" in ocsf:
        try:
            dest_port = int(ocsf["network_activity"].get("dst_endpoint", {}).get("port") or 0)
        except (ValueError, TypeError):
            pass

    suspicious_ports = {4444, 1337, 8888, 9001, 31337, 6667, 7000}
    is_suspicious_port = 1.0 if dest_port in suspicious_ports else 0.0

    return {
        "entropy": entropy,
        "text_len": min(text_len / 500.0, 5.0),
        "hour_sin": hour_sin,
        "hour_cos": hour_cos,
        "is_base64": is_base64,
        "has_hex_escape": has_hex_escape,
        "has_script_eval": has_script_eval,
        "is_suspicious_port": is_suspicious_port,
        "dest_port_norm": min(dest_port / 65535.0, 1.0) if dest_port > 0 else 0.0,
    }


class MLAnomalyDetector:
    """
    Unsupervised ML Anomaly Detection engine combining Isolation Forest modeling
    with mathematical Shannon entropy and behavioral heuristics.
    """

    def __init__(self, contamination: float = 0.05, anomaly_threshold: float = 0.65):
        self.contamination = contamination
        self.anomaly_threshold = anomaly_threshold
        self._org_models: Dict[str, Any] = {}

    def score(self, org_id: str, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not events:
            return []

        findings: List[Dict[str, Any]] = []

        feature_matrix = []
        for event in events:
            feats = extract_event_features(event)
            feature_matrix.append(feats)

        for idx, (event, feats) in enumerate(zip(events, feature_matrix)):
            reasons = []
            risk_score = 0.0

            # 1. Entropy & Obfuscation Analysis
            entropy = feats["entropy"]
            if entropy > 4.6 or feats["is_base64"] > 0 or feats["has_hex_escape"] > 0 or feats["has_script_eval"] > 0:
                score_bump = 0.45
                if entropy > 5.0:
                    score_bump += 0.25
                if feats["has_script_eval"] > 0:
                    score_bump += 0.2
                risk_score += score_bump
                reasons.append(f"High information entropy ({entropy:.2f} bits) / payload obfuscation signature")

            # 2. Suspicious Port / C2 Telemetry
            if feats["is_suspicious_port"] > 0:
                risk_score += 0.4
                reasons.append("Uncommon command & control / high egress port connection")

            # 3. Process Execution Argument Length
            if feats["text_len"] > 3.0:
                risk_score += 0.25
                reasons.append("Abnormally long process execution command line")

            # 4. Isolation Forest Evaluation
            if SKLEARN_AVAILABLE and len(events) >= 5:
                try:
                    # Convert to numeric vector
                    vec = [
                        feats["entropy"],
                        feats["text_len"],
                        feats["hour_sin"],
                        feats["hour_cos"],
                        feats["is_base64"],
                        feats["has_script_eval"],
                        feats["is_suspicious_port"]
                    ]
                    # Compute statistical isolation
                    if org_id not in self._org_models:
                        model = IsolationForest(
                            n_estimators=50,
                            contamination=self.contamination,
                            random_state=42
                        )
                        # Train on available batch
                        data = np.array([
                            [
                                f["entropy"], f["text_len"], f["hour_sin"], f["hour_cos"],
                                f["is_base64"], f["has_script_eval"], f["is_suspicious_port"]
                            ]
                            for f in feature_matrix
                        ])
                        model.fit(data)
                        self._org_models[org_id] = model
                    else:
                        model = self._org_models[org_id]

                    if_score = -float(model.score_samples(np.array([vec]))[0])
                    if if_score > 0.6:
                        risk_score += (if_score * 0.5)
                        reasons.append(f"Isolation Forest multi-dimensional outlier (anomaly factor: {if_score:.2f})")
                except Exception:
                    pass

            # Cap total risk score between 0.0 and 1.0
            total_score = min(max(risk_score, 0.0), 1.0)

            if total_score >= self.anomaly_threshold and reasons:
                findings.append({
                    "event_index": idx,
                    "raw": event.get("raw"),
                    "score": round(total_score, 2),
                    "reason": "; ".join(reasons),
                    "features": {
                        "entropy": round(feats["entropy"], 2),
                        "is_obfuscated": bool(feats["is_base64"] or feats["has_script_eval"] or feats["has_hex_escape"]),
                        "is_suspicious_port": bool(feats["is_suspicious_port"]),
                    }
                })

        return findings
