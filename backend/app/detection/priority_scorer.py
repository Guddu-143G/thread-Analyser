"""
Version 25: Multi-Dimensional Automated Prioritization Scoring (MDPS) Engine
Calculates dynamic risk-adjusted prioritization scores for incoming telemetry,
correlating Anomaly Scores, MITRE ATT&CK Severity Weights, Asset Criticality,
and Threat Intelligence Confidence.
"""

from typing import Dict, Any, Tuple


class PriorityScorer:
    def __init__(
        self,
        w_anomaly: float = 0.35,
        w_mitre: float = 0.35,
        w_asset: float = 0.15,
        w_intel: float = 0.15,
        acceleration_factor: float = 1.15
    ):
        total_w = w_anomaly + w_mitre + w_asset + w_intel
        if total_w <= 0:
            total_w = 1.0
        self.w_anomaly = w_anomaly / total_w
        self.w_mitre = w_mitre / total_w
        self.w_asset = w_asset / total_w
        self.w_intel = w_intel / total_w
        self.acceleration_factor = acceleration_factor

    def compute_score(
        self,
        anomaly_score: float,
        mitre_weight: float,
        asset_criticality: float,
        intel_confidence: float
    ) -> Tuple[float, str, Dict[str, Any]]:
        """
        Calculates normalized MDPS score (0-100) and assigns priority category:
        LOW, MEDIUM, HIGH, CRITICAL.
        """
        # Clamp inputs to 0.0 - 100.0 range
        a = max(0.0, min(100.0, float(anomaly_score)))
        m = max(0.0, min(100.0, float(mitre_weight)))
        v = max(0.0, min(100.0, float(asset_criticality)))
        c = max(0.0, min(100.0, float(intel_confidence)))

        raw_score = (
            (self.w_anomaly * a) +
            (self.w_mitre * m) +
            (self.w_asset * v) +
            (self.w_intel * c)
        )

        # Acceleration applied when high anomaly co-occurs with confirmed threat intel
        accelerated = False
        if a >= 75.0 and c >= 80.0:
            raw_score *= self.acceleration_factor
            accelerated = True

        final_score = round(max(0.0, min(100.0, raw_score)), 2)

        if final_score >= 85.0:
            level = "CRITICAL"
        elif final_score >= 65.0:
            level = "HIGH"
        elif final_score >= 40.0:
            level = "MEDIUM"
        else:
            level = "LOW"

        breakdown = {
            "anomaly_contrib": round(self.w_anomaly * a, 2),
            "mitre_contrib": round(self.w_mitre * m, 2),
            "asset_contrib": round(self.w_asset * v, 2),
            "intel_contrib": round(self.w_intel * c, 2),
            "accelerated": accelerated,
            "acceleration_factor": self.acceleration_factor if accelerated else 1.0,
            "final_score": final_score,
            "priority_level": level
        }

        return final_score, level, breakdown


# Global Default Scorer Instance
default_scorer = PriorityScorer()
