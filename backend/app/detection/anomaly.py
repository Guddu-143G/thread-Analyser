"""
Machine Learning Anomaly Detection Interface and Provider.

Provides an unsupervised behavioral anomaly detection engine scoring incoming
normalized events based on information entropy, cyclic temporal features,
command complexity, and statistical outlier factors.
"""
from typing import Protocol, List, Dict, Any

from app.detection.anomaly_detector import MLAnomalyDetector


class AnomalyDetector(Protocol):
    def score(self, org_id: str, events: list[dict]) -> list[dict]:
        """Return a list of anomaly findings: [{event, score, reason, features}, ...]."""
        ...


class NullAnomalyDetector:
    """No-op fallback implementation."""

    def score(self, org_id: str, events: list[dict]) -> list[dict]:
        return []


_global_anomaly_detector = MLAnomalyDetector(contamination=0.05, anomaly_threshold=0.60)


def get_anomaly_detector() -> AnomalyDetector:
    """Returns active production ML anomaly detector."""
    return _global_anomaly_detector
