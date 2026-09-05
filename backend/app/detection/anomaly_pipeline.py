import os
import time
import pickle
import logging
import threading
from typing import Dict, Any, List, Optional, Tuple
from collections import OrderedDict
import numpy as np

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import RobustScaler
    from sklearn.decomposition import PCA
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

logger = logging.getLogger(__name__)

MODEL_STORAGE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "scratch", "ml_models")
os.makedirs(MODEL_STORAGE_DIR, exist_ok=True)

# Standard features extracted from telemetry events
NUMERIC_FEATURES = [
    "request_rate_1m",
    "request_rate_5m",
    "failed_auth_count",
    "payload_entropy",
    "unusual_port_flag",
    "geo_distance_km",
    "packet_size_variance",
    "token_anomaly_score",
    "session_duration_sec",
    "concurrent_sessions"
]


class SecurityAnomalyDetector:
    """
    Isolated ML Anomaly Detector using Isolation Forest, RobustScaler, and baseline statistical thresholds.
    Supports feature extraction, fitting, inference scoring, decision boundaries, and model persistence.
    """
    def __init__(self, contamination: float = 0.05, n_estimators: int = 100, random_state: int = 42):
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state
        self.is_fitted = False
        self.scaler = RobustScaler() if SKLEARN_AVAILABLE else None
        self.pca = PCA(n_components=2) if SKLEARN_AVAILABLE else None
        self.model = IsolationForest(
            contamination=contamination,
            n_estimators=n_estimators,
            random_state=random_state,
            n_jobs=1
        ) if SKLEARN_AVAILABLE else None
        
        # Baselines & metadata
        self.feature_names = NUMERIC_FEATURES
        self.feature_means: Dict[str, float] = {f: 0.0 for f in NUMERIC_FEATURES}
        self.feature_stds: Dict[str, float] = {f: 1.0 for f in NUMERIC_FEATURES}
        self.training_samples_count = 0
        self.trained_at: Optional[float] = None
        self.version = "v27.0-isolation-forest"

    def extract_features(self, event: Dict[str, Any]) -> np.ndarray:
        """Extract standardized numeric vector from an event dictionary."""
        vector = []
        for feature in self.feature_names:
            val = event.get(feature, 0.0)
            try:
                val = float(val) if val is not None else 0.0
            except (ValueError, TypeError):
                val = 0.0
            vector.append(val)
        return np.array(vector, dtype=np.float32)

    def fit(self, telemetry_data: List[Dict[str, Any]]) -> "SecurityAnomalyDetector":
        """Fit Isolation Forest and baseline statistics on historical telemetry."""
        if not telemetry_data:
            logger.warning("Empty telemetry data passed to fit(). Skipping.")
            return self

        matrix = np.array([self.extract_features(evt) for evt in telemetry_data], dtype=np.float32)
        self.training_samples_count = len(matrix)
        
        # Calculate feature baselines (mean & std)
        means = np.mean(matrix, axis=0)
        stds = np.std(matrix, axis=0)
        for i, f in enumerate(self.feature_names):
            self.feature_means[f] = float(means[i])
            self.feature_stds[f] = float(stds[i]) if stds[i] > 1e-5 else 1.0

        if SKLEARN_AVAILABLE and len(matrix) >= 5:
            scaled_matrix = self.scaler.fit_transform(matrix)
            self.model.fit(scaled_matrix)
            if len(matrix) >= 2:
                try:
                    self.pca.fit(scaled_matrix)
                except Exception as e:
                    logger.debug(f"PCA fit skipped: {e}")
            self.is_fitted = True
            self.trained_at = time.time()
        else:
            # Cold-start fallback fitting
            self.is_fitted = True
            self.trained_at = time.time()

        return self

    def score(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate anomaly score [0.0 - 1.0] and diagnostic telemetry.
        Score >= 0.65 indicates anomaly.
        """
        raw_features = self.extract_features(event)
        
        # 1. Statistical Z-Score / Heuristic baseline evaluation
        z_scores = {}
        heuristic_anomaly_weight = 0.0
        for i, feature in enumerate(self.feature_names):
            mean = self.feature_means.get(feature, 0.0)
            std = self.feature_stds.get(feature, 1.0)
            z = abs((raw_features[i] - mean) / (std if std > 1e-5 else 1.0))
            z_scores[feature] = float(z)
            if z > 3.0:
                heuristic_anomaly_weight += 0.15

        # 2. Sklearn Isolation Forest inference (if fitted)
        ml_score = 0.0
        is_anomaly = False
        decision_function_val = 0.0

        if SKLEARN_AVAILABLE and self.is_fitted and self.model is not None:
            try:
                scaled = self.scaler.transform(raw_features.reshape(1, -1))
                decision_function_val = float(self.model.decision_function(scaled)[0])
                # In IsolationForest, lower decision function = more anomalous.
                # Normalized mapping: [ -0.5 to 0.5 ] -> [ 1.0 to 0.0 ]
                ml_score = max(0.0, min(1.0, 0.5 - decision_function_val))
                is_anomaly = bool(self.model.predict(scaled)[0] == -1)
            except Exception as e:
                logger.error(f"Error during ML inference: {e}")
                ml_score = min(1.0, heuristic_anomaly_weight)
                is_anomaly = ml_score >= 0.65
        else:
            # Fallback heuristic calculation
            ml_score = min(1.0, heuristic_anomaly_weight)
            is_anomaly = ml_score >= 0.65

        # Combined confidence score
        final_score = float(np.clip(0.7 * ml_score + 0.3 * min(1.0, heuristic_anomaly_weight), 0.0, 1.0))

        # Top contributing features
        feature_contributions = []
        for feature, z in sorted(z_scores.items(), key=lambda x: x[1], reverse=True)[:4]:
            feature_contributions.append({
                "feature": feature,
                "value": float(event.get(feature, 0.0) or 0.0),
                "z_score": round(z, 2),
                "deviation_level": "CRITICAL" if z > 3.5 else "HIGH" if z > 2.0 else "NORMAL"
            })

        # PCA 2D coordinates for visualization
        pca_coords = [0.0, 0.0]
        if SKLEARN_AVAILABLE and self.is_fitted and self.pca is not None:
            try:
                scaled = self.scaler.transform(raw_features.reshape(1, -1))
                coords = self.pca.transform(scaled)[0]
                pca_coords = [float(coords[0]), float(coords[1])]
            except Exception:
                pca_coords = [float(raw_features[0] % 10), float(raw_features[1] % 10)]

        severity = "CRITICAL" if final_score >= 0.85 else "HIGH" if final_score >= 0.65 else "MEDIUM" if final_score >= 0.40 else "LOW"

        return {
            "is_anomaly": is_anomaly or (final_score >= 0.65),
            "anomaly_score": round(final_score, 4),
            "severity": severity,
            "decision_boundary": round(decision_function_val, 4),
            "top_contributing_features": feature_contributions,
            "pca_coordinates": pca_coords,
            "detector_version": self.version,
            "model_fitted": self.is_fitted,
            "evaluated_at": time.time()
        }

    def get_feature_importances(self) -> Dict[str, float]:
        """Return relative feature importance heuristics."""
        # Derived from baseline standard deviations & variance
        total_std = sum(self.feature_stds.values()) or 1.0
        return {f: round(self.feature_stds[f] / total_std, 4) for f in self.feature_names}

    def save(self, filepath: str):
        """Serialize detector to disk."""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, "wb") as f:
            pickle.dump(self, f)

    @classmethod
    def load(cls, filepath: str) -> "SecurityAnomalyDetector":
        """Load serialized detector from disk."""
        with open(filepath, "rb") as f:
            return pickle.load(f)


class MultiTenantMLManager:
    """
    Thread-safe Multi-Tenant Anomaly Detector Manager.
    Manages tenant-isolated models, LRU memory caching, and on-demand inference.
    """
    def __init__(self, cache_capacity: int = 50, storage_dir: str = MODEL_STORAGE_DIR):
        self.cache_capacity = cache_capacity
        self.storage_dir = storage_dir
        self._cache: OrderedDict[str, SecurityAnomalyDetector] = OrderedDict()
        self._lock = threading.Lock()

    def _get_model_path(self, org_id: str) -> str:
        safe_org = "".join(c for c in org_id if c.isalnum() or c in ("-", "_"))
        return os.path.join(self.storage_dir, f"anomaly_detector_org_{safe_org}.pkl")

    def get_tenant_detector(self, org_id: str) -> SecurityAnomalyDetector:
        """Fetch tenant detector from cache, or disk, or instantiate a cold-start model."""
        with self._lock:
            if org_id in self._cache:
                self._cache.move_to_end(org_id)
                return self._cache[org_id]

        # Check disk
        path = self._get_model_path(org_id)
        detector = None
        if os.path.exists(path):
            try:
                detector = SecurityAnomalyDetector.load(path)
                logger.info(f"Loaded ML model for tenant '{org_id}' from {path}")
            except Exception as e:
                logger.error(f"Failed to load model for tenant '{org_id}' from {path}: {e}")

        if detector is None:
            # Cold-start detector with fallback synthetic baselines
            detector = SecurityAnomalyDetector()
            # Synthetic default baselines
            synthetic_defaults = [
                {"request_rate_1m": 15.0, "request_rate_5m": 70.0, "failed_auth_count": 0, "payload_entropy": 2.5, "unusual_port_flag": 0, "geo_distance_km": 50, "packet_size_variance": 120, "token_anomaly_score": 0.05, "session_duration_sec": 300, "concurrent_sessions": 1},
                {"request_rate_1m": 25.0, "request_rate_5m": 110.0, "failed_auth_count": 1, "payload_entropy": 3.1, "unusual_port_flag": 0, "geo_distance_km": 120, "packet_size_variance": 200, "token_anomaly_score": 0.1, "session_duration_sec": 450, "concurrent_sessions": 2},
                {"request_rate_1m": 10.0, "request_rate_5m": 45.0, "failed_auth_count": 0, "payload_entropy": 2.1, "unusual_port_flag": 0, "geo_distance_km": 10, "packet_size_variance": 80, "token_anomaly_score": 0.02, "session_duration_sec": 180, "concurrent_sessions": 1},
                {"request_rate_1m": 30.0, "request_rate_5m": 140.0, "failed_auth_count": 0, "payload_entropy": 3.4, "unusual_port_flag": 0, "geo_distance_km": 200, "packet_size_variance": 310, "token_anomaly_score": 0.08, "session_duration_sec": 600, "concurrent_sessions": 2},
                {"request_rate_1m": 18.0, "request_rate_5m": 85.0, "failed_auth_count": 0, "payload_entropy": 2.8, "unusual_port_flag": 0, "geo_distance_km": 75, "packet_size_variance": 150, "token_anomaly_score": 0.04, "session_duration_sec": 240, "concurrent_sessions": 1},
            ]
            detector.fit(synthetic_defaults)

        with self._lock:
            if len(self._cache) >= self.cache_capacity:
                self._cache.popitem(last=False)
            self._cache[org_id] = detector

        return detector

    def save_tenant_detector(self, org_id: str, detector: SecurityAnomalyDetector) -> str:
        """Persist tenant detector to disk and update LRU cache."""
        path = self._get_model_path(org_id)
        detector.save(path)
        with self._lock:
            self._cache[org_id] = detector
            self._cache.move_to_end(org_id)
        return path

    def evaluate_telemetry(self, org_id: str, event: Dict[str, Any]) -> Dict[str, Any]:
        """Run ML inference on telemetry event for a given tenant."""
        detector = self.get_tenant_detector(org_id)
        res = detector.score(event)
        res["org_id"] = org_id
        return res

    def get_model_metadata(self, org_id: str) -> Dict[str, Any]:
        """Get model status, training statistics, and baselines."""
        detector = self.get_tenant_detector(org_id)
        path = self._get_model_path(org_id)
        return {
            "org_id": org_id,
            "version": detector.version,
            "is_fitted": detector.is_fitted,
            "training_samples_count": detector.training_samples_count,
            "trained_at": detector.trained_at,
            "model_file_exists": os.path.exists(path),
            "model_file_path": path if os.path.exists(path) else None,
            "feature_names": detector.feature_names,
            "feature_means": detector.feature_means,
            "feature_stds": detector.feature_stds,
            "feature_importances": detector.get_feature_importances()
        }


# Global Singleton Manager
ml_manager = MultiTenantMLManager()
