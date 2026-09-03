import json
import datetime
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from app.models.models import AnomalyLog

class AnomalyMessageTracker:
    """
    Saves explainable machine learning anomaly metrics and attribution reasons 
    to Neon database while publishing real-time WebSocket broker packets.
    """
    def __init__(self, db: Session, redis_client=None, org_id: str = ""):
        self.db = db
        self.redis = redis_client
        self.org_id = org_id

    def process_and_track_anomaly(
        self,
        event_class: int,
        raw_payload: str,
        score: float,
        metrics: Dict[str, Any],
        reasons: List[str],
        model_version: str = "IsolationForest-v2.1"
    ) -> Dict[str, Any]:
        """Saves ML execution traces in Neon Postgres and broadcasts results over the Redis bus."""
        is_anomaly = score >= 0.50
        
        # Save trace to Neon database
        anomaly_record = AnomalyLog(
            org_id=self.org_id,
            event_class_uid=event_class,
            source_log_payload=raw_payload,
            raw_anomaly_score=float(score),
            is_anomaly=is_anomaly,
            model_version=model_version,
            features_analyzed=metrics,
            attribution_reasons=reasons,
            analyst_triage_status="unassigned"
        )
        
        self.db.add(anomaly_record)
        self.db.commit()
        self.db.refresh(anomaly_record)
        
        # Prepare WebSocket broadcast payload
        broadcast_payload = {
            "alert_id": str(anomaly_record.id),
            "org_id": self.org_id,
            "timestamp": anomaly_record.timestamp.isoformat() if anomaly_record.timestamp else datetime.datetime.utcnow().isoformat(),
            "class_uid": event_class,
            "score": round(score, 4),
            "is_anomaly": is_anomaly,
            "reasons": reasons,
            "metrics": metrics,
            "model_version": model_version,
            "triage_status": anomaly_record.analyst_triage_status
        }
        
        # Publish to Redis channel for FastAPI WebSocket consumption
        if self.redis:
            try:
                # Broadcast on both unified channel patterns
                self.redis.publish(f"threat-analyser:tenant:{self.org_id}:alerts", json.dumps(broadcast_payload))
                self.redis.publish(f"tenant:{self.org_id}:alerts", json.dumps(broadcast_payload))
            except Exception:
                pass
        
        return broadcast_payload

    def update_triage_status(self, anomaly_id: str, new_status: str) -> Optional[Dict[str, Any]]:
        """Updates the analyst triage status (unassigned, investigating, resolved)"""
        record = self.db.query(AnomalyLog).filter(
            AnomalyLog.id == anomaly_id,
            AnomalyLog.org_id == self.org_id
        ).first()
        if not record:
            return None
        record.analyst_triage_status = new_status
        self.db.commit()
        self.db.refresh(record)
        return {
            "id": str(record.id),
            "triage_status": record.analyst_triage_status,
            "updated_at": datetime.datetime.utcnow().isoformat()
        }
