from fastapi import APIRouter, Depends
from typing import Any, Dict, List, Optional
from pydantic import BaseModel
from app.core.deps import get_current_user
from app.models.models import User
from app.detection.gnn_provenance import GNNProvenanceClassifier, SecurityProvenanceGraph

router = APIRouter(prefix="/api/gnn", tags=["Graph Neural Network Provenance"])


class GNNPathRequest(BaseModel):
    telemetry_events: Optional[List[Dict[str, Any]]] = None


@router.get("/topology")
def get_sample_gnn_topology(current_user: User = Depends(get_current_user)) -> Dict[str, Any]:
    """Returns sample OCSF provenance graph topology."""
    sample_events = [
        {"source": "cmd.exe", "target": "powershell.exe", "source_label": "Process", "target_label": "Process", "relationship": "spawns"},
        {"source": "powershell.exe", "target": "admin", "source_label": "Process", "target_label": "Identity", "relationship": "authenticated_as"},
        {"source": "powershell.exe", "target": "185.220.101.5:4444", "source_label": "Process", "target_label": "Socket", "relationship": "connects_outbound"},
    ]
    return GNNProvenanceClassifier.analyze_incident_telemetry(sample_events)


@router.post("/analyze-path")
def analyze_gnn_path(request: GNNPathRequest, current_user: User = Depends(get_current_user)) -> Dict[str, Any]:
    """Analyzes telemetry graph with GNN message passing."""
    events = request.telemetry_events or [
        {"source": "nginx", "target": "sh", "source_label": "Process", "target_label": "Process", "relationship": "forks_shell"},
        {"source": "sh", "target": "curl 185.220.101.5", "source_label": "Process", "target_label": "Process", "relationship": "executes"},
        {"source": "curl 185.220.101.5", "target": "185.220.101.5:443", "source_label": "Process", "target_label": "Socket", "relationship": "downloads_payload"},
    ]
    return GNNProvenanceClassifier.analyze_incident_telemetry(events)
