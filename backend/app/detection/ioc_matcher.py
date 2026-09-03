"""
Matches a normalized event against active threat indicators (global + org-specific).
"""
from sqlalchemy.orm import Session

from app.models.models import ThreatIndicator


def _candidate_values(event: dict) -> dict[str, list[str]]:
    """Map IOC type -> list of values present in this event to check."""
    candidates: dict[str, list[str]] = {"ip": [], "domain": [], "hash": [], "process": []}

    for ip in (event.get("src_ip"), event.get("dest_ip")):
        if ip:
            candidates["ip"].append(ip)

    proc = event.get("process")
    if proc:
        candidates["process"].append(proc)

    normalized = event.get("normalized") or {}
    for key in ("domain", "hostname", "url"):
        if normalized.get(key):
            candidates["domain"].append(str(normalized[key]))
    for key in ("hash", "sha256", "md5", "file_hash"):
        if normalized.get(key):
            candidates["hash"].append(str(normalized[key]))

    return candidates


def match_iocs(db: Session, org_id: str, event: dict) -> list[ThreatIndicator]:
    candidates = _candidate_values(event)
    matches: list[ThreatIndicator] = []

    for ioc_type, values in candidates.items():
        if not values:
            continue
        values_lower = {v.lower() for v in values}
        iocs = (
            db.query(ThreatIndicator)
            .filter(ThreatIndicator.type == ioc_type)
            .filter((ThreatIndicator.org_id == org_id) | (ThreatIndicator.org_id.is_(None)))
            .all()
        )
        for ioc in iocs:
            if ioc.value.lower() in values_lower:
                matches.append(ioc)

    return matches
