"""
Declarative Detection Rule Engine.

Supports:
1. Match rules (fires once per matching event).
2. Threshold / Frequency rules (fires when N matching events share a group key within a time window).
3. Sigma standard rules (YAML/JSON Sigma detection specification compiled via SigmaCompiler).
"""
from collections import defaultdict
from datetime import timedelta
from typing import Any
import re
from sqlalchemy.orm import Session

from app.models.models import Rule, LogEvent
from app.detection.sigma_compiler import SigmaCompiler, CompiledSigmaRule


def _get_field(event: dict, field: str) -> Any:
    if field in event:
        return event.get(field)
    return (event.get("normalized") or {}).get(field)


def _eval_condition(event: dict, cond: dict) -> bool:
    value = _get_field(event, cond["field"])
    op = cond.get("op", "eq")
    target = cond.get("value")

    if value is None:
        return False
    value_str = str(value).lower()
    target_str = str(target).lower() if target is not None else None

    if op == "eq":
        return value_str == target_str
    if op == "contains":
        return target_str in value_str
    if op == "regex":
        return re.search(cond["value"], str(value), re.IGNORECASE) is not None
    if op == "gt":
        try:
            return float(value) > float(target)
        except (TypeError, ValueError):
            return False
    return False


def _eval_conditions(event: dict, conditions: list[dict], logic: str) -> bool:
    if not conditions:
        return False
    results = [_eval_condition(event, c) for c in conditions]
    return any(results) if logic == "or" else all(results)


def evaluate_match_rule(rule: Rule, events: list[dict]) -> list[dict]:
    conditions = rule.definition.get("conditions", [])
    logic = rule.definition.get("logic", "and")
    hits = []
    for event in events:
        if _eval_conditions(event, conditions, logic):
            hits.append(event)
    return hits


def evaluate_sigma_rule(rule: Rule, events: list[dict]) -> list[dict]:
    """Compiles and evaluates a standard Sigma rule against the batch of events."""
    sigma_def = rule.definition.get("sigma") or rule.definition
    try:
        compiled: CompiledSigmaRule = SigmaCompiler.compile_rule(sigma_def)
    except Exception:
        return []

    hits = []
    for event in events:
        if compiled.matches(event):
            hits.append(event)
    return hits


def evaluate_threshold_rule(
    db: Session, org_id: str, rule: Rule, events: list[dict]
) -> dict[str, list[dict]]:
    """Returns {group_key: [matching events]} for groups that hit the threshold."""
    conditions = rule.definition.get("conditions", [])
    logic = rule.definition.get("logic", "and")
    group_by = rule.definition.get("group_by", "src_ip")
    count_needed = rule.definition.get("count", 5)
    window_seconds = rule.definition.get("window_seconds", 300)

    matching_batch = [e for e in events if _eval_conditions(e, conditions, logic)]
    if not matching_batch:
        return {}

    grouped: dict[str, list[dict]] = defaultdict(list)
    for e in matching_batch:
        key = _get_field(e, group_by)
        if key:
            grouped[str(key)].append(e)

    fired: dict[str, list[dict]] = {}
    for key, group_events in grouped.items():
        latest_ts = max(e["ts"] for e in group_events)
        window_start = latest_ts - timedelta(seconds=window_seconds)

        # count recent matching events already in DB for this group+window too,
        # so a threshold split across two separate uploads still triggers.
        field_col_map = {
            "src_ip": LogEvent.src_ip,
            "dest_ip": LogEvent.dest_ip,
            "user": LogEvent.user,
            "process": LogEvent.process,
        }
        db_count = 0
        if group_by in field_col_map:
            db_count = (
                db.query(LogEvent)
                .filter(LogEvent.org_id == org_id)
                .filter(field_col_map[group_by] == key)
                .filter(LogEvent.ts >= window_start)
                .filter(LogEvent.event_type == matching_batch[0].get("event_type"))
                .count()
            )

        total = max(len(group_events), db_count)
        if total >= count_needed:
            fired[key] = group_events

    return fired
