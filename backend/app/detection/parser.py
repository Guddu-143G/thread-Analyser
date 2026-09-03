"""
Enterprise OCSF (Open Cybersecurity Schema Framework v1.1.0) Log Normalization Engine.

Normalizes raw security telemetry (Syslog, JSON, CEF, generic key-value, WinEvent)
into standard relational event records while embedding full high-fidelity OCSF
event payloads in the normalized event stream.
"""
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Optional, Dict, List

IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"
)
KV_RE = re.compile(r'([a-zA-Z0-9_\-\.]+)=("[^"]*"|\S+)')

# Common field keys across dialect schemas
SRC_IP_KEYS = ["src_ip", "srcip", "src", "source_ip", "ip", "client_ip", "sourceaddress", "c-ip"]
DEST_IP_KEYS = ["dest_ip", "dstip", "dst", "destination_ip", "target_ip", "destinationaddress", "s-ip"]
USER_KEYS = ["user", "username", "usr", "account", "suser", "target_user", "subject_user_name"]
PROCESS_KEYS = ["process", "proc", "process_name", "cmd", "command", "image", "file_path", "fname"]


# ==============================================================================
# OCSF Enterprise Schema Framework Definitions (v1.1.0-RC3 compliant)
# ==============================================================================

class OCSFCategory:
    SYSTEM_ACTIVITY = 1
    FINDINGS = 2
    IDENTITY_ACCESS = 3
    NETWORK_ACTIVITY = 4
    DEVICE_RF_ACTIVITY = 6


class OCSFEventClass:
    # System Activity (Category 1)
    PROCESS_ACTIVITY = 1007
    FILE_SYSTEM_ACTIVITY = 1001

    # Findings (Category 2)
    SECURITY_FINDING = 2001

    # Identity & Access (Category 3)
    AUTHENTICATION = 3002
    USER_ACCESS = 3001

    # Network Activity (Category 4)
    NETWORK_ACTIVITY = 4001

    # Device RF Activity (Category 6)
    BLUETOOTH_RF_ACTIVITY = 6001


class OCSFSeverity:
    INFORMATIONAL = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5
    UNKNOWN = 99


SEVERITY_MAP = {
    "info": OCSFSeverity.INFORMATIONAL,
    "informational": OCSFSeverity.INFORMATIONAL,
    "low": OCSFSeverity.LOW,
    "medium": OCSFSeverity.MEDIUM,
    "high": OCSFSeverity.HIGH,
    "critical": OCSFSeverity.CRITICAL,
    "error": OCSFSeverity.HIGH,
    "warning": OCSFSeverity.MEDIUM,
}


def _strip_quotes(v: str) -> str:
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        return v[1:-1]
    return v


def _first_present(d: dict, keys: list[str]) -> Optional[str]:
    for k in keys:
        if k in d and d[k] is not None and str(d[k]).strip() != "":
            return str(d[k])
    return None


def _extract_ips_from_text(text: str) -> list[str]:
    return IP_RE.findall(text)


def _parse_ts(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    for fmt in (
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%b %d %H:%M:%S",
        "%d/%b/%Y:%H:%M:%S %z",
    ):
        try:
            return datetime.strptime(str(value).strip(), fmt)
        except ValueError:
            continue
    return None


class OCSFParser:
    """
    Enterprise-grade Log Ingest Parser that maps incoming raw unstructured and semi-structured
    security telemetry (Syslog, JSON, CEF, WinEvent) into high-fidelity OCSF events.
    """

    def __init__(self):
        self.syslog_pattern = re.compile(
            r'^(?:<(?P<pri>\d+)>)?'
            r'(?:(?P<timestamp>[A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\S+))\s+'
            r'(?:(?P<hostname>[^\s:]+)\s+)?'
            r'(?:(?P<process>[a-zA-Z0-9_\-\(\)\[\]\./]+)(?:\[(?P<pid>\d+)\])?:\s+)?'
            r'(?P<message>.*)$'
        )

        self.ssh_failed_pattern = re.compile(
            r'Failed (?:password|publickey) for (?:invalid user )?(?P<user>[^\s]+) from (?P<ip>[0-9\.]+) port (?P<port>\d+)',
            re.IGNORECASE
        )
        self.ssh_success_pattern = re.compile(
            r'Accepted (?:password|publickey) for (?P<user>[^\s]+) from (?P<ip>[0-9\.]+) port (?P<port>\d+)',
            re.IGNORECASE
        )
        self.sudo_pattern = re.compile(
            r'(?P<user>[^\s]+)\s*:\s*(?:TTY=\S+\s*;\s*)?(?:PWD=\S+\s*;\s*)?USER=(?P<target_user>[^\s]+)\s*;\s*COMMAND=(?P<command>.*)',
            re.IGNORECASE
        )

    def parse_raw(self, raw_line: str, org_id: Optional[str] = None, device_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        raw_line = raw_line.strip()
        if not raw_line:
            return None

        parsed_data = {}
        log_format = "raw"

        # 1. JSON
        if raw_line.startswith('{') and raw_line.endswith('}'):
            try:
                parsed_data = json.loads(raw_line)
                log_format = "json"
            except json.JSONDecodeError:
                pass

        # 2. CEF
        elif raw_line.startswith('CEF:'):
            parsed_data = self._parse_cef(raw_line)
            log_format = "cef"

        # 3. Syslog
        elif self.syslog_pattern.match(raw_line):
            match = self.syslog_pattern.match(raw_line)
            if match:
                parsed_data = match.groupdict()
                log_format = "syslog"

        # 4. Key=Value Fallback
        if not parsed_data:
            kv_matches = KV_RE.findall(raw_line)
            if kv_matches and len(kv_matches) >= 2:
                parsed_data = {k.lower(): _strip_quotes(v) for k, v in kv_matches}
                log_format = "kv"
            else:
                parsed_data = {"message": raw_line}
                log_format = "raw"

        return self._normalize_to_ocsf(parsed_data, log_format, org_id, device_id, raw_line)

    def _parse_cef(self, cef_line: str) -> Dict[str, Any]:
        parts = cef_line.split('|')
        if len(parts) < 8:
            return {"message": cef_line}

        header = {
            "cef_version": parts[0].split(':')[-1],
            "vendor": parts[1],
            "product": parts[2],
            "version": parts[3],
            "signature_id": parts[4],
            "name": parts[5],
            "severity": parts[6]
        }

        extension_part = '|'.join(parts[7:])
        extensions = {}
        for match in KV_RE.finditer(extension_part):
            key = match.group(1)
            val = _strip_quotes(match.group(2))
            extensions[key] = val

        return {**header, **extensions, "is_cef": True}

    def _normalize_to_ocsf(
        self,
        parsed: Dict[str, Any],
        log_format: str,
        org_id: Optional[str],
        device_id: Optional[str],
        raw_message: str
    ) -> Dict[str, Any]:
        now_dt = datetime.now(timezone.utc)
        now_epoch = int(now_dt.timestamp() * 1000)

        ocsf_base: Dict[str, Any] = {
            "metadata": {
                "version": "1.1.0",
                "product": {
                    "vendor": "ThreatAnalyser",
                    "name": "Multi-Tenant Enterprise SIEM",
                    "version": "2.0.0"
                },
                "tenant_uid": org_id or "default"
            },
            "category_uid": OCSFCategory.SYSTEM_ACTIVITY,
            "class_uid": OCSFEventClass.PROCESS_ACTIVITY,
            "severity_id": OCSFSeverity.INFORMATIONAL,
            "time": now_epoch,
            "message": raw_message,
            "raw_data": raw_message,
            "device": {
                "uid": device_id or parsed.get("hostname") or "unknown-endpoint",
                "type_id": 1,
                "hostname": parsed.get("hostname") or "unknown-host"
            }
        }

        # ----------------------------------------------------------------------
        # PATH A: CEF Event Processing
        # ----------------------------------------------------------------------
        if log_format == "cef":
            ocsf_base["metadata"]["product"]["vendor"] = parsed.get("vendor", "Generic")
            ocsf_base["metadata"]["product"]["name"] = parsed.get("product", "Device")
            ocsf_base["metadata"]["product"]["version"] = parsed.get("version", "1.0")
            ocsf_base["severity_id"] = SEVERITY_MAP.get(str(parsed.get("severity")).lower(), OCSFSeverity.LOW)

            if any(k in parsed for k in ("src", "dst", "sPort", "dPort", "proto")):
                ocsf_base["category_uid"] = OCSFCategory.NETWORK_ACTIVITY
                ocsf_base["class_uid"] = OCSFEventClass.NETWORK_ACTIVITY
                ocsf_base["network_activity"] = {
                    "src_endpoint": {"ip": parsed.get("src"), "port": int(parsed.get("sPort", 0)) if parsed.get("sPort") else None},
                    "dst_endpoint": {"ip": parsed.get("dst"), "port": int(parsed.get("dPort", 0)) if parsed.get("dPort") else None},
                    "protocol": parsed.get("proto", "TCP")
                }
            elif any(k in parsed for k in ("shost", "filePath", "proc", "fname", "command")):
                ocsf_base["category_uid"] = OCSFCategory.SYSTEM_ACTIVITY
                ocsf_base["class_uid"] = OCSFEventClass.PROCESS_ACTIVITY
                ocsf_base["process"] = {
                    "name": parsed.get("proc") or parsed.get("fname"),
                    "cmd_line": parsed.get("filePath") or parsed.get("command"),
                    "uid": parsed.get("pid")
                }
            return ocsf_base

        # ----------------------------------------------------------------------
        # PATH B: Syslog & Text Parsing
        # ----------------------------------------------------------------------
        msg_str = parsed.get("message", "") or raw_message

        # SSH Auth
        ssh_failed = self.ssh_failed_pattern.search(msg_str)
        ssh_success = self.ssh_success_pattern.search(msg_str)
        if ssh_failed or ssh_success:
            match_data = (ssh_failed or ssh_success).groupdict()
            ocsf_base["category_uid"] = OCSFCategory.IDENTITY_ACCESS
            ocsf_base["class_uid"] = OCSFEventClass.AUTHENTICATION
            ocsf_base["severity_id"] = OCSFSeverity.HIGH if ssh_failed else OCSFSeverity.INFORMATIONAL
            ocsf_base["actor"] = {
                "user": {"name": match_data.get("user"), "type_id": 1}
            }
            ocsf_base["auth_protocol"] = "SSH"
            ocsf_base["status_id"] = 2 if ssh_failed else 1
            ocsf_base["src_endpoint"] = {
                "ip": match_data.get("ip"),
                "port": int(match_data.get("port", 0)) if match_data.get("port") else None
            }
            return ocsf_base

        # Sudo Privilege Use
        sudo_match = self.sudo_pattern.search(msg_str)
        if "sudo" in str(parsed.get("process", "")).lower() or sudo_match or "sudo:" in msg_str:
            ocsf_base["category_uid"] = OCSFCategory.IDENTITY_ACCESS
            ocsf_base["class_uid"] = OCSFEventClass.USER_ACCESS
            ocsf_base["severity_id"] = OCSFSeverity.MEDIUM
            user_name = parsed.get("process") or "unknown"
            target_user = "root"

            if sudo_match:
                match_data = sudo_match.groupdict()
                user_name = match_data.get("user")
                target_user = match_data.get("target_user", "root")

            ocsf_base["actor"] = {"user": {"name": user_name}}
            ocsf_base["user"] = {"name": target_user}
            ocsf_base["status_id"] = 2 if any(w in msg_str.lower() for w in ("incorrect password", "failed", "authentication failure")) else 1
            return ocsf_base

        # ----------------------------------------------------------------------
        # PATH C: JSON & Structured Key-Value
        # ----------------------------------------------------------------------
        if log_format in ("json", "kv"):
            category = str(parsed.get("category") or parsed.get("event_category") or "").lower()
            if category == "process" or any(k in parsed for k in ("process", "process_name", "cmdline", "command")):
                ocsf_base["category_uid"] = OCSFCategory.SYSTEM_ACTIVITY
                ocsf_base["class_uid"] = OCSFEventClass.PROCESS_ACTIVITY
                ocsf_base["process"] = {
                    "name": parsed.get("process_name") or parsed.get("process") or parsed.get("image"),
                    "cmd_line": parsed.get("cmdline") or parsed.get("command_line") or parsed.get("command") or parsed.get("cmd"),
                    "pid": parsed.get("pid")
                }
                ocsf_base["actor"] = {
                    "user": {"name": parsed.get("user") or parsed.get("username")}
                }
            elif category == "network" or any(k in parsed for k in ("src_ip", "dest_ip", "src", "dst")):
                ocsf_base["category_uid"] = OCSFCategory.NETWORK_ACTIVITY
                ocsf_base["class_uid"] = OCSFEventClass.NETWORK_ACTIVITY
                ocsf_base["network_activity"] = {
                    "src_endpoint": {"ip": parsed.get("src_ip") or parsed.get("src"), "port": parsed.get("src_port") or parsed.get("sPort")},
                    "dst_endpoint": {"ip": parsed.get("dest_ip") or parsed.get("dst_ip") or parsed.get("dst"), "port": parsed.get("dest_port") or parsed.get("dst_port") or parsed.get("dPort")},
                    "protocol": parsed.get("protocol") or parsed.get("proto") or "TCP"
                }
            
            # Allow direct OCSF overrides from JSON payload
            if "class_uid" in parsed:
                ocsf_base["class_uid"] = int(parsed["class_uid"])
            if "category_uid" in parsed:
                ocsf_base["category_uid"] = int(parsed["category_uid"])
            if "severity_id" in parsed:
                ocsf_base["severity_id"] = int(parsed["severity_id"])
            if "rf_activity" in parsed:
                ocsf_base["rf_activity"] = parsed["rf_activity"]

            return ocsf_base

        return ocsf_base


# Global parser instance
_ocsf_engine = OCSFParser()


def parse_line(line: str, org_id: Optional[str] = None, device_id: Optional[str] = None) -> dict[str, Any]:
    line = line.strip()
    if not line:
        return {}

    ocsf_event = _ocsf_engine.parse_raw(line, org_id=org_id, device_id=device_id) or {}

    fields: dict[str, Any] = {}

    # Extract JSON or CEF or key-values if structured
    if line.startswith("{"):
        try:
            fields = json.loads(line)
        except json.JSONDecodeError:
            fields = {}
    elif line.startswith("CEF:"):
        fields = _ocsf_engine._parse_cef(line)
    else:
        kv_matches = KV_RE.findall(line)
        if kv_matches:
            for k, v in kv_matches:
                fields[k.lower()] = _strip_quotes(v)

    normalized: dict[str, Any] = {k.lower(): v for k, v in fields.items()}
    normalized["ocsf"] = ocsf_event
    normalized["ocsf_class_uid"] = ocsf_event.get("class_uid", OCSFEventClass.PROCESS_ACTIVITY)
    normalized["ocsf_category_uid"] = ocsf_event.get("category_uid", OCSFCategory.SYSTEM_ACTIVITY)

    # Resolve IP addresses
    src_ip = _first_present(normalized, SRC_IP_KEYS)
    dest_ip = _first_present(normalized, DEST_IP_KEYS)

    if not src_ip and ocsf_event.get("src_endpoint"):
        src_ip = ocsf_event["src_endpoint"].get("ip")
    if not src_ip and ocsf_event.get("network_activity", {}).get("src_endpoint"):
        src_ip = ocsf_event["network_activity"]["src_endpoint"].get("ip")

    if not dest_ip and ocsf_event.get("network_activity", {}).get("dst_endpoint"):
        dest_ip = ocsf_event["network_activity"]["dst_endpoint"].get("ip")

    if not src_ip:
        ips_in_text = _extract_ips_from_text(line)
        if ips_in_text:
            src_ip = ips_in_text[0]
            if len(ips_in_text) > 1 and not dest_ip:
                dest_ip = ips_in_text[1]

    # Resolve user
    user = _first_present(normalized, USER_KEYS)
    if not user and ocsf_event.get("actor", {}).get("user"):
        user = ocsf_event["actor"]["user"].get("name")
    if not user:
        m = re.search(r"\buser(?:name)?\s+(\S+)", line, re.IGNORECASE)
        if m:
            user = m.group(1).strip(":,")
        else:
            m = re.search(r"\bfor\s+(?:invalid user\s+)?(\S+)\s+from\b", line, re.IGNORECASE)
            if m:
                user = m.group(1)

    # Resolve process
    process = _first_present(normalized, PROCESS_KEYS)
    if not process and ocsf_event.get("process"):
        process = ocsf_event["process"].get("name") or ocsf_event["process"].get("cmd_line")
    if not process:
        m = re.match(r"^\S+\s+\S+\s+\S+\s+([\w\-/.]+)(?:\[\d+\])?:", line)
        if m:
            process = m.group(1)

    # Classify event type
    event_type = normalized.get("event_type") or normalized.get("action")
    if not event_type:
        if ocsf_event.get("class_uid") == OCSFEventClass.AUTHENTICATION:
            event_type = "auth_failure" if ocsf_event.get("status_id") == 2 else "auth_success"
        elif ocsf_event.get("class_uid") == OCSFEventClass.USER_ACCESS:
            event_type = "privilege_use"
        elif ocsf_event.get("class_uid") == OCSFEventClass.NETWORK_ACTIVITY:
            event_type = "network_connection"
        else:
            event_type = _classify(line)

    ts_raw = normalized.get("ts") or normalized.get("timestamp") or normalized.get("time")
    ts = _parse_ts(ts_raw) or datetime.now(timezone.utc)

    return {
        "ts": ts,
        "event_type": event_type,
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "user": user,
        "process": process,
        "raw": line,
        "normalized": normalized,
    }


def _classify(line: str) -> str:
    lower = line.lower()
    if "failed password" in lower or "authentication failure" in lower:
        return "auth_failure"
    if "accepted password" in lower or "session opened" in lower:
        return "auth_success"
    if "sudo" in lower:
        return "privilege_use"
    if "connection" in lower and ("refused" in lower or "reset" in lower):
        return "network_error"
    return "generic"


def parse_log_batch(raw_text: str, org_id: Optional[str] = None, device_id: Optional[str] = None) -> list[dict[str, Any]]:
    events = []
    for line in raw_text.splitlines():
        parsed = parse_line(line, org_id=org_id, device_id=device_id)
        if parsed:
            events.append(parsed)
    return events
