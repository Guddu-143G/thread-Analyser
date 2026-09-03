import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    Column, String, DateTime, ForeignKey, Boolean, Integer, Float, Text, Enum, JSON, LargeBinary
)
from sqlalchemy.orm import relationship

from app.core.db import Base


def gen_uuid() -> str:
    return str(uuid.uuid4())


class Role(str, enum.Enum):
    admin = "admin"
    analyst = "analyst"
    viewer = "viewer"


class Severity(str, enum.Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class AlertStatus(str, enum.Enum):
    open = "open"
    acknowledged = "acknowledged"
    resolved = "resolved"
    false_positive = "false_positive"


class Organization(Base):
    __tablename__ = "organizations"
    id = Column(String, primary_key=True, default=gen_uuid)
    name = Column(String, nullable=False)
    plan = Column(String, default="free")
    created_at = Column(DateTime, default=datetime.utcnow)

    users = relationship("User", back_populates="org")
    devices = relationship("Device", back_populates="org")


class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, default=gen_uuid)
    org_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    email = Column(String, unique=True, nullable=False, index=True)
    hashed_password = Column(String, nullable=False)
    role = Column(Enum(Role), default=Role.analyst)
    created_at = Column(DateTime, default=datetime.utcnow)

    org = relationship("Organization", back_populates="users")


class Device(Base):
    __tablename__ = "devices"
    id = Column(String, primary_key=True, default=gen_uuid)
    org_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    name = Column(String, nullable=False)
    hostname = Column(String(255), nullable=True)
    agent_version = Column(String(50), default="17.0.0")
    os_name = Column(String(100), default="Linux")
    os_version = Column(String(100), default="6.5.0")
    status = Column(String(50), default="active")  # active, inactive, compromised, offline
    public_ip = Column(String(45), default="127.0.0.1")
    last_latitude = Column(Float, nullable=True)
    last_longitude = Column(Float, nullable=True)
    last_location_desc = Column(String(255), nullable=True)
    platform = Column(String, default="unknown")
    api_key_hash = Column(String, nullable=False)
    last_seen = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    org = relationship("Organization", back_populates="devices")
    heartbeats = relationship("DeviceHeartbeat", back_populates="device", cascade="all, delete-orphan")


class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"
    id = Column(String, primary_key=True, default=gen_uuid)
    org_id = Column(String, ForeignKey("organizations.id"), nullable=True)  # null = global
    type = Column(String, nullable=False)  # ip, domain, hash, process
    value = Column(String, nullable=False, index=True)
    severity = Column(Enum(Severity), default=Severity.medium)
    source = Column(String, default="manual")
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class Rule(Base):
    __tablename__ = "rules"
    id = Column(String, primary_key=True, default=gen_uuid)
    org_id = Column(String, ForeignKey("organizations.id"), nullable=True)  # null = global/built-in
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    definition = Column(JSON, nullable=False)
    severity = Column(Enum(Severity), default=Severity.medium)
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class LogEvent(Base):
    __tablename__ = "log_events"
    id = Column(String, primary_key=True, default=gen_uuid)
    org_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    device_id = Column(String, ForeignKey("devices.id"), nullable=True)
    ts = Column(DateTime, default=datetime.utcnow)
    event_type = Column(String, nullable=True)
    src_ip = Column(String, nullable=True, index=True)
    dest_ip = Column(String, nullable=True)
    user = Column(String, nullable=True)
    process = Column(String, nullable=True)
    raw = Column(Text, nullable=False)
    normalized = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class Alert(Base):
    __tablename__ = "alerts"
    id = Column(String, primary_key=True, default=gen_uuid)
    org_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    device_id = Column(String, ForeignKey("devices.id"), nullable=True)
    rule_id = Column(String, ForeignKey("rules.id"), nullable=True)
    ioc_id = Column(String, ForeignKey("threat_indicators.id"), nullable=True)
    severity = Column(Enum(Severity), default=Severity.medium)
    status = Column(Enum(AlertStatus), default=AlertStatus.open)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    evidence = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    resolved_at = Column(DateTime, nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_log"
    id = Column(String, primary_key=True, default=gen_uuid)
    org_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    actor_user_id = Column(String, ForeignKey("users.id"), nullable=True)
    action = Column(String, nullable=False)
    target = Column(String, nullable=True)
    meta = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    cryptographic_seal = Column(String(64), nullable=True)
    previous_seal = Column(String(64), nullable=True)


class TenantTechnologyInventory(Base):
    __tablename__ = "tenant_technology_inventory"
    id = Column(String, primary_key=True, default=gen_uuid)
    org_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    hostname = Column(String, nullable=True)
    technology = Column(String, nullable=False)
    detected_port = Column(Integer, nullable=True)
    confidence = Column(String, default="low")
    runtime = Column(String, nullable=True)
    category = Column(String, nullable=True)
    environment = Column(String, default="production")
    path = Column(String, nullable=True)
    first_seen = Column(DateTime, default=datetime.utcnow)


class TenantBluetoothThreat(Base):
    __tablename__ = "tenant_bluetooth_threats"
    id = Column(String, primary_key=True, default=gen_uuid)
    org_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    device_id = Column(String, ForeignKey("devices.id"), nullable=True)
    interface = Column(String, default="hci0")
    protocol = Column(String, default="L2CAP")
    attacker_mac = Column(String, nullable=False, index=True)
    rssi = Column(Integer, default=-45)
    payload_length_bytes = Column(Integer, default=65535)
    anomaly_type = Column(String, nullable=False)
    mitigation_action = Column(String, default="Host MAC Blocked")
    status = Column(String, default="BLOCKED")  # BLOCKED, CONTAINED, MONITORING
    created_at = Column(DateTime, default=datetime.utcnow)


class TPMAttestationRecord(Base):
    __tablename__ = "tpm_attestation_records"
    id = Column(String, primary_key=True, default=gen_uuid)
    org_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    device_id = Column(String, ForeignKey("devices.id"), nullable=True)
    block_hash = Column(String(64), nullable=False)
    signature = Column(Text, nullable=False)
    aik_key_id = Column(String(64), nullable=False)
    pcr_digest = Column(String(64), nullable=False)
    records_count = Column(Integer, default=1)
    verification_status = Column(String, default="VALID_HARDWARE_SEALED")
    created_at = Column(DateTime, default=datetime.utcnow)


class TenantChaosSimulation(Base):
    __tablename__ = "tenant_chaos_simulations"
    id = Column(String, primary_key=True, default=gen_uuid)
    org_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    device_id = Column(String, ForeignKey("devices.id"), nullable=True)
    simulation_id = Column(String, unique=True, index=True, default=gen_uuid)
    bug_variety = Column(String, nullable=False)
    cwe_class = Column(String, nullable=False)
    severity = Column(String, default="HIGH")
    injected_at = Column(DateTime, default=datetime.utcnow)
    detected_at = Column(DateTime, nullable=True)
    detection_latency_ms = Column(Integer, default=-1)
    alert_triggered = Column(Boolean, default=False)
    status = Column(String, default="RESOLVED_ALERT")  # RESOLVED_ALERT, UNDETECTED, TIMEOUT
    sla_compliance = Column(String, default="MET")     # MET, FAILED
    payload = Column(JSON, nullable=True)
    execution_notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"
    id = Column(String, primary_key=True, default=gen_uuid)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    token_hash = Column(String(64), unique=True, index=True, nullable=False)
    expires_at = Column(DateTime, nullable=False, index=True)
    is_redeemed = Column(Boolean, default=False, nullable=False)
    client_ip = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class ActiveUserSession(Base):
    __tablename__ = "active_user_sessions"
    id = Column(String, primary_key=True, default=gen_uuid)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    token_hash = Column(String(64), unique=True, index=True, nullable=False)
    device_info = Column(String, nullable=True)
    ip_address = Column(String(45), nullable=True)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


# ---- V13.0 Autonomous AI SOC Consensus & Cognitive Deception Models ----
class SOCConsensusEvaluation(Base):
    __tablename__ = "soc_consensus_evaluations"
    id = Column(String, primary_key=True, default=gen_uuid)
    org_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    event_uid = Column(String, index=True, nullable=False)
    composite_risk_score = Column(Float, nullable=False)
    evaluation_confidence = Column(Float, nullable=False)
    consensus_action = Column(String, nullable=False)
    agent_votes = Column(JSON, nullable=False)
    authorized_signature = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class CognitiveDecoyInstance(Base):
    __tablename__ = "cognitive_decoy_instances"
    id = Column(String, primary_key=True, default=gen_uuid)
    org_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    decoy_id = Column(String, unique=True, index=True, default=gen_uuid)
    target_stack = Column(String, nullable=False)
    port = Column(Integer, default=5432)
    ebpf_redirection_rule = Column(JSON, nullable=True)
    canary_credentials = Column(JSON, nullable=True)
    trapped_interactions_count = Column(Integer, default=0)
    status = Column(String, default="ACTIVE_SANDBOX")
    created_at = Column(DateTime, default=datetime.utcnow)


# ---- V16.0 Real-Time Tracking, Non-Destructive URL Sandbox & Email Mesh Models ----
class DeviceHeartbeatTelemetry(Base):
    __tablename__ = "device_heartbeat_telemetry"
    id = Column(String, primary_key=True, default=gen_uuid)
    org_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    device_uid = Column(String, index=True, nullable=False)
    hostname = Column(String, nullable=False)
    device_type = Column(String, default="laptop")
    os_name = Column(String, default="Unknown OS")
    os_version = Column(String, default="1.0.0")
    public_ip = Column(String(45), nullable=False)
    local_ips = Column(JSON, nullable=True)
    interfaces = Column(JSON, nullable=True)
    active_tcp_sockets = Column(Integer, default=0)
    cpu_load_percent = Column(Float, default=0.0)
    memory_used_mb = Column(Float, default=0.0)
    latitude = Column(Float, nullable=False)
    longitude = Column(Float, nullable=False)
    city = Column(String, default="Unknown City")
    country = Column(String, default="Unknown Country")
    isp = Column(String, default="Unknown ISP")
    asn = Column(Integer, default=0)
    status = Column(String, default="ACTIVE")
    last_ping = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)


class ImpossibleTravelAlert(Base):
    __tablename__ = "impossible_travel_alerts"
    id = Column(String, primary_key=True, default=gen_uuid)
    org_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    device_uid = Column(String, index=True, nullable=False)
    hostname = Column(String, nullable=False)
    prev_ip = Column(String(45), nullable=False)
    prev_location = Column(String, nullable=False)
    prev_latitude = Column(Float, nullable=False)
    prev_longitude = Column(Float, nullable=False)
    prev_time = Column(DateTime, nullable=False)
    current_ip = Column(String(45), nullable=False)
    current_location = Column(String, nullable=False)
    current_latitude = Column(Float, nullable=False)
    current_longitude = Column(Float, nullable=False)
    current_time = Column(DateTime, default=datetime.utcnow)
    distance_km = Column(Float, nullable=False)
    time_diff_minutes = Column(Float, nullable=False)
    velocity_kmh = Column(Float, nullable=False)
    severity = Column(Enum(Severity), default=Severity.high)
    status = Column(Enum(AlertStatus), default=AlertStatus.open)
    raw_ocsf = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class EmailSecurityAudit(Base):
    __tablename__ = "email_security_audits"
    id = Column(String, primary_key=True, default=gen_uuid)
    org_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    sender = Column(String, nullable=False)
    recipient = Column(String, nullable=False)
    subject = Column(String, nullable=False)
    domain = Column(String, nullable=False)
    sender_ip = Column(String(45), default="127.0.0.1")
    spf_status = Column(String(10), default="NONE")  # PASS, FAIL, NONE
    dkim_status = Column(String(10), default="NONE")  # PASS, FAIL, NONE
    dmarc_status = Column(String(10), default="NONE") # PASS, FAIL, NONE
    spam_hits = Column(Integer, default=0)
    risk_score = Column(Float, default=0.0)
    severity = Column(Enum(Severity), default=Severity.low)
    urls_found = Column(JSON, nullable=True)
    phishing_indicators = Column(JSON, nullable=True)
    raw_ocsf = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class URLSandboxInspection(Base):
    __tablename__ = "url_sandbox_inspections"
    id = Column(String, primary_key=True, default=gen_uuid)
    org_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    url = Column(Text, nullable=False)
    domain = Column(String, nullable=False)
    url_hash = Column(String(64), index=True, nullable=False)
    tier_matched = Column(String, default="Tier-01: Local Intel")
    is_malicious = Column(Boolean, default=False)
    severity = Column(Enum(Severity), default=Severity.low)
    detection_reason = Column(Text, nullable=False)
    emulation_triggered = Column(Boolean, default=False)
    sandbox_screenshot_path = Column(String, nullable=True)
    dom_metadata = Column(JSON, nullable=True)
    raw_ocsf = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


# ==========================================
# VERSION 17 NEON SERVERLESS & RLS MODELS
# ==========================================

class DeviceHeartbeat(Base):
    __tablename__ = "v17_device_heartbeats"
    id = Column(String, primary_key=True, default=gen_uuid)
    device_id = Column(String, ForeignKey("devices.id"), nullable=False)
    org_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    cpu_usage_pct = Column(Float, default=0.0)
    memory_usage_pct = Column(Float, default=0.0)
    disk_usage_pct = Column(Float, default=0.0)
    battery_pct = Column(Float, default=100.0)
    active_process_count = Column(Integer, default=0)
    listening_port_count = Column(Integer, default=0)
    reported_ip = Column(String(45), default="127.0.0.1")
    impossible_travel_triggered = Column(Boolean, default=False)

    device = relationship("Device", back_populates="heartbeats")


class EmailScan(Base):
    __tablename__ = "email_scans"
    id = Column(String, primary_key=True, default=gen_uuid)
    org_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    sender = Column(String(320), nullable=False)
    recipient = Column(String(320), nullable=False)
    subject = Column(String(998), nullable=False)
    sender_ip = Column(String(45), default="127.0.0.1")
    spf_status = Column(String(20), default="NONE")       # PASS, FAIL, NONE, ERROR
    dkim_status = Column(String(20), default="NONE")      # PASS, FAIL, NONE, ERROR
    dmarc_status = Column(String(20), default="NONE")     # PASS, FAIL, NONE, ERROR
    spam_text_score = Column(Float, default=0.0)
    is_phishing = Column(Boolean, default=False)
    raw_headers = Column(JSON, default=dict)
    extracted_urls = Column(JSON, default=list)
    risk_score = Column(Float, default=0.0)
    action_taken = Column(String(100), default="delivered") # quarantined, marked_spam, delivered


class URLScan(Base):
    __tablename__ = "url_scans"
    id = Column(String, primary_key=True, default=gen_uuid)
    org_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    original_url = Column(Text, nullable=False)
    target_domain = Column(String(253), nullable=False)
    url_hash = Column(String(64), index=True, nullable=False)
    reputation_score = Column(Float, default=0.0)
    dnsbl_listed = Column(Boolean, default=False)
    headless_sandbox_triggered = Column(Boolean, default=False)
    redirect_chain = Column(JSON, default=list)
    screenshot_blob_url = Column(Text, nullable=True)
    rendered_dom_hash = Column(String(64), nullable=True)
    malicious_status = Column(Boolean, default=False)
    detection_summary = Column(Text, nullable=True)


class AnomalyLog(Base):
    __tablename__ = "anomaly_logs"
    id = Column(String, primary_key=True, default=gen_uuid)
    org_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    event_class_uid = Column(Integer, default=2004)
    source_log_payload = Column(Text, nullable=False)
    raw_anomaly_score = Column(Float, default=0.0)
    is_anomaly = Column(Boolean, default=False)
    model_version = Column(String(50), default="IsolationForest-v2.1")
    features_analyzed = Column(JSON, default=dict)
    attribution_reasons = Column(JSON, default=list)
    analyst_triage_status = Column(String(50), default="unassigned") # unassigned, investigating, resolved


# =========================================================================
# VERSION 18 ZERO-TRUST LIVE RESPONSE & REMOTE TERMINAL MESH MODELS
# =========================================================================

class LiveResponseSession(Base):
    __tablename__ = "live_response_sessions"
    session_id = Column(String, primary_key=True, default=gen_uuid)
    org_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    device_id = Column(String, ForeignKey("devices.id"), nullable=False)
    analyst_id = Column(String, ForeignKey("users.id"), nullable=False)
    approver_id = Column(String, ForeignKey("users.id"), nullable=True) # NULL until dual-authorization is signed
    created_at = Column(DateTime, default=datetime.utcnow)
    closed_at = Column(DateTime, nullable=True)
    status = Column(String(30), default="PENDING_APPROVAL") # PENDING_APPROVAL, ACTIVE, CLOSED, REJECTED
    auth_token_hash = Column(String(64), nullable=False)
    encryption_key_hex = Column(String(128), nullable=False)

    device = relationship("Device")
    commands = relationship("LiveResponseCommand", back_populates="session", cascade="all, delete-orphan")
    keystrokes = relationship("TerminalKeystroke", back_populates="session", cascade="all, delete-orphan")


class LiveResponseCommand(Base):
    __tablename__ = "live_response_commands"
    command_id = Column(String, primary_key=True, default=gen_uuid)
    session_id = Column(String, ForeignKey("live_response_sessions.session_id"), nullable=False)
    org_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    command_string = Column(Text, nullable=False)
    executed_by = Column(String, ForeignKey("users.id"), nullable=False)
    dispatched_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    exit_code = Column(Integer, nullable=True)
    raw_output = Column(Text, nullable=True)
    raw_output_compressed = Column(LargeBinary, nullable=True)

    session = relationship("LiveResponseSession", back_populates="commands")


class TerminalKeystroke(Base):
    __tablename__ = "terminal_keystrokes"
    keystroke_id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String, ForeignKey("live_response_sessions.session_id"), nullable=False)
    org_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    direction = Column(String(4), nullable=False) # 'IN' or 'OUT'
    timestamp = Column(DateTime, default=datetime.utcnow)
    data = Column(Text, nullable=False)

    session = relationship("LiveResponseSession", back_populates="keystrokes")


# =========================================================================
# VERSION 19 INTERACTIVE FLEET C2, OSQUERY & GIS AUDITING MODELS
# =========================================================================

class LiveQueryRun(Base):
    __tablename__ = "live_query_runs"
    query_run_id = Column(String, primary_key=True, default=gen_uuid)
    org_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    analyst_id = Column(String, ForeignKey("users.id"), nullable=False)
    sql_statement = Column(Text, nullable=False)
    target_filter = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)
    status = Column(String(30), default="DISPATCHED") # DISPATCHED, EXECUTED, COMPLETED, FAILED

    results = relationship("LiveQueryResult", back_populates="query_run", cascade="all, delete-orphan")


class LiveQueryResult(Base):
    __tablename__ = "live_query_results"
    result_id = Column(String, primary_key=True, default=gen_uuid)
    org_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    query_run_id = Column(String, ForeignKey("live_query_runs.query_run_id"), nullable=False)
    device_id = Column(String, ForeignKey("devices.id"), nullable=False)
    returned_data = Column(JSON, default=list) # Tabular rows
    executed_at = Column(DateTime, default=datetime.utcnow)

    device = relationship("Device")
    query_run = relationship("LiveQueryRun", back_populates="results")


class RemoteFileTransfer(Base):
    __tablename__ = "remote_file_transfers"
    transfer_id = Column(String, primary_key=True, default=gen_uuid)
    org_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    device_id = Column(String, ForeignKey("devices.id"), nullable=False)
    analyst_id = Column(String, ForeignKey("users.id"), nullable=False)
    transfer_direction = Column(String(10), nullable=False) # UPLOAD, DOWNLOAD
    local_file_path = Column(Text, nullable=False)
    server_storage_url = Column(Text, nullable=False)
    file_size_bytes = Column(Integer, default=0)
    sha256_hash = Column(String(64), nullable=False)
    transferred_at = Column(DateTime, default=datetime.utcnow)

    device = relationship("Device")


class FleetActionLog(Base):
    __tablename__ = "fleet_action_logs"
    action_id = Column(String, primary_key=True, default=gen_uuid)
    org_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    device_id = Column(String, ForeignKey("devices.id"), nullable=False)
    analyst_id = Column(String, ForeignKey("users.id"), nullable=False)
    action_type = Column(String(30), nullable=False) # KILL_PROCESS, ISOLATE_HOST, UNISOLATE_HOST, SERVICE_RESTART
    target_parameters = Column(JSON, default=dict)
    execution_status = Column(String(20), default="PENDING") # PENDING, SUCCESS, FAILED
    error_message = Column(Text, nullable=True)
    logged_at = Column(DateTime, default=datetime.utcnow)

    device = relationship("Device")


# ---------------------------------------------------------
# Version 20: Dynamic Edge Remediation & Adaptive GPS Mesh Models
# ---------------------------------------------------------

class DeviceLocationLog(Base):
    __tablename__ = "device_location_logs"
    log_id = Column(String, primary_key=True, default=gen_uuid)
    org_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    device_id = Column(String, ForeignKey("devices.id"), nullable=False)
    latitude = Column(Float, nullable=False)
    longitude = Column(Float, nullable=False)
    altitude = Column(Float, nullable=True)
    speed_mps = Column(Float, default=0.0)
    horizontal_accuracy = Column(Float, nullable=True)
    battery_level = Column(Integer, nullable=True) # 0 to 100
    power_source = Column(String(20), default="BATTERY") # BATTERY, AC
    tracking_state = Column(String(30), nullable=False, default="STATIONARY") # STATIONARY, ACTIVE_TRANSIT, LOW_POWER, GEOFENCE_BREACH, STANDARD_MOTION
    polling_interval_seconds = Column(Integer, default=60)
    tracked_at = Column(DateTime, default=datetime.utcnow)

    device = relationship("Device")


class LiveTerminalStream(Base):
    __tablename__ = "live_terminal_streams"
    command_id = Column(String, primary_key=True, default=gen_uuid)
    session_id = Column(String, ForeignKey("live_response_sessions.session_id"), nullable=False)
    org_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    command_input = Column(Text, nullable=False)
    command_output_summary = Column(Text, nullable=True)
    exit_code = Column(Integer, default=0)
    executed_at = Column(DateTime, default=datetime.utcnow)

    session = relationship("LiveResponseSession")
