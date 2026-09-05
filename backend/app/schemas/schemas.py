from datetime import datetime
from typing import Optional, Any, List, Dict, Union

from pydantic import BaseModel, EmailStr, ConfigDict, Field


# ---- Auth ----
class RegisterRequest(BaseModel):
    org_name: str
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    email: str
    role: str
    org_id: str


# ---- Devices ----
class DeviceCreate(BaseModel):
    name: str
    platform: Optional[str] = "unknown"


class DeviceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    name: str
    platform: str
    last_seen: Optional[datetime] = None
    created_at: datetime


class DeviceCreatedOut(DeviceOut):
    api_key: str  # only returned once, at creation/rotation


# ---- Threat Indicators (IOCs) ----
class IOCCreate(BaseModel):
    type: str
    value: str
    severity: str = "medium"
    description: Optional[str] = None


class IOCOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    type: str
    value: str
    severity: str
    source: str
    description: Optional[str] = None
    created_at: datetime


# ---- Rules ----
class RuleCreate(BaseModel):
    name: str
    description: Optional[str] = None
    definition: dict[str, Any]
    severity: str = "medium"
    enabled: bool = True


class RuleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    definition: Optional[dict[str, Any]] = None
    severity: Optional[str] = None
    enabled: Optional[bool] = None


class RuleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    name: str
    description: Optional[str] = None
    definition: dict[str, Any]
    severity: str
    enabled: bool
    created_at: datetime


# ---- Alerts ----
class AlertUpdate(BaseModel):
    status: Optional[str] = None
    comment: Optional[str] = None


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    device_id: Optional[str] = None
    rule_id: Optional[str] = None
    ioc_id: Optional[str] = None
    severity: str
    status: str
    title: str
    description: Optional[str] = None
    evidence: Optional[dict] = None
    created_at: datetime
    resolved_at: Optional[datetime] = None


class MitigateRequest(BaseModel):
    action: str  # "isolate_host", "terminate_process", "block_ip"
    target: Optional[str] = None
    comment: Optional[str] = None


class MitigateResponse(BaseModel):
    status: str
    message: str
    alert_id: str
    action: str
    mitigated_at: datetime


# ---- Ingestion & Normalized Events ----
class IngestResult(BaseModel):
    accepted_events: int
    queued: bool = True


class LogEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    device_id: Optional[str] = None
    ts: datetime
    event_type: Optional[str] = None
    src_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    user: Optional[str] = None
    process: Optional[str] = None
    raw: str
    normalized: Optional[dict] = None
    created_at: datetime


# ---- Audit Logs ----
class AuditLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    actor_user_id: Optional[str] = None
    action: str
    target: Optional[str] = None
    meta: Optional[dict] = None
    created_at: datetime
    cryptographic_seal: Optional[str] = None
    previous_seal: Optional[str] = None


class AuditVerificationResult(BaseModel):
    valid: bool
    records_verified: int
    latest_seal: str
    message: str
    tampered_index: Optional[int] = None
    expected_seal: Optional[str] = None
    stored_seal: Optional[str] = None



# ---- Dashboard ----
class DashboardStats(BaseModel):
    total_events: int
    total_alerts: int
    open_alerts: int
    alerts_by_severity: dict[str, int]
    top_devices: list[dict[str, Any]]
    top_source_ips: list[dict[str, Any]]


# ---- V9.0 Passive SBOM Extraction ----
class TechnologyInventoryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    hostname: Optional[str] = None
    technology: str
    detected_port: Optional[int] = None
    confidence: str
    runtime: Optional[str] = None
    category: Optional[str] = None
    environment: Optional[str] = "production"
    path: Optional[str] = None
    first_seen: datetime


# ---- V9.0 Bluetooth Module HCI Guard ----
class BluetoothThreatOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    interface: str
    protocol: str
    attacker_mac: str
    rssi: int
    payload_length_bytes: int
    anomaly_type: str
    mitigation_action: str
    status: str
    created_at: datetime


class BluetoothContainmentRequest(BaseModel):
    attacker_mac: str
    action: Optional[str] = "block_mac"  # "block_mac" | "rfkill_radio"
    interface: Optional[str] = "hci0"


class BluetoothContainmentResponse(BaseModel):
    status: str
    action_dispatched: str
    target_mac: str
    interface: str
    containment_verdict: str
    timestamp: datetime


class BluetoothSimulateRequest(BaseModel):
    exploit_vector: Optional[str] = "BLUEBORNE_L2CAP_OVERFLOW"  # "BLUEBORNE_L2CAP_OVERFLOW" | "BLEEDINGTOOTH_ZERO_CLICK" | "BLE_ROGUE_PAIRING"
    source_mac: Optional[str] = "00:1A:7D:DA:71:11"
    payload_size: Optional[int] = 65535


# ---- V9.0 TPM 2.0 Hardware-Rooted Attestation ----
class TPMAttestationRecordOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    block_hash: str
    signature: str
    aik_key_id: str
    pcr_digest: str
    records_count: int
    verification_status: str
    created_at: datetime


class TPMAttestationStatus(BaseModel):
    tpm_version: str
    hardware_status: str
    aik_enrolled: bool
    aik_public_fingerprint: str
    pcr_banks: dict[str, str]
    immutable_chain_height: int
    latest_block_hash: str


class TPMSignBlockRequest(BaseModel):
    log_records: list[dict[str, Any]]
    device_id: Optional[str] = None


class TPMSignBlockResponse(BaseModel):
    status: str
    block_hash: str
    hardware_signature: str
    aik_key_id: str
    pcr_digest: str
    records_signed: int
    timestamp: datetime


class TPMVerifyChainRequest(BaseModel):
    limit: Optional[int] = 50


class TPMVerifyChainResponse(BaseModel):
    valid: bool
    records_verified: int
    aik_key_id: str
    hardware_seal_status: str
    merkle_root: str
    message: str


# ---- V9.0 Targeted Stack Deception ----
class TargetedDecoyRequest(BaseModel):
    technology: str  # "PostgreSQL", "FastAPI", "Spring Boot", "ExpressJS", "Redis"
    hostname: Optional[str] = "prod-app-01"


# ---- V10.0 Security Chaos Engineering (SCE) & Defect Simulation ----
class ChaosInjectRequest(BaseModel):
    bug_variety: str  # e.g. "Tenant Isolation Bypass", "Buffer Overflow Attempt", "BlueBorne L2CAP Overflow", "Model Evasion Attempt", "SQL Injection Attempt", "Insecure Transmit Protocol", "Resource Exhaustion"
    target_org_id: Optional[str] = "org_enterprise_tenant_target"
    target_mac: Optional[str] = "00:1A:7D:DA:99:88"
    baseline_rate_eps: Optional[float] = 1.0
    payload_override: Optional[dict[str, Any]] = None


class ChaosInjectResponse(BaseModel):
    simulation_id: str
    status: str
    bug_variety: str
    cwe_class: str
    severity: str
    injected_at: datetime
    detected_at: Optional[datetime] = None
    detection_latency_ms: int
    alert_triggered: bool
    sla_compliance: str
    payload: dict[str, Any]
    execution_notes: str
    alert_id: Optional[str] = None


class ChaosSimulationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    simulation_id: str
    bug_variety: str
    cwe_class: str
    severity: str
    injected_at: datetime
    detected_at: Optional[datetime] = None
    detection_latency_ms: int
    alert_triggered: bool
    status: str
    sla_compliance: str
    payload: Optional[dict[str, Any]] = None
    execution_notes: Optional[str] = None
    created_at: datetime


class ResilienceReportMetrics(BaseModel):
    total_fault_simulations_run: int
    successfully_blocked_and_logged: int
    defensive_coverage_index: float
    unique_cwe_classes_tested: int
    remediations_required_count: int
    avg_detection_latency_ms: float
    sla_met_count: int
    sla_failed_count: int


class ResilienceReportCompliance(BaseModel):
    assessment_tier: str
    recommending_active_mitigations: bool


class ResilienceReportOut(BaseModel):
    tenant_uid: str
    report_reference: str
    report_generation_timestamp: int
    metrics: ResilienceReportMetrics
    compliance_evaluation: ResilienceReportCompliance
    detailed_simulation_ledger: list[dict[str, Any]]
    markdown_report: str


class DefectTaxonomyItem(BaseModel):
    defect_class: str
    bug_variety: str
    cwe_mapping: str
    severity: str
    simulation_method: str
    description: str


class BugVulnerabilityItem(BaseModel):
    id: str
    cwe_class: str
    name: str
    severity: float
    remediation: str


class BugVersionProfileOut(BaseModel):
    software_id: str
    software_name: str
    detected_version: str
    vulnerabilities: list[BugVulnerabilityItem]
    verification_test_available: bool
    simulation_handler_id: str


# ---- V11.0 Neon Auth & Password Recovery ----
class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordSubmit(BaseModel):
    token: str = Field(..., min_length=32)
    new_password: str = Field(..., min_length=8, description="Must meet password complexity")


class ValidateResetTokenResponse(BaseModel):
    valid: bool
    email: Optional[str] = None
    expires_at: Optional[datetime] = None
    message: str


class GenericMessageResponse(BaseModel):
    message: str
    dev_token_preview: Optional[str] = None
    dev_reset_link: Optional[str] = None


class NeonAuthStatusOut(BaseModel):
    neon_auth_enabled: bool
    pg_session_jwt: str
    neon_authorize_rls: str
    jwks_url: str
    active_branch: str
    sync_schema: str


# ---- V13.0 Autonomous AI SOC Consensus & Deception Schemas ----
class ConsensusAgentVote(BaseModel):
    risk: float
    confidence: float
    vote_isolate: bool
    detail: str


class ConsensusTriageRequest(BaseModel):
    event_uid: Optional[str] = None
    hostname: Optional[str] = "finance-workstation-01"
    process_cmd: Optional[str] = "powershell.exe -EncodedCommand BASE64DUMP..."
    src_ip: Optional[str] = "185.220.101.5"
    src_port: Optional[int] = 49210
    severity: Optional[int] = 4
    raw_event: Optional[dict[str, Any]] = None


class ConsensusTriageResponse(BaseModel):
    event_uid: str
    timestamp: float
    composite_risk_score: float
    evaluation_confidence: float
    consensus_action: str
    agent_votes: dict[str, ConsensusAgentVote]
    authorized_signature: Optional[str] = None
    majority_verdict: str
    execution_status: str


class CognitiveDecoyTriggerRequest(BaseModel):
    attacker_ip: str = "198.51.100.44"
    target_port: int = 5432
    target_stack: str = "PostgreSQL 16.1 (Production Cluster)"


class CognitiveDecoyOut(BaseModel):
    decoy_id: str
    target_stack: str
    port: int
    ebpf_redirection_rule: dict[str, Any]
    canary_credentials: dict[str, Any]
    trapped_interactions_count: int
    status: str
    spawn_latency_ms: float
    created_at: datetime


class DPUStatusOut(BaseModel):
    dpu_model: str
    acceleration_engine: str
    current_eps: int
    hardware_terminated_tls: bool
    dma_kernel_bypass: bool
    in_silicon_ocsf_normalization: bool
    packet_loss_ratio: float
    avg_latency_microseconds: float
    status: str


class GNNMeshOut(BaseModel):
    mesh_topology: str
    active_tenant_nodes: int
    privacy_mechanism: str
    differential_privacy_epsilon: float
    smpc_aggregation_status: str
    global_model_version: str
    coordinated_campaigns_detected: int
    global_threat_level: str


# ==========================================
# Version 12.0 Real-Time Telemetry & WebSocket Schemas
# ==========================================

class RealtimeMetricsOut(BaseModel):
    current_eps: int
    average_eps_60s: float
    pipeline_latency_ms: float
    healthy: bool
    sla_target_ms: float
    window_duration_seconds: int
    timestamp: float


class AgentHeartbeatRequest(BaseModel):
    device_id: str
    hostname: str
    os_version: Optional[str] = "Linux x86_64"
    agent_version: Optional[str] = "v12.0.4-stream"


class AgentHeartbeatOut(BaseModel):
    device_id: str
    hostname: str
    status: str
    last_seen: float
    ttl_seconds: int


class FleetDeviceStatusOut(BaseModel):
    device_id: str
    hostname: str
    os_version: str
    agent_version: str
    status: str
    last_seen: float
    latency_sec: Optional[float] = None


class SimulateLogRequest(BaseModel):
    count: int = 10
    event_type: str = "raw_logs"
    severity_id: int = 2
    class_name: str = "Process Activity"
    message: Optional[str] = "Synthetic high-frequency agent telemetry event"
    hostname: Optional[str] = "prod-api-gateway-01"


class AlertLockRequest(BaseModel):
    alert_id: str
    action: str = "acquire_lock"


class AlertLockOut(BaseModel):
    alert_id: str
    locked_by: str
    locked_at: float
    status: str


class WebSocketStatusOut(BaseModel):
    active_connections_count: int
    active_tenants_connected: int
    redis_pubsub_channel_pattern: str
    server_status: str
    supported_stream_events: list[str]


# ==========================================
# Version 14.0 Sovereign Edge & Zero-Trust Schemas
# ==========================================

class STRIDEThreatItem(BaseModel):
    threat_id: str
    threat_class: str
    element: str
    severity: str
    cwe_id: str
    description: str
    mitigation: str


class STRIDEModelSummaryOut(BaseModel):
    total_nodes: int
    total_edges: int
    nodes: list[dict[str, Any]]
    edges: list[dict[str, Any]]
    threats: list[STRIDEThreatItem]
    total_threats_identified: int
    stride_breakdown: dict[str, int]
    architecture_health_score: float
    evaluation_standard: str
    status: str


class EvaluateTopologyRequest(BaseModel):
    connections: Optional[list[dict[str, Any]]] = None


class ZKPSIMatchRequest(BaseModel):
    party_a_name: str = "Organization Alpha (Defense Corp)"
    party_a_indicators: list[str] = [
        "185.220.101.5",
        "d41d8cd98f00b204e9800998ecf8427e",
        "apt29-c2-beacon.darknet.org",
        "mimikatz_x64.dll",
        "198.51.100.44",
    ]
    party_b_name: str = "Organization Beta (Financial Cloud)"
    party_b_indicators: list[str] = [
        "185.220.101.5",
        "legit-azure-login.microsoft.com",
        "apt29-c2-beacon.darknet.org",
        "system_update_patch_99.bin",
    ]


class ZKPSIMatchOut(BaseModel):
    protocol: str
    prime_field: str
    org_a_count: int
    org_b_count: int
    intersection_matches_count: int
    matched_indicators: list[dict[str, Any]]
    zero_knowledge_proof_valid: bool
    information_leakage_bytes: int


class MMRPeakOut(BaseModel):
    root_hash: str
    total_audit_leaves: int
    peak_count: int
    peaks: list[dict[str, Any]]
    tamper_resistance_status: str


class MMRVerifyProofRequest(BaseModel):
    leaf_index: int = 0
    claimed_root: str


class MMRVerifyProofOut(BaseModel):
    leaf_index: int
    leaf_hash: str
    entry_payload: dict[str, Any]
    root_hash: str
    proof_path: list[dict[str, Any]]
    total_leaves: int
    peak_count: int
    cryptographic_proof_status: str


class WasmPluginOut(BaseModel):
    plugin_id: str
    name: str
    version: str
    runtime_target: str
    wasm_sha256: str
    author: str
    bytecode_size_kb: float
    sandbox_memory_limit_mb: float
    syscalls_granted: int
    allowed_capabilities: list[str]
    signature_status: str
    active_deployed_endpoints: int
    created_at: str


class WasmDeployRequest(BaseModel):
    name: str = "Sigma Fast Parser"
    version: str = "2.5.0"
    allowed_capabilities: list[str] = ["read_proc_names", "parse_ocsf_json", "sigma_evaluate"]


class WasmTestExecutionRequest(BaseModel):
    plugin_id: str = "wasm-sigma-engine-v2"
    sample_payload: str = "powershell.exe -ExecutionPolicy Bypass -Command whoami /priv"


class WasmTestExecutionOut(BaseModel):
    plugin_id: str
    execution_runtime: str
    heap_consumed_kb: float
    execution_latency_microseconds: float
    host_isolation_violation_count: int
    detection_triggered: bool
    ocsf_output_event: dict[str, Any]


class SDRRFTelemetryOut(BaseModel):
    center_frequency_mhz: float
    bandwidth_mhz: float
    signal_to_noise_ratio_db: float
    iq_sample_entropy: float
    signal_power_dbm: float
    spectrum_band: str
    anomaly_detected: bool
    airspace_threat_type: Optional[str]
    hardware_sdr_frontend: str
    timestamp: float


class BGPRouteLeakOut(BaseModel):
    target_prefix: str
    origin_as: int
    origin_as_name: str
    observed_as_path: list[int]
    hijack_detected: bool
    leak_confidence: float
    mitigation_action: str
    route_views_feed_status: str


# ==========================================
# Version 15.0 Post-Quantum & Hardware Mesh Schemas
# ==========================================

class PQCHandshakeRequest(BaseModel):
    node_id: str = "agent-node-perimeter-01"
    client_pqc_pub: Optional[str] = None
    client_classical_pub: Optional[str] = None


class PQCHandshakeOut(BaseModel):
    node_id: str
    pqc_metadata: dict[str, str]
    ml_kem_1024_public_key: str
    x25519_public_key: str
    ml_dsa_87_verify_key: str
    ed25519_verify_key: str
    handshake_status: str


class PQCEnvelopeRequest(BaseModel):
    raw_payload: dict[str, Any] = {"event": "PROCESS_SPAWN", "user": "root", "cmd": "/bin/sh"}


class PQCEnvelopeOut(BaseModel):
    pqc_metadata: dict[str, str]
    encapsulated_key_hex: str
    agent_signature_hex: str
    encrypted_payload: dict[str, str]
    security_posture: str


class PMUMetricsOut(BaseModel):
    metadata: dict[str, Any]
    category_uid: int
    severity_id: int
    time: int
    hardware_metrics: dict[str, Any]
    attack_analysis: dict[str, Any]
    device: dict[str, str]


class PMUSimulateAttackRequest(BaseModel):
    attack_type: str = "flush_reload"  # flush_reload | spectre_v1 | rowhammer_bitflip | normal


class GARTRunLoopRequest(BaseModel):
    seed_id: Optional[str] = "SEED-01"


class GARTPatchOut(BaseModel):
    patch_id: str
    seed_id: str
    target_attack: Optional[str] = None
    evasion_technique: str
    bypassed_payload_sample: Optional[str] = None
    synthesized_rule_yaml: str
    resilience_score: float
    created_at: str
    status: str


class GARTRunLoopOut(BaseModel):
    cycle_status: str
    seed_attack: dict[str, Any]
    mutations_tested: int
    evasions_discovered: int
    mutations: list[dict[str, Any]]
    synthesized_patch: Optional[GARTPatchOut] = None
    total_active_patches: int


class ZKRollupCommitRequest(BaseModel):
    indicator: str = "185.220.101.5"
    indicator_type: str = "ipv4"
    confidence: float = 0.95


class ZKRollupCommitOut(BaseModel):
    status: str
    active_batch_id: int
    blinded_hash: str
    current_state_root: str
    pending_batch_size: int


class ZKRollupStateOut(BaseModel):
    genesis_state_root: str
    current_state_root: str
    total_sealed_batches: int
    pending_commitments_count: int
    sealed_batches: list[dict[str, Any]]
    zk_proof_system: str
    tamper_resistance: str


# =========================================================================
# V16.0 Sovereign Real-Time Tracking, URL Sandbox & Email Mesh Schemas
# =========================================================================

class DeviceHeartbeatIn(BaseModel):
    device_uid: str = Field(..., description="Unique hardware or UUID identifier of device")
    hostname: str = "win-laptop-89a"
    device_type: str = "laptop"
    os_name: str = "Windows 11 Enterprise"
    os_version: str = "10.0.22631"
    public_ip: str = "185.190.140.2"
    local_ips: Optional[list[str]] = ["192.168.1.45"]
    interfaces: Optional[list[str]] = ["Ethernet0", "wlan0"]
    active_tcp_sockets: int = 14
    cpu_load_percent: float = 18.5
    memory_used_mb: float = 4096.0
    latitude: Optional[float] = None
    longitude: Optional[float] = None


class DeviceHeartbeatOut(BaseModel):
    status: str
    device_uid: str
    hostname: str
    public_ip: str
    location: dict[str, Any]
    ocsf_5001: dict[str, Any]
    impossible_travel_detected: bool = False
    impossible_travel_details: Optional[dict[str, Any]] = None


class ImpossibleTravelSimulateRequest(BaseModel):
    device_uid: str = "dev_exec_laptop_01"
    hostname: str = "exec-thinkpad-x1"
    origin_ip: str = "185.190.140.2"       # London
    destination_ip: str = "203.0.113.88"     # Tokyo
    time_delta_minutes: float = 12.0


class ImpossibleTravelAlertOut(BaseModel):
    id: str
    device_uid: str
    hostname: str
    prev_ip: str
    prev_location: str
    current_ip: str
    current_location: str
    distance_km: float
    time_diff_minutes: float
    velocity_kmh: float
    severity: str
    status: str
    created_at: datetime


class EmailScanRequest(BaseModel):
    raw_eml: Optional[str] = None
    sender: Optional[str] = None
    recipient: Optional[str] = None
    subject: Optional[str] = None
    body_text: Optional[str] = None
    sender_ip: str = "185.220.101.5"


class EmailScanOut(BaseModel):
    status: str
    from_address: str
    to_address: list[str]
    subject: str
    domain: str
    sender_ip: str
    spf_status: str
    dkim_status: str
    dmarc_status: str
    spam_hits: int
    risk_score: float
    severity: str
    is_phishing_or_spam: bool
    urls_found: list[str]
    phishing_indicators: list[dict[str, Any]]
    ocsf_4009: dict[str, Any]


class URLScanRequest(BaseModel):
    url: str = Field(..., description="Target URL to inspect without client execution")
    force_sandbox: bool = False


class URLScanOut(BaseModel):
    status: str
    url: str
    domain: str
    url_hash: str
    tier_matched: str
    is_malicious: bool
    severity: str
    detection_reason: str
    emulation_triggered: bool
    sandbox_screenshot_path: Optional[str] = None
    dom_metadata: Optional[dict[str, Any]] = None
    ocsf_4002: dict[str, Any]


class V16MeshStatsOut(BaseModel):
    total_heartbeats_processed: int
    active_devices_count: int
    impossible_travel_alerts_count: int
    emails_scanned_count: int
    phishing_blocked_count: int
    urls_inspected_count: int
    malicious_urls_isolated: int
    realtime_websocket_active_tenants: int
    mesh_integrity_score: str


# ==========================================
# VERSION 17 NEON SERVERLESS & RLS SCHEMAS
# ==========================================

class V17DeviceTelemetryIn(BaseModel):
    device_id: str
    hostname: Optional[str] = None
    public_ip: str = "185.190.140.2"
    latitude: float = 51.5074
    longitude: float = -0.1278
    location_desc: str = "London, United Kingdom"
    cpu_usage: float = 5.0
    memory_usage: float = 22.0
    disk_usage: float = 45.0
    battery: float = 100.0
    processes: int = 120
    ports: int = 15
    agent_version: str = "17.0.0"
    os_name: str = "Linux"
    os_version: str = "6.5.0"


class V17DeviceTelemetryOut(BaseModel):
    device_id: str
    status: str
    impossible_travel: bool
    calculated_speed_kmh: float
    distance_km: float
    heartbeat_id: str
    public_ip: str
    location: str
    battery_pct: float
    cpu_usage_pct: float
    memory_usage_pct: float
    disk_usage_pct: float
    active_process_count: int
    listening_port_count: int


class V17DeviceOut(BaseModel):
    id: str
    org_id: str
    name: str
    hostname: Optional[str] = None
    status: str
    public_ip: str
    last_latitude: Optional[float] = None
    last_longitude: Optional[float] = None
    last_location_desc: Optional[str] = None
    agent_version: str
    os_name: str
    os_version: str
    last_seen: Optional[datetime] = None
    created_at: Optional[datetime] = None


class V17DeviceHeartbeatOut(BaseModel):
    id: str
    device_id: str
    org_id: str
    timestamp: datetime
    cpu_usage_pct: float
    memory_usage_pct: float
    disk_usage_pct: float
    battery_pct: float
    active_process_count: int
    listening_port_count: int
    reported_ip: str
    impossible_travel_triggered: bool


class V17EmailAuditIn(BaseModel):
    sender: str
    recipient: str = "analyst@acme.corp"
    subject: str
    body: str
    sender_ip: str = "127.0.0.1"
    spf_override: Optional[str] = None
    headers: Optional[dict[str, Any]] = None


class V17EmailAuditOut(BaseModel):
    scan_id: str
    sender: str
    recipient: str
    subject: str
    spf_status: str
    dkim_status: str
    dmarc_status: str
    spam_text_score: float
    risk_score: float
    is_phishing: bool
    urls_harvested: list[str]
    action_taken: str
    timestamp: str


class V17URLAuditIn(BaseModel):
    url: str


class V17URLAuditOut(BaseModel):
    scan_id: str
    url: str
    domain: str
    url_hash: str
    cached: bool
    malicious: bool
    reputation_score: float
    dnsbl_listed: bool
    headless_sandbox_triggered: bool
    redirect_chain: list[dict[str, Any]]
    screenshot: Optional[str] = None
    detection_summary: Optional[str] = None
    timestamp: str


class V17AnomalyTrackIn(BaseModel):
    model_config = {"protected_namespaces": ()}
    event_class: int = 2004
    raw_payload: str
    score: float = 0.85
    metrics: dict[str, Any] = Field(default_factory=dict)
    reasons: list[str] = Field(default_factory=list)
    model_version: str = "IsolationForest-v2.1"


class V17AnomalyTrackOut(BaseModel):
    model_config = {"protected_namespaces": ()}
    alert_id: str
    org_id: str
    timestamp: str
    class_uid: int
    score: float
    is_anomaly: bool
    reasons: list[str]
    metrics: dict[str, Any]
    model_version: str
    triage_status: str


class V17AnomalyTriageUpdateIn(BaseModel):
    triage_status: str = Field(..., description="unassigned, investigating, or resolved")


class V17NeonStatusOut(BaseModel):
    database_core: str
    branch: str
    rls_enabled: bool
    rls_policies: list[str]
    connection_pool: str
    active_devices_count: int
    total_heartbeats_logged: int
    total_email_scans_logged: int
    total_url_scans_logged: int
    total_anomaly_traces_logged: int
    system_integrity: str


# =========================================================================
# VERSION 18 LIVE RESPONSE & REMOTE TERMINAL MESH SCHEMAS
# =========================================================================

class V18SessionRequestIn(BaseModel):
    device_id: str = Field(..., description="Target enrolled device UUID or hostname")


class V18SessionApproveIn(BaseModel):
    approver_signature: Optional[str] = Field(None, description="Dual-authorization cryptographic signature")


class V18SessionRejectIn(BaseModel):
    reason: str = Field("Administrative policy veto", description="Reason for rejection")


class V18SessionOut(BaseModel):
    session_id: str
    org_id: str
    device_id: str
    device_name: Optional[str] = None
    device_ip: Optional[str] = None
    analyst_id: str
    approver_id: Optional[str] = None
    created_at: Optional[datetime] = None
    closed_at: Optional[datetime] = None
    status: str
    auth_token_hash: str
    encryption_key_hex: str
    command_count: int = 0


class V18CommandExecuteIn(BaseModel):
    command: str = Field(..., description="Shell or administrative diagnostic command")
    signature: Optional[str] = Field(None, description="Dual-authorization token or signature")


class V18CommandOut(BaseModel):
    command_id: str
    session_id: str
    command: str
    exit_code: int
    output: str
    dispatched_at: str
    completed_at: str


class V18KeystrokeOut(BaseModel):
    keystroke_id: int
    session_id: str
    direction: str
    timestamp: str
    data: str


class V18LiveResponseMeshStatusOut(BaseModel):
    status: str
    reverse_tunnel_protocol: str
    mtls_version: str
    two_man_rule_enforced: bool
    active_sessions_count: int
    pending_approval_count: int
    total_commands_executed: int
    total_keystrokes_recorded: int
    system_integrity: str


# =========================================================================
# VERSION 19 FLEET C2, OSQUERY & GIS AUDITING SCHEMAS
# =========================================================================

class V19QueryDispatchIn(BaseModel):
    sql_statement: str = Field(..., description="Osquery-style SQL query")
    target_filter: Optional[dict[str, Any]] = Field(default_factory=dict, description="Filter rules (e.g. device_id, os)")


class V19QueryResultOut(BaseModel):
    result_id: str
    query_run_id: str
    device_id: str
    device_hostname: Optional[str] = None
    returned_data: list[dict[str, Any]]
    row_count: int = 0
    executed_at: str


class V19QueryRunOut(BaseModel):
    query_run_id: str
    org_id: str
    analyst_id: str
    sql_statement: str
    target_filter: dict[str, Any]
    created_at: str
    status: str
    target_devices_count: int = 0
    total_rows_returned: int = 0


class V19FleetActionIn(BaseModel):
    device_id: str = Field(..., description="Target enrolled device UUID")
    action_type: str = Field(..., description="KILL_PROCESS, ISOLATE_HOST, UNISOLATE_HOST, SERVICE_RESTART")
    target_parameters: dict[str, Any] = Field(default_factory=dict, description="e.g. pid, process_name, isolate flag")


class V19FleetActionOut(BaseModel):
    action_id: str
    org_id: str
    device_id: str
    analyst_id: str
    action_type: str
    target_parameters: dict[str, Any]
    execution_status: str
    error_message: Optional[str] = None
    logged_at: str


class V19FileExploreIn(BaseModel):
    device_id: str = Field(..., description="Target device UUID")
    path: str = Field("/var/log", description="Remote directory path")


class V19FileItemOut(BaseModel):
    name: str
    path: str
    type: str
    size: str
    size_bytes: int
    owner: str
    permissions: str
    modified: str


class V19FileTransferIn(BaseModel):
    device_id: str = Field(..., description="Target device UUID")
    direction: str = Field("DOWNLOAD", description="UPLOAD or DOWNLOAD")
    local_file_path: str = Field(..., description="Remote device file path")
    file_content: Optional[str] = Field(None, description="Raw content for upload payload")


class V19FileTransferOut(BaseModel):
    transfer_id: str
    org_id: str
    device_id: str
    analyst_id: str
    transfer_direction: str
    local_file_path: str
    server_storage_url: str
    file_size_bytes: int
    sha256_hash: str
    transferred_at: str


class V19FleetMapDeviceOut(BaseModel):
    device_id: str
    hostname: str
    public_ip: str
    status: str
    os_name: str
    latitude: float
    longitude: float
    location_desc: str
    rtt_latency_ms: float
    latency_status: str # green, amber, red
    is_online: bool
    last_seen: str


class V19FleetMeshStatusOut(BaseModel):
    mesh_status: str
    multi_channel_socket_version: str
    osquery_evaluator_version: str
    gis_map_engine: str
    enrolled_fleet_count: int
    active_query_runs_count: int
    total_actions_logged: int
    total_file_transfers: int
    system_integrity: str


# ---------------------------------------------------------
# Version 20: Dynamic Edge Remediation & Adaptive GPS Mesh Schemas
# ---------------------------------------------------------

class V20GPSLocationIn(BaseModel):
    device_id: str
    latitude: float
    longitude: float
    altitude: Optional[float] = None
    speed_mps: Optional[float] = 0.0
    horizontal_accuracy: Optional[float] = None
    battery_level: Optional[int] = 100
    power_source: Optional[str] = "BATTERY" # BATTERY, AC


class V20GPSLocationOut(BaseModel):
    log_id: str
    device_id: str
    latitude: float
    longitude: float
    altitude: Optional[float] = None
    speed_mps: float
    horizontal_accuracy: Optional[float] = None
    battery_level: Optional[int] = None
    power_source: str
    tracking_state: str # STATIONARY, ACTIVE_TRANSIT, LOW_POWER, GEOFENCE_BREACH, STANDARD_MOTION
    polling_interval_seconds: int
    tracked_at: str
    ocsf_class_uid: int = 5005
    ocsf_severity: int = 1


class V20GeofenceConfigIn(BaseModel):
    device_id: str
    center_latitude: float
    center_longitude: float
    radius_meters: float = 50000.0


class V20GeofenceConfigOut(BaseModel):
    device_id: str
    center_latitude: float
    center_longitude: float
    radius_meters: float
    status: str


class V20TerminalStreamIn(BaseModel):
    session_id: str
    command_input: str
    command_output_summary: Optional[str] = None
    exit_code: Optional[int] = 0


class V20TerminalStreamOut(BaseModel):
    command_id: str
    session_id: str
    command_input: str
    command_output_summary: Optional[str] = None
    exit_code: Optional[int] = 0
    executed_at: str


class V20EdgeRemediationStatusOut(BaseModel):
    status: str
    adaptive_gps_engine_version: str
    ocsf_class_mapping: str
    pty_multiplexer_version: str
    total_location_logs: int
    active_geofences_count: int
    total_terminal_streams: int
    system_integrity: str


# ---------------------------------------------------------
# Version 21: Hardware-Assisted Mobile Forensics & Passcode Auditing Schemas
# ---------------------------------------------------------

class V21DeviceProbeIn(BaseModel):
    usb_port_path: Optional[str] = "/dev/bus/usb/001/004"
    probe_protocol: Optional[str] = "AUTO" # AUTO, USBMUXD, ADB, LIBUSB


class V21DeviceProbeOut(BaseModel):
    device_id: str
    manufacturer: str
    model: str
    serial_number: str
    udid: str
    os_name: str
    os_version: str
    battery_level: int
    is_encrypted: bool
    connection_type: str
    usb_vid: Optional[str] = "0x18d1"
    usb_pid: Optional[str] = "0x4ee1"
    status: str


class V21ForensicSessionCreateIn(BaseModel):
    device_name: str
    device_model: str
    serial_number: str
    udid: str
    os_name: str
    os_version: str
    connection_type: Optional[str] = "USB"
    passcode_type: str = "PATTERN" # PATTERN, PIN_4, PIN_6, ALPHANUMERIC
    target_mock_passcode: Optional[str] = "1994"


class V21ForensicSessionOut(BaseModel):
    session_id: str
    org_id: str
    analyst_id: str
    device_name: str
    device_model: str
    serial_number: str
    udid: str
    os_name: str
    os_version: str
    connection_type: str
    passcode_type: str
    max_estimated_entropy: float
    created_at: str
    completed_at: Optional[str] = None
    status: str
    total_attempts_count: Optional[int] = 0
    is_unlocked: Optional[bool] = False


class V21PasscodeAttemptIn(BaseModel):
    candidate_passcode: str
    pattern_path: Optional[List[int]] = None
    passcode_type: Optional[str] = "PIN_4"


class V21PasscodeAttemptOut(BaseModel):
    attempt_id: Optional[int] = None
    session_id: str
    attempt_index: int
    entropy: float
    is_successful: bool
    response_code: str
    latency_ms: int
    candidate_hash: str
    pattern_path: Optional[List[int]] = None
    backoff_triggered_sec: float
    timestamp: str


class V21AuditRunIn(BaseModel):
    max_attempts: Optional[int] = 20
    delay_between_attempts_sec: Optional[float] = 0.05
    target_secret_override: Optional[str] = None


class V21AuditRunOut(BaseModel):
    session_id: str
    status: str
    total_attempts_run: int
    is_unlocked: bool
    last_response_code: str
    backoff_active_sec: float
    final_entropy: float
    attempts_history: List[V21PasscodeAttemptOut]


class V21ForensicStatusOut(BaseModel):
    status: str
    engine_version: str
    ocsf_class_mapping: str
    hid_emulation_driver: str
    total_forensic_sessions: int
    active_sessions_count: int
    total_passcode_attempts: int
    lockout_events_detected: int
    supported_vectors: List[str]
    system_integrity: str


# ---------------------------------------------------------
# Version 23: Spatial-Temporal GNN, eBPF CO-RE RASP, CPA & Merkle Ledger Schemas
# ---------------------------------------------------------

class V23StatusOut(BaseModel):
    status: str
    version: str
    gnn_model_type: str
    ebpf_driver_type: str
    side_channel_mode: str
    ledger_integrity_state: str
    total_ledger_records: int
    gnn_active_nodes: int
    gnn_active_edges: int
    cpa_reconstruction_fidelity: float
    system_integrity: str


class V23GNNEventIn(BaseModel):
    event_type: str # auth, process, file, network
    source_entity: str # e.g. "admin", "srv-app-01", "mimikatz.exe"
    target_entity: str # e.g. "srv-app-01", "pg_dump", "/etc/shadow", "10.0.0.5"
    class_uid: Optional[int] = 3002
    metadata: Optional[Dict[str, Any]] = None


class V23GNNTopologyOut(BaseModel):
    total_nodes: int
    total_edges: int
    pyg_tensor_shapes: Dict[str, str]
    mean_anomaly_score: float
    max_anomaly_score: float
    is_anomalous: bool
    nodes: List[Dict[str, Any]]
    edges: List[Dict[str, Any]]


class V23GNNAnomalyOut(BaseModel):
    is_anomalous: bool
    mean_anomaly_score: float
    max_anomaly_score: float
    top_anomalous_nodes: List[Dict[str, Any]]
    evaluated_edges_count: int


class V23RASPPolicyIn(BaseModel):
    uid: int = 1000
    enforce_kill: bool = True


class V23RASPStatusOut(BaseModel):
    status: str
    btf_available: bool
    btf_path: str
    kernel_hook: str
    relocation_type: str
    active_policies_count: int
    blocked_paths: List[str]
    driver: str


class V23RASPSimulationIn(BaseModel):
    uid: int = 1000
    binary_path: str = "/dev/shm/.stealth_dropper"
    command_args: Optional[str] = "--inject"


class V23RASPSimulationOut(BaseModel):
    uid: int
    binary_path: str
    command_args: Optional[str] = ""
    policy_enforced: bool
    is_risky_path: bool
    action: str
    exit_code: int
    reason: str


class V23SideChannelTraceIn(BaseModel):
    num_traces: Optional[int] = 50
    key_length: Optional[int] = 8
    target_key_hex: Optional[str] = "5345435245543233" # ASCII "SECRET23"
    noise_level: Optional[float] = 0.25


class V23SideChannelTraceOut(BaseModel):
    traces_generated_count: int
    sample_trace_wave: List[float]
    power_consumption_mean_mw: float
    simulated_sampling_rate_msps: float
    noise_deviation: float


class V23CPAAnalysisIn(BaseModel):
    num_traces: Optional[int] = 100
    key_length: Optional[int] = 8
    target_key_hex: Optional[str] = "5345435245543233"


class V23CPAAnalysisOut(BaseModel):
    key_length_bytes: int
    traces_analyzed_count: int
    max_correlation_peak: float
    recovered_key_hex: str
    recovered_key_text: str
    correlation_matrix: List[Dict[str, Any]]
    status: str


class V23LedgerAppendIn(BaseModel):
    device_id: str
    hostname: str
    ip_address: str
    system_status: Optional[str] = "active"
    operation_type: Optional[str] = "UPDATE"


class V23LedgerRecordOut(BaseModel):
    ledger_id: str
    device_id: str
    org_id: str
    hostname: str
    ip_address: str
    system_status: str
    operation_type: str
    transaction_timestamp: str
    parent_hash: Optional[str]
    record_hash: str


class V23LedgerVerifyOut(BaseModel):
    total_records: int
    is_valid: bool
    chain_status: str
    verified_blocks: int
    tampered_blocks_count: int
    genesis_hash: str
    latest_root_hash: str
    tampered_details: List[Dict[str, Any]]


# ==========================================
# Version 24: Baseband IMEI, Adaptive GPS, Network Audit & Merkle Ledger Schemas
# ==========================================

class V24StatusOut(BaseModel):
    status: str
    version: str
    modem_layer: str
    gps_engine: str
    network_auditor_mode: str
    audit_ledger_status: str
    total_audit_blocks: int
    system_integrity: str


class V24ModemProbeIn(BaseModel):
    raw_at_command: Optional[str] = "AT+CGSN"
    at_command: Optional[str] = None
    mock_serial_port: Optional[str] = "/dev/ttyUSB0"
    serial_port: Optional[str] = None


class V24ModemProbeOut(BaseModel):
    valid: bool
    command_executed: str
    imei: Optional[str]
    tac: Optional[str]
    fac: Optional[str]
    snr: Optional[str]
    check_digit: Optional[str]
    status: str
    access_technology: Optional[str] = "LTE 4G"


class V24TriangulationIn(BaseModel):
    imei: Optional[str] = None
    towers: Optional[List[Dict[str, Any]]] = None
    default_lat: Optional[float] = 37.7749
    default_lon: Optional[float] = -122.4194


class V24TriangulationOut(BaseModel):
    latitude: float
    longitude: float
    accuracy_radius_meters: float
    towers_used_count: int
    triangulation_algorithm: str
    towers_metadata: List[Dict[str, Any]]


class V24CeirBlacklistIn(BaseModel):
    imei: str
    action: Optional[str] = None
    is_stolen: bool = True
    reason: Optional[str] = "SOC_ASSET_THEFT_CONTAINMENT"


class V24CeirBlacklistOut(BaseModel):
    imei: str
    ceir_list_status: str
    gsma_device_status: str
    global_blocking_active: bool
    blacklist_reason: Optional[str]
    updated_at: int


class V24GPSUpdateIn(BaseModel):
    current_lat: Optional[float] = 37.7833
    current_lon: Optional[float] = -122.4167
    current_latitude: Optional[float] = None
    current_longitude: Optional[float] = None
    battery_pct: Optional[float] = 85.0
    battery_percentage: Optional[float] = None
    geofence_center_lat: Optional[float] = 37.7749
    geofence_center_lon: Optional[float] = -122.4194
    geofence_radius_meters: Optional[float] = 20000.0
    simulated_speed_kmh: Optional[float] = None


class V24GPSUpdateOut(BaseModel):
    state: str
    speed_mps: float
    speed_kmh: float
    distance_to_center_m: float
    outside_geofence: bool
    battery_pct: float
    next_scheduled_interval: int


class V24NetworkAuditIn(BaseModel):
    interface_name: Optional[str] = "wlan0"
    local_ip: Optional[str] = "192.168.1.144"
    ip_address: Optional[str] = None
    mac_address: Optional[str] = "00:0a:95:9d:68:16"
    gateway_ip: Optional[str] = "192.168.1.1"
    gateway_mac: Optional[str] = "a0:04:cb:11:ff:dd"
    subnet_mask: Optional[str] = "255.255.255.0"
    dns_servers: Optional[List[str]] = None


class V24NetworkAuditOut(BaseModel):
    interface_name: str
    ip_address: str
    mac_address: str
    subnet_mask: str
    gateway_ip: str
    gateway_mac: str
    gateway_vendor: str
    dns_servers: List[str]
    is_mitm_detected: bool
    mitm_threat_reason: Optional[str]
    is_randomized_mac: bool
    baseline_gateway_mac: str
    status: str
    timestamp: int


class V24ARPMitmIn(BaseModel):
    interface_name: Optional[str] = "wlan0"
    rogue_gateway_mac: Optional[str] = "de:ad:be:ef:13:37"
    mutated_gateway_mac: Optional[str] = None
    original_gateway_mac: Optional[str] = None
    gateway_ip: Optional[str] = None
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None


class V24AuditLedgerAppendIn(BaseModel):
    action: str = "SECURITY_RULE_MODIFIED"
    actor_email: str = "admin@acme.corp"
    ip_address: str = "192.168.1.50"
    mac_address: str = "00:1A:2B:3C:4D:5E"
    device_id: Optional[str] = "dev-corp-sec-01"


class V24AuditLedgerRecordOut(BaseModel):
    sequence_id: int
    org_id: str
    device_id: Optional[str]
    event_timestamp: str
    action: str
    actor_email: str
    ip_address: str
    mac_address: str
    payload_hash: str
    previous_record_hash: Optional[str]
    current_ledger_hash: str


class V24AuditLedgerVerifyOut(BaseModel):
    total_records: int
    is_valid: bool
    chain_status: str
    verified_blocks: int
    tampered_blocks_count: int
    genesis_hash: str
    latest_tip_hash: str
    tampered_details: List[Dict[str, Any]]


# ==========================================
# Version 25: Real-Time MITRE Matrix, MDPS & Explainable AI Schemas
# ==========================================

class V25StatusOut(BaseModel):
    status: str
    version: str
    pipeline_throughput_eps: float
    pipeline_latency_ms: float
    total_events_ingested: int
    total_mitre_alerts: int
    active_tactics_count: int
    ai_summaries_generated: int
    stream_broker_status: str
    system_integrity: str


class V25LogEventIn(BaseModel):
    device_id: Optional[str] = "dev-core-node-01"
    ocsf_class_id: Optional[int] = 4001
    source_ip: Optional[str] = "192.168.1.105"
    destination_ip: Optional[str] = "185.220.101.5"
    command: Optional[str] = None
    process_name: Optional[str] = None
    uri: Optional[str] = None
    payload: Optional[str] = None
    technique_id: Optional[str] = None
    anomaly_score: Optional[float] = 65.0
    asset_criticality: Optional[float] = 70.0
    intel_confidence: Optional[float] = 80.0
    metadata: Optional[Dict[str, Any]] = None


class V25IngestLogStreamIn(BaseModel):
    batch_size: Optional[int] = 100
    events: Optional[List[V25LogEventIn]] = None
    source_stream: Optional[str] = "logs:raw_stream"


class V25IngestResultOut(BaseModel):
    batch_id: str
    events_received: int
    events_processed: int
    alerts_generated: int
    instantaneous_eps: float
    latency_ms: float
    status: str
    sample_alerts: List[Dict[str, Any]]


class V25PriorityScoreIn(BaseModel):
    anomaly_score: float = 85.0
    mitre_weight: float = 80.0
    asset_criticality: float = 75.0
    intel_confidence: float = 90.0


class V25PriorityScoreOut(BaseModel):
    final_score: float
    priority_level: str
    breakdown: Dict[str, Any]


class V25AISummaryIn(BaseModel):
    model_config = {"protected_namespaces": ()}
    alert_id: Optional[str] = None
    technique_id: Optional[str] = "T1059"
    technique_name: Optional[str] = "Command and Scripting Interpreter"
    tactic_id: Optional[str] = "TA0002"
    tactic_name: Optional[str] = "Execution"
    priority_score: Optional[float] = 88.5
    priority_level: Optional[str] = "CRITICAL"
    source_ip: Optional[str] = "192.168.1.45"
    destination_ip: Optional[str] = "185.220.101.5"
    payload_summary: Optional[str] = "PowerShell download cradle invoking mimikatz with user admin@acme.corp"
    raw_event_data: Optional[Dict[str, Any]] = None


class V25AISummaryOut(BaseModel):
    model_config = {"protected_namespaces": ()}
    summary_id: str
    alert_id: Optional[str]
    sanitized_input: str
    model_used: str
    executive_summary: str
    threat_actor_attribution: Optional[str]
    actionable_remediation: str
    created_at: str



class V25MitreAlertOut(BaseModel):
    alert_id: str
    org_id: str
    device_id: Optional[str]
    source_ip: Optional[str]
    destination_ip: Optional[str]
    technique_id: str
    technique_name: Optional[str]
    tactic_id: str
    tactic_name: Optional[str]
    anomaly_score: float
    mitre_weight: float
    asset_criticality: float
    intel_confidence: float
    priority_score: float
    priority_level: str
    payload_summary: Optional[str]
    parent_alert_hash: Optional[str]
    alert_hash: str
    created_at: str


class V25MitreHeatmapOut(BaseModel):
    total_alerts: int
    overall_avg_priority: float
    matrix: List[Dict[str, Any]]
    generated_at: str


# ==========================================
# Version 26.0 Causal Provenance & SOAR Schemas
# ==========================================

class V26StatusOut(BaseModel):
    version: str
    provenance_graph_nodes: int
    provenance_graph_edges: int
    active_soar_playbooks: int
    tpm_hardware_status: Dict[str, Any]
    system_integrity: str
    timestamp: str


class V26ProvenanceNodeIn(BaseModel):
    node_type: str = "PROCESS" # PROCESS, FILE, SOCKET, DOMAIN, IP_ADDRESS, USER
    entity_key: str = "proc:/usr/bin/powershell"
    name: str = "powershell"
    device_id: Optional[str] = None
    node_metadata: Optional[Dict[str, Any]] = None


class V26ProvenanceNodeOut(BaseModel):
    id: str
    org_id: str
    device_id: str
    node_type: str
    entity_key: str
    name: str
    node_metadata: Dict[str, Any]
    created_at: str


class V26ProvenanceEdgeIn(BaseModel):
    source_node_id: str
    target_node_id: str
    relation_type: str = "SPAWNED" # EXECUTED, SPAWNED, READ, WROTE, CONNECTED_TO, RESOLVED
    edge_weight: float = 1.0
    metadata: Optional[Dict[str, Any]] = None


class V26ProvenanceEdgeOut(BaseModel):
    id: str
    org_id: str
    source_node_id: str
    target_node_id: str
    source_name: Optional[str] = None
    target_name: Optional[str] = None
    source_type: Optional[str] = None
    target_type: Optional[str] = None
    relation_type: str
    edge_weight: float
    edge_hash_sha256: Optional[str]
    metadata: Optional[Dict[str, Any]] = None
    timestamp: str


class V26GraphQueryOut(BaseModel):
    org_id: str
    total_nodes: int
    total_edges: int
    nodes: List[Dict[str, Any]]
    edges: List[Dict[str, Any]]
    node_types_count: Dict[str, int]
    timestamp: str


class V26TracebackIn(BaseModel):
    target_entity_or_id: str = "powershell"
    max_depth: int = 10
    asp_shell_descendants_only: bool = True


class V26TracebackOut(BaseModel):
    status: str
    patient_zero_node: Optional[Dict[str, Any]]
    target_node: Optional[Dict[str, Any]]
    causal_path_nodes: List[Dict[str, Any]]
    causal_path_edges: List[Dict[str, Any]]
    depth: int
    total_nodes_traversed: int
    total_edges_traversed: int
    latency_ms: float


class V26SOARPlaybookIn(BaseModel):
    name: str = "High-Risk Threat Edge Isolation"
    playbook_yaml: str
    is_active: bool = True


class V26SOARPlaybookOut(BaseModel):
    id: str
    org_id: str
    name: str
    is_active: bool
    playbook_yaml: str
    created_at: str


class V26SOARExecuteIn(BaseModel):
    playbook_id: Optional[str] = None
    device_id: Optional[str] = None
    threat_context: Optional[Dict[str, Any]] = None


class V26SOARExecuteOut(BaseModel):
    playbook_id: Optional[str]
    playbook_name: Optional[str]
    device_id: str
    status: str
    total_steps_executed: int
    execution_duration_ms: float
    steps_executed: List[Dict[str, Any]]
    threat_context: Dict[str, Any]
    timestamp: str


class V26SOARExecutionLogOut(BaseModel):
    id: str
    org_id: str
    playbook_id: str
    playbook_name: Optional[str] = None
    device_id: str
    status: str
    execution_dag_trace: Dict[str, Any]
    started_at: str
    completed_at: Optional[str] = None


class V26TPMAttestIn(BaseModel):
    block_limit: int = 1000
    alert_ids: Optional[List[str]] = None


class V26TPMAttestOut(BaseModel):
    id: str
    org_id: str
    block_start_id: str
    block_end_id: str
    total_alerts_attested: int
    merkle_root_hash: str
    pcr_composite_digest: str
    tpm_hardware_signature: str
    attestation_status: str
    attested_at: str


class V26TPMVerifyIn(BaseModel):
    merkle_root_hash: str
    tpm_hardware_signature: str
    pcr_composite_digest: Optional[str] = None


class V26TPMVerifyOut(BaseModel):
    is_attestation_valid: bool
    merkle_root_hash: str
    status: str
    pcr_integrity_verified: bool
    verified_at: str


# ==========================================
# Version 27 Schemas: ML Anomaly Engine
# ==========================================

class V27TelemetryEventIn(BaseModel):
    request_rate_1m: Optional[float] = 0.0
    request_rate_5m: Optional[float] = 0.0
    failed_auth_count: Optional[int] = 0
    payload_entropy: Optional[float] = 0.0
    unusual_port_flag: Optional[int] = 0
    geo_distance_km: Optional[float] = 0.0
    packet_size_variance: Optional[float] = 0.0
    token_anomaly_score: Optional[float] = 0.0
    session_duration_sec: Optional[float] = 0.0
    concurrent_sessions: Optional[int] = 1
    device_id: Optional[str] = None
    ip_address: Optional[str] = None
    endpoint: Optional[str] = None


class V27FeatureContribution(BaseModel):
    feature: str
    value: float
    z_score: float
    deviation_level: str


class V27AnomalyScoreOut(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    is_anomaly: bool
    anomaly_score: float
    severity: str
    decision_boundary: float
    top_contributing_features: List[V27FeatureContribution]
    pca_coordinates: List[float]
    detector_version: str
    model_fitted: bool
    evaluated_at: float
    org_id: str


class V27ModelTrainIn(BaseModel):
    lookback_days: int = Field(default=30, ge=1, le=365)
    contamination: float = Field(default=0.05, ge=0.001, le=0.5)
    n_estimators: int = Field(default=100, ge=10, le=500)
    include_synthetic: bool = True


class V27ModelTrainOut(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    task_id: Optional[str] = None
    status: str
    org_id: str
    model_id: str
    samples_used: int
    duration_sec: float
    version: str
    metrics: Dict[str, Any]
    trained_at: str


class V27FeatureBaselineOut(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    id: str
    model_id: str
    feature_name: str
    mean_value: float
    std_value: float
    min_value: float
    max_value: float
    importance_weight: float
    calculated_at: str


class V27ModelDetailsOut(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    id: str
    org_id: str
    algorithm: str
    version: str
    contamination: float
    training_samples_count: int
    model_artifact_path: Optional[str] = None
    status: str
    metrics: Dict[str, Any]
    created_at: str
    updated_at: str
    baselines: List[V27FeatureBaselineOut]
    recent_runs: List[Dict[str, Any]]


# ==============================================================
# Version 28 Schemas: Federated ML & Collaborative Threat Mesh
# ==============================================================

class V28ClientUpdateIn(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    model_id: Optional[str] = None
    sample_count: int = Field(default=100, ge=1)
    weights: Optional[List[float]] = None
    checksum_signature: Optional[str] = None


class V28ClientUpdateOut(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    id: str
    org_id: str
    model_id: str
    local_sample_count: int
    checksum_signature: str
    submitted_at: str
    status: str = "SUBMITTED"


class V28FederationAggregateIn(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    model_name: str = "global_anomaly_forest"
    min_clients: int = Field(default=2, ge=2, le=50)
    dp_epsilon: float = Field(default=1.2, ge=0.1, le=10.0)


class V28FederationRunOut(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    id: str
    global_model_id: str
    consolidated_at: str
    active_client_count: int
    aggregated_loss: float
    signature_proof: str
    status: str = "CONSOLIDATED"
    total_samples: int = 0
    global_epoch: int = 1


class V28GlobalModelOut(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    id: str
    model_name: str
    version_id: int
    org_id: Optional[str] = None
    model_state: str
    total_epochs_trained: int
    metrics: Dict[str, Any]
    created_at: str
    updated_at: str
    recent_runs: List[Dict[str, Any]]
    active_client_updates: int


class V28FederationStatusOut(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    mesh_status: str
    active_peers_count: int
    global_model_version: int
    total_samples_ingested: int
    latest_federated_loss: float
    differential_privacy_epsilon: float
    homomorphic_encryption_scheme: str
    version: str = "v28.0"


# =========================================================================
# Version 29 Schemas: Synthetic Telemetry Generation (STG) & Purple-Team Emulation
# =========================================================================

class SimulationStepBase(BaseModel):
    step_order: int = Field(..., ge=1, description="Sequential order of the simulation step")
    delay_seconds: int = Field(default=3, ge=0, le=60, description="Delay in seconds before firing this step")
    ocsf_class_uid: int = Field(..., description="OCSF Class UID (e.g. 3002 for Auth, 1007 for Process, 4001 for Network)")
    mock_log_payload: Dict[str, Any] = Field(..., description="OCSF JSON log payload")


class SimulationStepCreate(SimulationStepBase):
    pass


class SimulationStepResponse(SimulationStepBase):
    id: str
    profile_id: str

    model_config = ConfigDict(from_attributes=True)


class SimulationProfileBase(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    description: str = Field(...)
    threat_actor: str = Field(..., max_length=50)
    is_active: bool = True


class SimulationProfileCreate(SimulationProfileBase):
    steps: List[SimulationStepCreate] = Field(default_factory=list)


class SimulationProfileResponse(SimulationProfileBase):
    id: str
    org_id: Optional[str] = None
    created_at: datetime
    steps: List[SimulationStepResponse] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


class SimulationRunBase(BaseModel):
    profile_id: str
    status: str = "RUNNING"


class SimulationRunResponse(BaseModel):
    id: str
    org_id: str
    profile_id: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    status: str
    alerts_triggered_count: int
    triggered_alert_ids: List[Any] = Field(default_factory=list)
    details: Dict[str, Any] = Field(default_factory=dict)
    profile_name: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class SyntheticGenerationRequest(BaseModel):
    count: int = Field(default=5000, ge=10, le=50000, description="Number of synthetic OCSF events to generate")
    diurnal_profile: bool = Field(default=True, description="Apply diurnal business hour sine/cosine curve")
    noise_ratio: float = Field(default=0.3, ge=0.0, le=1.0, description="Proportion of background benign noise")
    user_clusters_count: int = Field(default=5, ge=1, le=50, description="Number of mock UEBA user clusters")
    bootstrap_ml_coldstart: bool = Field(default=True, description="Train Isolation Forest model on generated telemetry")
    inject_to_stream: bool = Field(default=True, description="Publish events into Redis raw stream logs:raw_stream")
    persist_to_db: bool = Field(default=True, description="Persist sample logs into PostgreSQL logs table")


class SyntheticGenerationResponse(BaseModel):
    status: str
    org_id: str
    events_generated: int
    events_persisted: int
    events_streamed: int
    ml_coldstart_bootstrapped: bool
    ml_model_version: Optional[str] = None
    diurnal_curve_applied: bool
    user_clusters: List[str]
    time_elapsed_sec: float
    sample_events: List[Dict[str, Any]] = Field(default_factory=list)


class SimulationTriggerRequest(BaseModel):
    profile_id: str
    async_execution: bool = True
    delay_multiplier: float = Field(default=1.0, ge=0.1, le=5.0)


class SimulationTriggerResponse(BaseModel):
    run_id: str
    profile_id: str
    profile_name: str
    status: str
    steps_count: int
    message: str


class KedaScaleConfigResponse(BaseModel):
    api_version: str = "keda.sh/v1alpha1"
    kind: str = "ScaledObject"
    metadata_name: str = "celery-worker-scaler"
    stream_name: str = "logs:raw_stream"
    target_backlog_threshold: int = 10000
    min_replicas: int = 2
    max_replicas: int = 50
    redis_host: str = "redis://redis:6379/0"
    argocd_sync_wave: int = 2
    gitops_status: str = "HEALTHY_SYNCED"


class V29StatusResponse(BaseModel):
    stg_engine_version: str = "v29.0-sovereign-stg"
    stg_active: bool = True
    purple_team_emulation_active: bool = True
    supported_threat_profiles: List[str]
    keda_autoscaling_enabled: bool
    cold_start_ml_readiness: str
    redis_stream_backlog: int
    version: str = "v29.0"


# =========================================================================
# Version 30 Schemas: Generative Security Digital Twin & Cyber Range
# =========================================================================

class TwinNodeBase(BaseModel):
    name: str = Field(..., max_length=100)
    asset_type: str = Field(..., max_length=50)  # WORKSTATION, DOMAIN_CONTROLLER, DATABASE_SERVER, etc.
    hostname_hash: Optional[str] = None
    ip_address_hash: Optional[str] = None
    mac_address_hash: Optional[str] = None
    os_version: str = "Linux 6.5.0"
    criticality_id: int = Field(default=3, ge=1, le=5)
    status: str = "SAFE"


class TwinNodeCreate(TwinNodeBase):
    pass


class TwinNodeResponse(TwinNodeBase):
    id: str
    org_id: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class TwinRelationshipBase(BaseModel):
    source_node_id: str
    target_node_id: str
    relationship_type: str = "NETWORK_ROUTE"


class TwinRelationshipCreate(TwinRelationshipBase):
    pass


class TwinRelationshipResponse(TwinRelationshipBase):
    id: str
    org_id: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class TwinTopologyResponse(BaseModel):
    nodes: List[TwinNodeResponse] = Field(default_factory=list)
    relationships: List[TwinRelationshipResponse] = Field(default_factory=list)
    total_assets: int = 0
    zero_pii_sanitized: bool = True
    anonymization_algorithm: str = "HMAC-SHA-256"


class SimulationExecutionLedgerResponse(BaseModel):
    id: str
    org_id: str
    session_id: str
    step_index: int
    mitre_tactic_id: str
    mitre_technique_id: str
    agent_action_description: str
    simulated_ocsf_payload: Dict[str, Any]
    is_detected: bool
    remediation_triggered: Optional[str] = None
    previous_step_hash: str
    current_ledger_hash: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class GAANSessionBase(BaseModel):
    scenario_name: str
    red_agent_model: str = "local-mistral-7b-v1"
    blue_agent_model: str = "local-mistral-7b-v1"


class GAANSessionResponse(GAANSessionBase):
    id: str
    org_id: str
    status: str
    red_score: int
    blue_score: int
    started_at: datetime
    ended_at: Optional[datetime] = None
    steps: List[SimulationExecutionLedgerResponse] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


class TriggerScenarioRequest(BaseModel):
    scenario_name: str = Field(default="APT29_COZYBEAR")
    red_agent_model: Optional[str] = "local-mistral-7b-v1"
    blue_agent_model: Optional[str] = "local-mistral-7b-v1"
    target_device_id: Optional[str] = None
    async_execution: bool = True


class TriggerScenarioResponse(BaseModel):
    session_id: str
    scenario_name: str
    status: str
    message: str
    steps_count: int


class CarrierBurstRequest(BaseModel):
    eps_target: int = Field(default=1000000, ge=10000, le=5000000, description="Simulated EPS target volume")
    duration_seconds: int = Field(default=5, ge=1, le=60)
    packet_type: str = Field(default="NETFLOW_OCSF", description="Raw packet protocol simulation")


class CarrierBurstResponse(BaseModel):
    status: str
    eps_achieved: int
    total_packets_transmitted: int
    ebpf_xdp_bypass_active: bool
    ring_buffer_utilization_pct: float
    kernel_bypass_latency_us: float
    duration_seconds: int
    pipeline_drop_rate: float = 0.0


class V30StatusResponse(BaseModel):
    gsdt_engine_version: str = "v30.0-gsdt-range"
    cyber_range_active: bool = True
    gaan_agents_active: bool = True
    supported_scenarios: List[str]
    carrier_scale_eps_capacity: int = 1000000
    zero_pii_compliance_mode: str = "HMAC-SHA-256-SAFE-CLONE"
    version: str = "v30.0"










