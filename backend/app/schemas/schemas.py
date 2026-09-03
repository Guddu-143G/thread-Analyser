from datetime import datetime
from typing import Optional, Any

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
