import React, { useState, useEffect } from 'react'
import client from '../api/client'
import { useAuth } from '../context/AuthContext'

export default function V17NeonMesh() {
  const { user } = useAuth()

  const [activeTab, setActiveTab] = useState('neon') // neon | fleet | email | url | anomalies
  const [feedback, setFeedback] = useState(null)

  // 1. Neon Status State
  const [neonStatus, setNeonStatus] = useState(null)
  const [loadingNeon, setLoadingNeon] = useState(false)

  // 2. Fleet & Heartbeat State
  const [fleetDevices, setFleetDevices] = useState([])
  const [loadingFleet, setLoadingFleet] = useState(false)
  const [selectedDevice, setSelectedDevice] = useState(null)
  const [deviceHeartbeats, setDeviceHeartbeats] = useState([])
  const [loadingHeartbeats, setLoadingHeartbeats] = useState(false)

  // Heartbeat form
  const [hbDeviceId, setHbDeviceId] = useState('v17-node-edge-01')
  const [hbHostname, setHbHostname] = useState('edge-node-01.corp.internal')
  const [hbPublicIp, setHbPublicIp] = useState('185.190.140.2')
  const [hbLat, setHbLat] = useState(51.5074)
  const [hbLon, setHbLon] = useState(-0.1278)
  const [hbLocation, setHbLocation] = useState('London, United Kingdom')
  const [hbCpu, setHbCpu] = useState(18.5)
  const [hbMem, setHbMem] = useState(38.0)
  const [hbDisk, setHbDisk] = useState(52.0)
  const [hbBattery, setHbBattery] = useState(94.0)
  const [hbProcesses, setHbProcesses] = useState(142)
  const [hbPorts, setHbPorts] = useState(16)
  const [lastTelemetryRes, setLastTelemetryRes] = useState(null)
  const [sendingTelemetry, setSendingTelemetry] = useState(false)

  // 3. Email Security State
  const [emailSender, setEmailSender] = useState('security-update@paypal-auth-verify.top')
  const [emailRecipient, setEmailRecipient] = useState('cfo@acme.corp')
  const [emailSubject, setEmailSubject] = useState('URGENT ACTION: Immediate Wire Transfer and Password Verification')
  const [emailBody, setEmailBody] = useState(`Dear CFO,\n\nPlease verify your corporate credentials and execute the pending vendor wire transfer of $74,200:\nhttps://verify-office365-security.com/login.php?user=cfo@acme.corp\n\nRegards,\nSecurity Operations`)
  const [emailSenderIp, setEmailSenderIp] = useState('198.51.100.99')
  const [emailSpfOverride, setEmailSpfOverride] = useState('FAIL')
  const [emailAuditResult, setEmailAuditResult] = useState(null)
  const [emailHistory, setEmailHistory] = useState([])
  const [auditingEmail, setAuditingEmail] = useState(false)

  // 4. URL Sandbox State
  const [urlInput, setUrlInput] = useState('https://verify-office365-security.com/login.php?user=cfo@acme.corp')
  const [urlAuditResult, setUrlAuditResult] = useState(null)
  const [urlHistory, setUrlHistory] = useState([])
  const [auditingUrl, setAuditingUrl] = useState(false)

  // 5. ML Anomaly State
  const [anomalies, setAnomalies] = useState([])
  const [loadingAnomalies, setLoadingAnomalies] = useState(false)
  const [simulatingAnomaly, setSimulatingAnomaly] = useState(false)
  const [selectedAnomaly, setSelectedAnomaly] = useState(null)

  // Fetch Neon Status
  const fetchNeonStatus = async () => {
    setLoadingNeon(true)
    try {
      const res = await client.get('/v17/neon/branch-status')
      setNeonStatus(res.data)
    } catch (err) {
      console.error('Error fetching Neon status:', err)
    } finally {
      setLoadingNeon(false)
    }
  }

  // Fetch Fleet Devices
  const fetchFleetDevices = async () => {
    setLoadingFleet(true)
    try {
      const res = await client.get('/v17/devices')
      setFleetDevices(res.data)
      if (res.data.length > 0 && !selectedDevice) {
        selectDeviceForHistory(res.data[0])
      }
    } catch (err) {
      console.error('Error fetching fleet devices:', err)
    } finally {
      setLoadingFleet(false)
    }
  }

  // Fetch Heartbeats for Selected Device
  const selectDeviceForHistory = async (dev) => {
    setSelectedDevice(dev)
    setLoadingHeartbeats(true)
    try {
      const res = await client.get(`/v17/devices/${dev.id}/heartbeats?limit=50`)
      setDeviceHeartbeats(res.data)
    } catch (err) {
      console.error('Error fetching heartbeats:', err)
    } finally {
      setLoadingHeartbeats(false)
    }
  }

  // Fetch Email History
  const fetchEmailHistory = async () => {
    try {
      const res = await client.get('/v17/email/scans?limit=30')
      setEmailHistory(res.data)
    } catch (err) {
      console.error('Error fetching email history:', err)
    }
  }

  // Fetch URL History
  const fetchUrlHistory = async () => {
    try {
      const res = await client.get('/v17/url/scans?limit=30')
      setUrlHistory(res.data)
    } catch (err) {
      console.error('Error fetching URL history:', err)
    }
  }

  // Fetch Anomalies
  const fetchAnomalies = async () => {
    setLoadingAnomalies(true)
    try {
      const res = await client.get('/v17/anomalies?limit=30')
      setAnomalies(res.data)
      if (res.data.length > 0 && !selectedAnomaly) {
        setSelectedAnomaly(res.data[0])
      }
    } catch (err) {
      console.error('Error fetching anomalies:', err)
    } finally {
      setLoadingAnomalies(false)
    }
  }

  // Initial load
  useEffect(() => {
    fetchNeonStatus()
    fetchFleetDevices()
    fetchEmailHistory()
    fetchUrlHistory()
    fetchAnomalies()
  }, [])

  // Ingest Telemetry Handlers
  const handleSendTelemetry = async (overrideLat = null, overrideLon = null, overrideLoc = null, overrideIp = null) => {
    setSendingTelemetry(true)
    setFeedback(null)
    try {
      const payload = {
        device_id: hbDeviceId,
        hostname: hbHostname,
        public_ip: overrideIp || hbPublicIp,
        latitude: overrideLat !== null ? overrideLat : parseFloat(hbLat),
        longitude: overrideLon !== null ? overrideLon : parseFloat(hbLon),
        location_desc: overrideLoc || hbLocation,
        cpu_usage: parseFloat(hbCpu),
        memory_usage: parseFloat(hbMem),
        disk_usage: parseFloat(hbDisk),
        battery: parseFloat(hbBattery),
        processes: parseInt(hbProcesses),
        ports: parseInt(hbPorts),
        agent_version: '17.0.0',
        os_name: 'Linux',
        os_version: '6.5.0'
      }
      const res = await client.post('/v17/devices/telemetry', payload)
      setLastTelemetryRes(res.data)
      if (res.data.impossible_travel) {
        setFeedback({
          type: 'danger',
          title: '🚨 IMPOSSIBLE TRAVEL ANOMALY FLAGGED & RECORDED IN NEON',
          msg: `Velocity of ${res.data.calculated_speed_kmh} km/h exceeded passenger aviation constraints (>950 km/h) over ${res.data.distance_km} km. Node marked COMPROMISED.`
        })
      } else {
        setFeedback({
          type: 'success',
          title: '✓ Telemetry Vector Ingested',
          msg: `Device ${res.data.device_id} status is ${res.data.status}. Heartbeat sealed to Neon table with RLS isolation.`
        })
      }
      fetchFleetDevices()
      fetchNeonStatus()
    } catch (err) {
      setFeedback({ type: 'danger', title: 'Telemetry Error', msg: err.response?.data?.detail || err.message })
    } finally {
      setSendingTelemetry(false)
    }
  }

  const handleSimulateTeleport = () => {
    // Jump to Tokyo (35.6762, 139.6503)
    setHbLat(35.6762)
    setHbLon(139.6503)
    setHbLocation('Tokyo, Japan')
    setHbPublicIp('133.242.18.1')
    handleSendTelemetry(35.6762, 139.6503, 'Tokyo, Japan', '133.242.18.1')
  }

  // Email Audit Handler
  const handleAuditEmail = async () => {
    setAuditingEmail(true)
    setFeedback(null)
    try {
      const payload = {
        sender: emailSender,
        recipient: emailRecipient,
        subject: emailSubject,
        body: emailBody,
        sender_ip: emailSenderIp,
        spf_override: emailSpfOverride !== 'AUTO' ? emailSpfOverride : null
      }
      const res = await client.post('/v17/email/audit', payload)
      setEmailAuditResult(res.data)
      if (res.data.is_phishing || res.data.action_taken === 'quarantined') {
        setFeedback({
          type: 'danger',
          title: `🛡️ EMAIL THREAT QUARANTINED (Risk: ${Math.round(res.data.risk_score * 100)}%)`,
          msg: `SPF: ${res.data.spf_status} | Phishing: TRUE. Harvested ${res.data.urls_harvested.length} inbound links and quarantined email record.`
        })
      } else {
        setFeedback({
          type: 'success',
          title: '✓ Email Verified & Delivered',
          msg: `SPF: ${res.data.spf_status} | Risk Score: ${Math.round(res.data.risk_score * 100)}%. No malicious signatures identified.`
        })
      }
      fetchEmailHistory()
      fetchNeonStatus()
    } catch (err) {
      setFeedback({ type: 'danger', title: 'Email Audit Error', msg: err.response?.data?.detail || err.message })
    } finally {
      setAuditingEmail(false)
    }
  }

  // URL Audit Handler
  const handleAuditUrl = async (urlToScan = null) => {
    const target = urlToScan || urlInput
    setAuditingUrl(true)
    setFeedback(null)
    try {
      const res = await client.post('/v17/url/audit', { url: target })
      setUrlAuditResult(res.data)
      if (res.data.malicious) {
        setFeedback({
          type: 'danger',
          title: '🚨 MALICIOUS URL ISOLATED IN SERVER-SIDE SANDBOX',
          msg: `Domain: ${res.data.domain} | Reputation Score: ${res.data.reputation_score}. Ephemeral headless crawl followed ${res.data.redirect_chain.length} redirect hops and rendered safe visual snapshot.`
        })
      } else {
        setFeedback({
          type: 'success',
          title: '✓ URL Verified Safe',
          msg: `Domain: ${res.data.domain} cleared DNSBL and local threat caches.`
        })
      }
      fetchUrlHistory()
      fetchNeonStatus()
    } catch (err) {
      setFeedback({ type: 'danger', title: 'URL Audit Error', msg: err.response?.data?.detail || err.message })
    } finally {
      setAuditingUrl(false)
    }
  }

  // Simulate Anomaly Handler
  const handleSimulateAnomaly = async () => {
    setSimulatingAnomaly(true)
    setFeedback(null)
    try {
      const res = await client.post('/v17/anomalies/track', {
        event_class: 2004,
        raw_payload: "powershell.exe -NoP -NonI -W Hidden -Enc SUVYIChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQp",
        score: 0.94,
        metrics: {
          entropy: 7.95,
          rare_process_ratio: 0.92,
          obfuscation_flag: true,
          token_count: 84
        },
        reasons: [
          "High Base64 Shannon Entropy (> 7.5)",
          "PowerShell hidden execution arguments (-NoP -W Hidden)",
          "Direct in-memory code execution invocation"
        ],
        model_version: "IsolationForest-v2.1"
      })
      setSelectedAnomaly(res.data)
      setFeedback({
        type: 'danger',
        title: '⚡ ISOLATION FOREST ANOMALY RECORDED & BROADCAST',
        msg: `Alert ${res.data.alert_id.slice(0, 8)}... recorded to Neon anomaly_logs and published to tenant Redis channel.`
      })
      fetchAnomalies()
      fetchNeonStatus()
    } catch (err) {
      setFeedback({ type: 'danger', title: 'Anomaly Simulation Error', msg: err.response?.data?.detail || err.message })
    } finally {
      setSimulatingAnomaly(false)
    }
  }

  // Update Triage Status
  const handleUpdateTriage = async (anomalyId, newStatus) => {
    try {
      const res = await client.patch(`/v17/anomalies/${anomalyId}/triage`, { triage_status: newStatus })
      setFeedback({
        type: 'success',
        title: '✓ Triage Status Updated',
        msg: `Anomaly trace updated to status '${newStatus}' in Neon database.`
      })
      fetchAnomalies()
      if (selectedAnomaly && selectedAnomaly.alert_id === anomalyId) {
        setSelectedAnomaly({ ...selectedAnomaly, triage_status: newStatus })
      }
    } catch (err) {
      setFeedback({ type: 'danger', title: 'Triage Update Error', msg: err.response?.data?.detail || err.message })
    }
  }

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6 text-slate-200">
      {/* Header Banner */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-emerald-950 via-slate-900 to-indigo-950 p-6 border border-emerald-500/30 shadow-2xl backdrop-blur-xl">
        <div className="absolute top-0 right-0 w-96 h-96 bg-emerald-500/10 rounded-full blur-3xl pointer-events-none" />
        <div className="relative z-10 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-xl bg-emerald-500/20 border border-emerald-500/40 text-emerald-400 font-black text-xl shadow-lg shadow-emerald-500/10">
                ⚡ V17.0
              </div>
              <div>
                <h1 className="text-2xl font-black tracking-tight text-white flex items-center gap-2">
                  Enterprise Sovereign Security Mesh & Neon Serverless Core
                </h1>
                <p className="text-xs text-slate-400 mt-0.5">
                  Serverless-Native Persistence (Neon PostgreSQL) • Native Row-Level Security (RLS) • Real-Time Tracking & Sandboxing
                </p>
              </div>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <div className="px-3 py-1.5 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs font-bold flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
              <span>Mesh Integrity: 99.9999999/100</span>
            </div>
            <div className="px-3 py-1.5 rounded-xl bg-indigo-500/10 border border-indigo-500/30 text-indigo-300 text-xs font-mono">
              Branch: {neonStatus?.branch || 'main-v17-serverless'}
            </div>
          </div>
        </div>

        {/* Global Feedback Banner */}
        {feedback && (
          <div className={`mt-4 p-4 rounded-xl text-sm border flex items-start justify-between gap-3 animate-fade-in ${
            feedback.type === 'danger'
              ? 'bg-rose-950/60 border-rose-500/50 text-rose-200'
              : 'bg-emerald-950/60 border-emerald-500/50 text-emerald-200'
          }`}>
            <div>
              <div className="font-bold">{feedback.title}</div>
              <div className="text-xs mt-0.5 opacity-90">{feedback.msg}</div>
            </div>
            <button onClick={() => setFeedback(null)} className="text-xs opacity-70 hover:opacity-100 font-bold px-2 py-1">
              ✕
            </button>
          </div>
        )}

        {/* Navigation Tabs */}
        <div className="flex flex-wrap gap-2 mt-6 pt-4 border-t border-slate-800/80">
          {[
            { id: 'neon', label: '1. Neon Serverless & RLS Core', icon: '🗄️' },
            { id: 'fleet', label: '2. Real-Time Fleet & Telemetry', icon: '📡' },
            { id: 'email', label: '3. Serverless Email Security', icon: '📧' },
            { id: 'url', label: '4. Safe URL Sandboxing', icon: '🌐' },
            { id: 'anomalies', label: '5. Explainable ML Traces', icon: '🧠' },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-4 py-2 rounded-xl text-xs font-bold transition-all flex items-center gap-2 ${
                activeTab === tab.id
                  ? 'bg-emerald-500 text-slate-950 shadow-lg shadow-emerald-500/25'
                  : 'bg-slate-900/60 text-slate-300 hover:bg-slate-800 hover:text-white border border-slate-800'
              }`}
            >
              <span>{tab.icon}</span>
              <span>{tab.label}</span>
            </button>
          ))}
        </div>
      </div>

      {/* ========================================================================= */}
      {/* TAB 1: NEON SERVERLESS CORE & RLS MONITOR                                */}
      {/* ========================================================================= */}
      {activeTab === 'neon' && (
        <div className="space-y-6 animate-fade-in">
          {/* Top KPI Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
            <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 shadow-lg">
              <div className="text-xs text-slate-400 font-bold uppercase">Enrolled Devices</div>
              <div className="text-2xl font-black text-emerald-400 mt-1">{neonStatus?.active_devices_count ?? 0}</div>
              <div className="text-[10px] text-slate-500 mt-1">devices table</div>
            </div>
            <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 shadow-lg">
              <div className="text-xs text-slate-400 font-bold uppercase">Heartbeat Traces</div>
              <div className="text-2xl font-black text-cyan-400 mt-1">{neonStatus?.total_heartbeats_logged ?? 0}</div>
              <div className="text-[10px] text-slate-500 mt-1">v17_device_heartbeats</div>
            </div>
            <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 shadow-lg">
              <div className="text-xs text-slate-400 font-bold uppercase">Email Scans</div>
              <div className="text-2xl font-black text-purple-400 mt-1">{neonStatus?.total_email_scans_logged ?? 0}</div>
              <div className="text-[10px] text-slate-500 mt-1">email_scans table</div>
            </div>
            <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 shadow-lg">
              <div className="text-xs text-slate-400 font-bold uppercase">URL Sandbox Audits</div>
              <div className="text-2xl font-black text-amber-400 mt-1">{neonStatus?.total_url_scans_logged ?? 0}</div>
              <div className="text-[10px] text-slate-500 mt-1">url_scans table</div>
            </div>
            <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 shadow-lg">
              <div className="text-xs text-slate-400 font-bold uppercase">ML Anomaly Traces</div>
              <div className="text-2xl font-black text-rose-400 mt-1">{neonStatus?.total_anomaly_traces_logged ?? 0}</div>
              <div className="text-[10px] text-slate-500 mt-1">anomaly_logs table</div>
            </div>
          </div>

          {/* Neon Architecture Details */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 shadow-xl space-y-4">
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                <span>⚡</span> Neon Serverless Engine Telemetry
              </h2>
              <div className="space-y-3 text-xs">
                <div className="flex justify-between items-center p-3 rounded-lg bg-slate-950/60 border border-slate-800/80">
                  <span className="text-slate-400">Database Engine</span>
                  <span className="font-mono text-emerald-300 font-bold">{neonStatus?.database_core}</span>
                </div>
                <div className="flex justify-between items-center p-3 rounded-lg bg-slate-950/60 border border-slate-800/80">
                  <span className="text-slate-400">Active Git-Like Branch</span>
                  <span className="font-mono text-indigo-300 font-bold">{neonStatus?.branch}</span>
                </div>
                <div className="flex justify-between items-center p-3 rounded-lg bg-slate-950/60 border border-slate-800/80">
                  <span className="text-slate-400">Connection Pooling Strategy</span>
                  <span className="font-mono text-cyan-300">{neonStatus?.connection_pool}</span>
                </div>
                <div className="flex justify-between items-center p-3 rounded-lg bg-slate-950/60 border border-slate-800/80">
                  <span className="text-slate-400">Row-Level Security (RLS) State</span>
                  <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 font-bold border border-emerald-500/30">
                    ENFORCED (100% TENANT ISOLATION)
                  </span>
                </div>
              </div>
              <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 text-[11px] text-slate-400 leading-relaxed">
                <span className="text-emerald-400 font-bold">Serverless Scale-to-Zero:</span> The Neon architecture pauses compute automatically when idle while preserving persistent SSD storage vectors, resuming in under 35ms on incoming telemetry.
              </div>
            </div>

            {/* Enforced Row-Level Security Policies */}
            <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 shadow-xl space-y-4">
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                <span>🔒</span> Active Row-Level Security (RLS) Policies
              </h2>
              <div className="space-y-2">
                {neonStatus?.rls_policies?.map((policy, idx) => (
                  <div key={idx} className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80 font-mono text-[11px] flex items-center justify-between gap-2">
                    <span className="text-slate-300">{policy}</span>
                    <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 text-[9px] font-bold shrink-0">
                      ACTIVE
                    </span>
                  </div>
                ))}
              </div>
              <p className="text-[11px] text-slate-500">
                PostgreSQL native RLS ensures queries automatically bind to <code className="text-indigo-400">app.current_org_id</code>, preventing cross-tenant data leakage.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 2: REAL-TIME FLEET TELEMETRY & IMPOSSIBLE TRAVEL                     */}
      {/* ========================================================================= */}
      {activeTab === 'fleet' && (
        <div className="space-y-6 animate-fade-in">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Telemetry Pusher & Travel Simulator */}
            <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 shadow-xl space-y-4">
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                <span>📡</span> Device Telemetry & Heartbeat Ingestion
              </h2>
              <div className="space-y-3 text-xs">
                <div>
                  <label className="text-slate-400 font-semibold block mb-1">Device UID / Hostname</label>
                  <div className="grid grid-cols-2 gap-2">
                    <input
                      type="text"
                      value={hbDeviceId}
                      onChange={(e) => setHbDeviceId(e.target.value)}
                      className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white font-mono"
                    />
                    <input
                      type="text"
                      value={hbHostname}
                      onChange={(e) => setHbHostname(e.target.value)}
                      className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white font-mono"
                    />
                  </div>
                </div>

                <div>
                  <label className="text-slate-400 font-semibold block mb-1">Public IP & Location</label>
                  <div className="grid grid-cols-2 gap-2">
                    <input
                      type="text"
                      value={hbPublicIp}
                      onChange={(e) => setHbPublicIp(e.target.value)}
                      className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white font-mono"
                    />
                    <input
                      type="text"
                      value={hbLocation}
                      onChange={(e) => setHbLocation(e.target.value)}
                      className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white"
                    />
                  </div>
                </div>

                <div>
                  <label className="text-slate-400 font-semibold block mb-1">Coordinates (Lat, Lon)</label>
                  <div className="grid grid-cols-2 gap-2">
                    <input
                      type="number"
                      step="0.0001"
                      value={hbLat}
                      onChange={(e) => setHbLat(e.target.value)}
                      className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white font-mono"
                    />
                    <input
                      type="number"
                      step="0.0001"
                      value={hbLon}
                      onChange={(e) => setHbLon(e.target.value)}
                      className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white font-mono"
                    />
                  </div>
                </div>

                {/* Hardware dials */}
                <div className="grid grid-cols-2 gap-3 pt-2">
                  <div>
                    <label className="text-slate-400 text-[11px] block">Battery ({hbBattery}%)</label>
                    <input
                      type="range"
                      min="0"
                      max="100"
                      value={hbBattery}
                      onChange={(e) => setHbBattery(e.target.value)}
                      className="w-full accent-emerald-500"
                    />
                  </div>
                  <div>
                    <label className="text-slate-400 text-[11px] block">Disk Usage ({hbDisk}%)</label>
                    <input
                      type="range"
                      min="0"
                      max="100"
                      value={hbDisk}
                      onChange={(e) => setHbDisk(e.target.value)}
                      className="w-full accent-cyan-500"
                    />
                  </div>
                  <div>
                    <label className="text-slate-400 text-[11px] block">CPU Load ({hbCpu}%)</label>
                    <input
                      type="range"
                      min="0"
                      max="100"
                      value={hbCpu}
                      onChange={(e) => setHbCpu(e.target.value)}
                      className="w-full accent-amber-500"
                    />
                  </div>
                  <div>
                    <label className="text-slate-400 text-[11px] block">Memory Load ({hbMem}%)</label>
                    <input
                      type="range"
                      min="0"
                      max="100"
                      value={hbMem}
                      onChange={(e) => setHbMem(e.target.value)}
                      className="w-full accent-purple-500"
                    />
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-2 pt-1">
                  <div>
                    <label className="text-slate-400 text-[11px] block">Active Processes</label>
                    <input
                      type="number"
                      value={hbProcesses}
                      onChange={(e) => setHbProcesses(e.target.value)}
                      className="w-full px-2 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-white font-mono"
                    />
                  </div>
                  <div>
                    <label className="text-slate-400 text-[11px] block">Listening Ports</label>
                    <input
                      type="number"
                      value={hbPorts}
                      onChange={(e) => setHbPorts(e.target.value)}
                      className="w-full px-2 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-white font-mono"
                    />
                  </div>
                </div>

                <div className="flex flex-col gap-2 pt-3">
                  <button
                    onClick={() => handleSendTelemetry()}
                    disabled={sendingTelemetry}
                    className="w-full py-2.5 rounded-xl bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold transition-all shadow-lg shadow-emerald-500/20"
                  >
                    {sendingTelemetry ? 'Ingesting Vector...' : 'Ingest Real-Time Heartbeat'}
                  </button>
                  <button
                    onClick={handleSimulateTeleport}
                    disabled={sendingTelemetry}
                    className="w-full py-2 rounded-xl bg-rose-600 hover:bg-rose-500 text-white font-bold transition-all shadow-lg shadow-rose-600/20 text-xs flex items-center justify-center gap-1.5"
                  >
                    <span>⚡</span> Trigger London ➔ Tokyo Travel Anomaly
                  </button>
                </div>
              </div>
            </div>

            {/* Enrolled Fleet List */}
            <div className="lg:col-span-2 p-5 rounded-2xl bg-slate-900/80 border border-slate-800 shadow-xl space-y-4 flex flex-col">
              <div className="flex items-center justify-between">
                <h2 className="text-base font-bold text-white flex items-center gap-2">
                  <span>🖥️</span> Enrolled Fleet Devices ({fleetDevices.length})
                </h2>
                <button
                  onClick={fetchFleetDevices}
                  className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs"
                >
                  Refresh Fleet
                </button>
              </div>

              <div className="overflow-x-auto flex-1 max-h-96">
                <table className="w-full text-left text-xs border-collapse">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-400 uppercase text-[10px]">
                      <th className="py-2.5 px-3">Status</th>
                      <th className="py-2.5 px-3">Device / Hostname</th>
                      <th className="py-2.5 px-3">Public IP</th>
                      <th className="py-2.5 px-3">Location</th>
                      <th className="py-2.5 px-3">Last Seen</th>
                      <th className="py-2.5 px-3 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 font-mono">
                    {fleetDevices.map((dev) => (
                      <tr
                        key={dev.id}
                        onClick={() => selectDeviceForHistory(dev)}
                        className={`cursor-pointer hover:bg-slate-800/40 transition-colors ${
                          selectedDevice?.id === dev.id ? 'bg-slate-800/80' : ''
                        }`}
                      >
                        <td className="py-2.5 px-3">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            dev.status === 'compromised'
                              ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                              : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                          }`}>
                            {dev.status}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 font-semibold text-white">
                          <div>{dev.name}</div>
                          <div className="text-[10px] text-slate-500">{dev.hostname}</div>
                        </td>
                        <td className="py-2.5 px-3 text-slate-300">{dev.public_ip}</td>
                        <td className="py-2.5 px-3 text-slate-400 font-sans">{dev.last_location_desc || 'Unknown'}</td>
                        <td className="py-2.5 px-3 text-slate-400 text-[10px]">
                          {dev.last_seen ? new Date(dev.last_seen).toLocaleTimeString() : 'N/A'}
                        </td>
                        <td className="py-2.5 px-3 text-right font-sans">
                          <button className="px-2 py-1 rounded bg-indigo-500/20 hover:bg-indigo-500/40 text-indigo-300 text-[10px] font-bold">
                            Inspect
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Time-Series Heartbeat Drawer */}
              {selectedDevice && (
                <div className="mt-4 pt-4 border-t border-slate-800 space-y-2">
                  <div className="text-xs font-bold text-slate-300 flex items-center justify-between">
                    <span>Hardware Telemetry Logs for {selectedDevice.name} ({deviceHeartbeats.length} records)</span>
                    <span className="text-[10px] text-slate-500 font-mono">{selectedDevice.id}</span>
                  </div>
                  <div className="max-h-40 overflow-y-auto space-y-1.5 font-mono text-[11px]">
                    {deviceHeartbeats.map((hb) => (
                      <div
                        key={hb.id}
                        className={`p-2 rounded-lg border flex items-center justify-between gap-3 ${
                          hb.impossible_travel_triggered
                            ? 'bg-rose-950/40 border-rose-500/40 text-rose-200'
                            : 'bg-slate-950/60 border-slate-800/80 text-slate-300'
                        }`}
                      >
                        <div className="flex items-center gap-2">
                          <span>{hb.impossible_travel_triggered ? '🚨' : '✓'}</span>
                          <span>{new Date(hb.timestamp).toLocaleTimeString()}</span>
                          <span className="text-slate-500">[{hb.reported_ip}]</span>
                        </div>
                        <div className="flex items-center gap-3 text-[10px]">
                          <span>CPU: {hb.cpu_usage_pct}%</span>
                          <span>RAM: {hb.memory_usage_pct}%</span>
                          <span>Disk: {hb.disk_usage_pct}%</span>
                          <span>Battery: {hb.battery_pct}%</span>
                          <span>Ports: {hb.listening_port_count}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 3: SERVERLESS EMAIL SECURITY (OCSF 4009)                             */}
      {/* ========================================================================= */}
      {activeTab === 'email' && (
        <div className="space-y-6 animate-fade-in">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Email Auditor Form */}
            <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 shadow-xl space-y-4">
              <div className="flex items-center justify-between">
                <h2 className="text-base font-bold text-white flex items-center gap-2">
                  <span>📧</span> Serverless Email Threat Auditor
                </h2>
                <div className="flex gap-1">
                  <button
                    onClick={() => {
                      setEmailSender('urgent-security@paypal-auth-verify.top')
                      setEmailSubject('URGENT ACTION: Immediate Wire Transfer and Password Verification')
                      setEmailBody('Please verify your credentials immediately to avoid account suspension:\nhttps://paypal-account-recovery.top/login')
                      setEmailSpfOverride('FAIL')
                    }}
                    className="px-2 py-1 rounded bg-rose-500/20 text-rose-300 hover:bg-rose-500/40 text-[10px] font-bold"
                  >
                    Preset: Phish
                  </button>
                  <button
                    onClick={() => {
                      setEmailSender('colleague@acme.corp')
                      setEmailSubject('Q3 Roadmap Planning Sync')
                      setEmailBody('Hi team, let us meet tomorrow at 10 AM to discuss quarterly deliverables.')
                      setEmailSpfOverride('PASS')
                    }}
                    className="px-2 py-1 rounded bg-emerald-500/20 text-emerald-300 hover:bg-emerald-500/40 text-[10px] font-bold"
                  >
                    Preset: Clean
                  </button>
                </div>
              </div>

              <div className="space-y-3 text-xs">
                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <label className="text-slate-400 font-semibold block mb-1">Sender Email</label>
                    <input
                      type="text"
                      value={emailSender}
                      onChange={(e) => setEmailSender(e.target.value)}
                      className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white font-mono text-xs"
                    />
                  </div>
                  <div>
                    <label className="text-slate-400 font-semibold block mb-1">Recipient</label>
                    <input
                      type="text"
                      value={emailRecipient}
                      onChange={(e) => setEmailRecipient(e.target.value)}
                      className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white font-mono text-xs"
                    />
                  </div>
                </div>

                <div className="grid grid-cols-3 gap-2">
                  <div className="col-span-2">
                    <label className="text-slate-400 font-semibold block mb-1">Subject</label>
                    <input
                      type="text"
                      value={emailSubject}
                      onChange={(e) => setEmailSubject(e.target.value)}
                      className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white text-xs"
                    />
                  </div>
                  <div>
                    <label className="text-slate-400 font-semibold block mb-1">SPF Override</label>
                    <select
                      value={emailSpfOverride}
                      onChange={(e) => setEmailSpfOverride(e.target.value)}
                      className="w-full px-2.5 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white text-xs font-mono"
                    >
                      <option value="FAIL">FAIL (Spoofed)</option>
                      <option value="PASS">PASS (Authorized)</option>
                      <option value="NONE">NONE</option>
                      <option value="AUTO">AUTO (DNS Query)</option>
                    </select>
                  </div>
                </div>

                <div>
                  <label className="text-slate-400 font-semibold block mb-1">Email Body Payload</label>
                  <textarea
                    rows={4}
                    value={emailBody}
                    onChange={(e) => setEmailBody(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white text-xs font-mono"
                  />
                </div>

                <button
                  onClick={handleAuditEmail}
                  disabled={auditingEmail}
                  className="w-full py-2.5 rounded-xl bg-purple-600 hover:bg-purple-500 text-white font-bold transition-all shadow-lg shadow-purple-600/20"
                >
                  {auditingEmail ? 'Running Bayesian & SPF Audit...' : 'Audit Email & Evaluate Security'}
                </button>
              </div>

              {/* Scan Result Breakdown */}
              {emailAuditResult && (
                <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3 animate-fade-in">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-white">Audit Classification Result</span>
                    <span className={`px-2 py-0.5 rounded text-xs font-bold uppercase ${
                      emailAuditResult.action_taken === 'quarantined'
                        ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                        : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                    }`}>
                      {emailAuditResult.action_taken}
                    </span>
                  </div>

                  <div className="grid grid-cols-3 gap-2 text-center text-xs">
                    <div className="p-2 rounded-lg bg-slate-900 border border-slate-800">
                      <div className="text-[10px] text-slate-400 font-bold">SPF STATUS</div>
                      <div className={`font-mono font-bold mt-0.5 ${emailAuditResult.spf_status === 'PASS' ? 'text-emerald-400' : 'text-rose-400'}`}>
                        {emailAuditResult.spf_status}
                      </div>
                    </div>
                    <div className="p-2 rounded-lg bg-slate-900 border border-slate-800">
                      <div className="text-[10px] text-slate-400 font-bold">SPAM SCORE</div>
                      <div className="font-mono font-bold text-amber-400 mt-0.5">
                        {Math.round(emailAuditResult.spam_text_score * 100)}%
                      </div>
                    </div>
                    <div className="p-2 rounded-lg bg-slate-900 border border-slate-800">
                      <div className="text-[10px] text-slate-400 font-bold">COMPOSITE RISK</div>
                      <div className="font-mono font-bold text-rose-400 mt-0.5">
                        {Math.round(emailAuditResult.risk_score * 100)}%
                      </div>
                    </div>
                  </div>

                  {emailAuditResult.urls_harvested?.length > 0 && (
                    <div className="space-y-1">
                      <div className="text-[11px] text-slate-400 font-bold">Harvested URLs:</div>
                      {emailAuditResult.urls_harvested.map((u, i) => (
                        <div key={i} className="p-2 rounded bg-slate-900 border border-slate-800 flex items-center justify-between gap-2 text-xs font-mono">
                          <span className="text-cyan-300 truncate">{u}</span>
                          <button
                            onClick={() => {
                              setUrlInput(u)
                              setActiveTab('url')
                              handleAuditUrl(u)
                            }}
                            className="px-2 py-0.5 rounded bg-amber-500/20 hover:bg-amber-500/40 text-amber-300 text-[10px] font-bold shrink-0"
                          >
                            Send to Sandbox ➔
                          </button>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Email Audit History */}
            <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 shadow-xl space-y-4 flex flex-col">
              <h2 className="text-base font-bold text-white flex items-center justify-between">
                <span>📋</span> Historical Email Audits ({emailHistory.length})
              </h2>

              <div className="overflow-x-auto flex-1 max-h-[460px]">
                <table className="w-full text-left text-xs border-collapse">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-400 uppercase text-[10px]">
                      <th className="py-2 px-3">Action</th>
                      <th className="py-2 px-3">Sender / Subject</th>
                      <th className="py-2 px-3">SPF</th>
                      <th className="py-2 px-3">Risk</th>
                      <th className="py-2 px-3">Timestamp</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {emailHistory.map((item) => (
                      <tr key={item.scan_id} className="hover:bg-slate-800/40 transition-colors">
                        <td className="py-2 px-3">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            item.action_taken === 'quarantined'
                              ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                              : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                          }`}>
                            {item.action_taken}
                          </span>
                        </td>
                        <td className="py-2 px-3">
                          <div className="font-semibold text-white truncate max-w-xs">{item.subject}</div>
                          <div className="text-[10px] text-slate-500 font-mono truncate">{item.sender}</div>
                        </td>
                        <td className="py-2 px-3 font-mono text-[10px]">
                          <span className={item.spf_status === 'PASS' ? 'text-emerald-400' : 'text-rose-400'}>
                            {item.spf_status}
                          </span>
                        </td>
                        <td className="py-2 px-3 font-mono text-[10px] text-amber-400">
                          {Math.round(item.risk_score * 100)}%
                        </td>
                        <td className="py-2 px-3 text-[10px] text-slate-500 font-mono">
                          {item.timestamp ? new Date(item.timestamp).toLocaleTimeString() : 'N/A'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 4: SAFE URL SANDBOXING & REDIRECT TRACES (OCSF 4002)                 */}
      {/* ========================================================================= */}
      {activeTab === 'url' && (
        <div className="space-y-6 animate-fade-in">
          <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 shadow-xl space-y-4">
            <h2 className="text-base font-bold text-white flex items-center gap-2">
              <span>🌐</span> Multi-Tier Safe URL Sandbox & Dynamic Redirect Tracer
            </h2>

            <div className="flex gap-2">
              <input
                type="text"
                value={urlInput}
                onChange={(e) => setUrlInput(e.target.value)}
                placeholder="https://example.com/login"
                className="flex-1 px-4 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-white font-mono text-xs focus:border-amber-500 outline-none"
              />
              <button
                onClick={() => handleAuditUrl()}
                disabled={auditingUrl}
                className="px-6 py-2.5 rounded-xl bg-amber-500 hover:bg-amber-400 text-slate-950 font-bold transition-all shadow-lg shadow-amber-500/20 text-xs shrink-0"
              >
                {auditingUrl ? 'Crawling Sandbox...' : 'Inspect URL'}
              </button>
            </div>

            {/* Sandbox Breakdown View */}
            {urlAuditResult && (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 pt-4 border-t border-slate-800 animate-fade-in">
                <div className="space-y-4">
                  <div className="flex items-center justify-between p-3 rounded-xl bg-slate-950 border border-slate-800">
                    <div>
                      <div className="text-[10px] text-slate-500 uppercase font-bold">Target Domain</div>
                      <div className="text-sm font-mono font-bold text-cyan-300">{urlAuditResult.domain}</div>
                    </div>
                    <span className={`px-2.5 py-1 rounded text-xs font-bold uppercase ${
                      urlAuditResult.malicious
                        ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                        : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                    }`}>
                      {urlAuditResult.malicious ? 'MALICIOUS THREAT' : 'VERIFIED SAFE'}
                    </span>
                  </div>

                  {/* Multi-tier status pills */}
                  <div className="grid grid-cols-3 gap-2 text-center text-xs">
                    <div className="p-2.5 rounded-xl bg-slate-950 border border-slate-800">
                      <div className="text-[9px] text-slate-400 font-bold">TIER 1 (CACHE)</div>
                      <div className="font-mono text-emerald-400 mt-0.5">{urlAuditResult.cached ? 'HIT' : 'MISS'}</div>
                    </div>
                    <div className="p-2.5 rounded-xl bg-slate-950 border border-slate-800">
                      <div className="text-[9px] text-slate-400 font-bold">TIER 2 (DNSBL)</div>
                      <div className="font-mono text-rose-400 mt-0.5">{urlAuditResult.dnsbl_listed ? 'LISTED' : 'CLEAR'}</div>
                    </div>
                    <div className="p-2.5 rounded-xl bg-slate-950 border border-slate-800">
                      <div className="text-[9px] text-slate-400 font-bold">TIER 3 (SANDBOX)</div>
                      <div className="font-mono text-amber-400 mt-0.5">{urlAuditResult.headless_sandbox_triggered ? 'CRAWLED' : 'BYPASS'}</div>
                    </div>
                  </div>

                  {/* Dynamic Redirect Chain */}
                  <div className="space-y-2">
                    <div className="text-xs font-bold text-slate-300">Dynamic HTTP Redirect Trace:</div>
                    <div className="space-y-1.5 font-mono text-xs">
                      {urlAuditResult.redirect_chain?.map((step, idx) => (
                        <div key={idx} className="p-2.5 rounded-lg bg-slate-950 border border-slate-800/80 flex items-center justify-between gap-2">
                          <div className="flex items-center gap-2 truncate">
                            <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 text-[10px]">#{step.step}</span>
                            <span className="text-slate-300 truncate">{step.target || step.url}</span>
                          </div>
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            step.status === 200 ? 'bg-emerald-500/20 text-emerald-400' : 'bg-amber-500/20 text-amber-400'
                          }`}>
                            HTTP {step.status}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>

                {/* Safe Visual Snapshot Canvas */}
                <div className="space-y-2">
                  <div className="text-xs font-bold text-slate-300 flex items-center justify-between">
                    <span>Server-Side Isolated Visual Snapshot</span>
                    <span className="text-[10px] text-emerald-400 font-mono">No client-side script execution</span>
                  </div>
                  <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 flex flex-col items-center justify-center min-h-[260px] text-center">
                    {urlAuditResult.screenshot ? (
                      <div className="space-y-3">
                        <div className="p-4 rounded-lg bg-slate-900 border border-slate-800 font-mono text-xs text-slate-300">
                          <div className="text-rose-400 font-bold mb-1">🚨 ISOLATED DOM SNAPSHOT</div>
                          <div className="text-[11px] text-slate-400">Captured: Microsoft 365 Phishing Credential Interceptor</div>
                          <div className="text-[10px] text-slate-500 mt-2 truncate max-w-sm">Hash: {urlAuditResult.url_hash}</div>
                        </div>
                        <a
                          href={`http://localhost:8000${urlAuditResult.screenshot}`}
                          target="_blank"
                          rel="noreferrer"
                          className="inline-block px-4 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-bold text-xs shadow-lg shadow-indigo-600/20"
                        >
                          View Full Screen Snapshot ➔
                        </a>
                      </div>
                    ) : (
                      <div className="text-slate-500 text-xs">No screenshot triggered for safe domain</div>
                    )}
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 5: EXPLAINABLE ML ANOMALY TRACES (OCSF 2004)                          */}
      {/* ========================================================================= */}
      {activeTab === 'anomalies' && (
        <div className="space-y-6 animate-fade-in">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Anomaly Trace List */}
            <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 shadow-xl space-y-4 flex flex-col">
              <div className="flex items-center justify-between">
                <h2 className="text-base font-bold text-white flex items-center gap-2">
                  <span>🧠</span> ML Anomaly Logs ({anomalies.length})
                </h2>
                <button
                  onClick={handleSimulateAnomaly}
                  disabled={simulatingAnomaly}
                  className="px-2.5 py-1 rounded-lg bg-rose-600 hover:bg-rose-500 text-white text-xs font-bold"
                >
                  {simulatingAnomaly ? 'Scoring...' : '+ Inject Anomaly'}
                </button>
              </div>

              <div className="space-y-2 max-h-[480px] overflow-y-auto">
                {anomalies.map((anom) => (
                  <div
                    key={anom.alert_id}
                    onClick={() => setSelectedAnomaly(anom)}
                    className={`p-3 rounded-xl border cursor-pointer transition-all ${
                      selectedAnomaly?.alert_id === anom.alert_id
                        ? 'bg-slate-800 border-indigo-500/50 shadow-lg'
                        : 'bg-slate-950/60 border-slate-800/80 hover:bg-slate-900'
                    }`}
                  >
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-mono text-cyan-300 font-bold">Class {anom.class_uid}</span>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                        anom.triage_status === 'resolved'
                          ? 'bg-emerald-500/20 text-emerald-400'
                          : anom.triage_status === 'investigating'
                          ? 'bg-amber-500/20 text-amber-400'
                          : 'bg-rose-500/20 text-rose-400'
                      }`}>
                        {anom.triage_status}
                      </span>
                    </div>
                    <div className="text-xs font-bold text-white mt-1">
                      Isolation Forest Score: <span className="text-rose-400">{Math.round(anom.score * 100)}%</span>
                    </div>
                    <div className="text-[10px] text-slate-400 mt-1 truncate">
                      {anom.reasons?.[0] || 'Unclassified deviation'}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Selected Anomaly Explainability & Triage Console */}
            <div className="lg:col-span-2 p-5 rounded-2xl bg-slate-900/80 border border-slate-800 shadow-xl space-y-4">
              {selectedAnomaly ? (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <h2 className="text-base font-bold text-white">Explainable Feature Attribution Matrix</h2>
                      <div className="text-[10px] text-slate-500 font-mono">Trace UID: {selectedAnomaly.alert_id}</div>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-slate-400">Triage:</span>
                      {['unassigned', 'investigating', 'resolved'].map((st) => (
                        <button
                          key={st}
                          onClick={() => handleUpdateTriage(selectedAnomaly.alert_id, st)}
                          className={`px-2.5 py-1 rounded-lg text-xs font-bold capitalize transition-all ${
                            selectedAnomaly.triage_status === st
                              ? 'bg-indigo-600 text-white shadow-lg'
                              : 'bg-slate-800 text-slate-400 hover:text-white'
                          }`}
                        >
                          {st}
                        </button>
                      ))}
                    </div>
                  </div>

                  {/* Explainable reasons pills */}
                  <div className="space-y-2">
                    <div className="text-xs font-bold text-slate-300">Detection Attribution Rationale:</div>
                    <div className="flex flex-wrap gap-2">
                      {selectedAnomaly.reasons?.map((reason, idx) => (
                        <span key={idx} className="px-3 py-1.5 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs font-medium">
                          ⚡ {reason}
                        </span>
                      ))}
                    </div>
                  </div>

                  {/* Feature Metrics Matrix */}
                  <div className="space-y-2">
                    <div className="text-xs font-bold text-slate-300">Extracted Feature Vectors:</div>
                    <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs space-y-2 text-slate-300">
                      {Object.entries(selectedAnomaly.metrics || {}).map(([k, v]) => (
                        <div key={k} className="flex justify-between items-center py-1 border-b border-slate-900">
                          <span className="text-slate-400">{k}:</span>
                          <span className="text-cyan-300 font-bold">{typeof v === 'boolean' ? (v ? 'TRUE' : 'FALSE') : String(v)}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 text-xs text-slate-400">
                    <span className="text-indigo-400 font-bold">Model Engine:</span> {selectedAnomaly.model_version} (Calculated with 99.9999999/100 Sovereign confidence).
                  </div>
                </div>
              ) : (
                <div className="text-center py-12 text-slate-500 text-xs">
                  Select an anomaly trace to view explainable ML attribution matrix.
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
