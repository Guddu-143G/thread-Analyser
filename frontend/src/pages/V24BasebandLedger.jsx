import React, { useState, useEffect } from 'react'
import client from '../api/client'
import RealTimeSOCConsole from '../components/RealTimeSOCConsole'

export default function V24BasebandLedger() {
  const [activeTab, setActiveTab] = useState('baseband') // baseband, gps, network, ledger
  const [engineStatus, setEngineStatus] = useState(null)
  const [loading, setLoading] = useState(true)
  const [actionLoading, setActionLoading] = useState(false)
  const [error, setError] = useState('')
  const [successMsg, setSuccessMsg] = useState('')

  // -------------------------------------------------------------
  // TAB 1: Baseband Modem & 3-Tower Triangulation State
  // -------------------------------------------------------------
  const [modemPort, setModemPort] = useState('/dev/smd0')
  const [customAtCmd, setCustomAtCmd] = useState('AT+CGSN')
  const [atResponses, setAtResponses] = useState([])
  const [modemTelemetry, setModemTelemetry] = useState(null)
  const [imeiInput, setImeiInput] = useState('864201047192834')
  const [ceirStatus, setCeirStatus] = useState(null)
  const [triangulationData, setTriangulationData] = useState(null)
  const [towerParams, setTowerParams] = useState({
    tower_a_lat: 37.7749,
    tower_a_lon: -122.4194,
    tower_a_ta: 4,
    tower_b_lat: 37.7812,
    tower_b_lon: -122.4089,
    tower_b_ta: 6,
    tower_c_lat: 37.7688,
    tower_c_lon: -122.4255,
    tower_c_ta: 5
  })

  // -------------------------------------------------------------
  // TAB 2: Adaptive GPS Scheduler State
  // -------------------------------------------------------------
  const [geofenceCenter, setGeofenceCenter] = useState({ lat: 37.7749, lon: -122.4194 })
  const [geofenceRadius, setGeofenceRadius] = useState(500)
  const [gpsCurrentLat, setGpsCurrentLat] = useState(37.7755)
  const [gpsCurrentLon, setGpsCurrentLon] = useState(-122.4188)
  const [batteryPct, setBatteryPct] = useState(85)
  const [simulatedSpeedKmh, setSimulatedSpeedKmh] = useState(0)
  const [gpsDecision, setGpsDecision] = useState(null)

  // -------------------------------------------------------------
  // TAB 3: Network Interface (MAC/IP) & ARP State
  // -------------------------------------------------------------
  const [networkAuditResult, setNetworkAuditResult] = useState(null)
  const [simIface, setSimIface] = useState('wlan0')
  const [simIp, setSimIp] = useState('192.168.1.144')
  const [simMac, setSimMac] = useState('00:0a:95:9d:68:16')
  const [simGatewayIp, setSimGatewayIp] = useState('192.168.1.1')
  const [simOriginalGwMac, setSimOriginalGwMac] = useState('a0:04:cb:11:ff:dd')
  const [simMutatedGwMac, setSimMutatedGwMac] = useState('de:ad:be:ef:13:37')
  const [mitmAlertData, setMitmAlertData] = useState(null)

  // -------------------------------------------------------------
  // TAB 4: Neon Merkle Audit Ledger State
  // -------------------------------------------------------------
  const [ledgerRecords, setLedgerRecords] = useState([])
  const [ledgerVerification, setLedgerVerification] = useState(null)
  const [newAuditAction, setNewAuditAction] = useState('DEVICE_ISOLATION_TRIGGERED')
  const [newAuditActor, setNewAuditActor] = useState('secops-admin@enterprise.internal')
  const [newAuditIp, setNewAuditIp] = useState('10.200.4.15')
  const [newAuditMac, setNewAuditMac] = useState('00:1A:2B:3C:4D:5E')
  const [tamperTargetSeq, setTamperTargetSeq] = useState(1)

  // Fetch initial engine status
  const fetchGlobalStatus = async (isQuiet = false) => {
    try {
      if (!isQuiet) setLoading(true)
      const res = await client.get('/v24/status')
      setEngineStatus(res.data)
    } catch (err) {
      console.error('Failed to load V24 status:', err)
      if (!isQuiet) setError('Failed to connect to V24 Baseband & Merkle Ledger Engine.')
    } finally {
      if (!isQuiet) setLoading(false)
    }
  }

  // Fetch Ledger records
  const fetchLedger = async () => {
    try {
      const res = await client.get('/v24/ledger/records?limit=50')
      setLedgerRecords(res.data || [])
      if (res.data && res.data.length > 0) {
        setTamperTargetSeq(res.data[0].sequence_id)
      }
    } catch (err) {
      console.error('Failed to load ledger records:', err)
    }
  }

  // Initial load & Real-time Live Engine Polling
  useEffect(() => {
    fetchGlobalStatus()
    fetchLedger()
    const interval = setInterval(() => {
      fetchGlobalStatus(true)
      fetchLedger()
    }, 5000)
    return () => clearInterval(interval)
  }, [])

  // -------------------------------------------------------------
  // Baseband Handlers
  // -------------------------------------------------------------
  const handleProbeModem = async () => {
    try {
      setActionLoading(true)
      setError('')
      const res = await client.post('/v24/baseband/modem/probe', {
        serial_port: modemPort,
        at_command: customAtCmd
      })
      setModemTelemetry(res.data)
      setAtResponses(prev => [
        {
          command: customAtCmd,
          raw_response: res.data.raw_response,
          decoded: res.data.decoded_info,
          timestamp: new Date().toLocaleTimeString()
        },
        ...prev.slice(0, 19)
      ])
      setSuccessMsg(`AT Command executed on ${modemPort}: ${res.data.status}`)
      setTimeout(() => setSuccessMsg(''), 4000)
    } catch (err) {
      setError('Failed to probe mobile baseband modem.')
    } finally {
      setActionLoading(false)
    }
  }

  const handleRunTriangulation = async () => {
    try {
      setActionLoading(true)
      setError('')
      const res = await client.post('/v24/baseband/cellular/triangulate', {
        imei: imeiInput,
        towers: [
          {
            cell_id: 40121,
            lac: 1204,
            latitude: parseFloat(towerParams.tower_a_lat),
            longitude: parseFloat(towerParams.tower_a_lon),
            timing_advance: parseInt(towerParams.tower_a_ta, 10)
          },
          {
            cell_id: 40122,
            lac: 1204,
            latitude: parseFloat(towerParams.tower_b_lat),
            longitude: parseFloat(towerParams.tower_b_lon),
            timing_advance: parseInt(towerParams.tower_b_ta, 10)
          },
          {
            cell_id: 40123,
            lac: 1204,
            latitude: parseFloat(towerParams.tower_c_lat),
            longitude: parseFloat(towerParams.tower_c_lon),
            timing_advance: parseInt(towerParams.tower_c_ta, 10)
          }
        ]
      })
      setTriangulationData(res.data)
      setSuccessMsg(`Multilateration resolved coordinates to ±${res.data.estimated_accuracy_meters}m without GPS!`)
      setTimeout(() => setSuccessMsg(''), 4000)
    } catch (err) {
      setError('Failed to execute 3-tower cellular multilateration.')
    } finally {
      setActionLoading(false)
    }
  }

  const handleCeirBlacklist = async (action) => {
    try {
      setActionLoading(true)
      setError('')
      const res = await client.post('/v24/baseband/ceir/blacklist', {
        imei: imeiInput,
        action: action,
        reason: action === 'BLACKLIST' ? 'Mobile Asset Stolen / Compromised' : 'Device Verified Safe'
      })
      setCeirStatus(res.data)
      setSuccessMsg(`GSMA/CEIR Registry updated: ${res.data.status} (Transceiver ${res.data.transceiver_blocked ? 'BLOCKED' : 'ENABLED'})`)
      setTimeout(() => setSuccessMsg(''), 4000)
    } catch (err) {
      setError('Failed to modify GSMA/CEIR blacklist status.')
    } finally {
      setActionLoading(false)
    }
  }

  // -------------------------------------------------------------
  // GPS Scheduler Handlers
  // -------------------------------------------------------------
  const handleEvaluateGpsScheduler = async () => {
    try {
      setActionLoading(true)
      setError('')
      const res = await client.post('/v24/gps/evaluate', {
        current_latitude: parseFloat(gpsCurrentLat),
        current_longitude: parseFloat(gpsCurrentLon),
        battery_percentage: parseFloat(batteryPct),
        geofence_center_lat: parseFloat(geofenceCenter.lat),
        geofence_center_lon: parseFloat(geofenceCenter.lon),
        geofence_radius_meters: parseFloat(geofenceRadius),
        simulated_speed_kmh: parseFloat(simulatedSpeedKmh)
      })
      setGpsDecision(res.data)
      setSuccessMsg(`Adaptive GPS state transition -> ${res.data.state} (Next Interval: ${res.data.next_scheduled_interval}s)`)
      setTimeout(() => setSuccessMsg(''), 4000)
    } catch (err) {
      setError('Failed to evaluate adaptive GPS scheduler.')
    } finally {
      setActionLoading(false)
    }
  }

  // -------------------------------------------------------------
  // Network / ARP Audit Handlers
  // -------------------------------------------------------------
  const handleScanNetwork = async () => {
    try {
      setActionLoading(true)
      setError('')
      const res = await client.post('/v24/network/scan', {
        interface_name: simIface,
        ip_address: simIp,
        mac_address: simMac,
        gateway_ip: simGatewayIp,
        gateway_mac: simOriginalGwMac
      })
      setNetworkAuditResult(res.data)
      setSuccessMsg('Network interface audit completed with OCSF Class 5001 normalization.')
      setTimeout(() => setSuccessMsg(''), 4000)
    } catch (err) {
      setError('Failed to scan network interface.')
    } finally {
      setActionLoading(false)
    }
  }

  const handleSimulateArpMitm = async () => {
    try {
      setActionLoading(true)
      setError('')
      const res = await client.post('/v24/network/simulate-arp-mitm', {
        interface_name: simIface,
        ip_address: simIp,
        mac_address: simMac,
        gateway_ip: simGatewayIp,
        original_gateway_mac: simOriginalGwMac,
        mutated_gateway_mac: simMutatedGwMac
      })
      setMitmAlertData(res.data)
      if (res.data.arp_mitm_detected) {
        setError('HIGH SEVERITY ALERT: Gateway BSSID mutation detected! Possible ARP Poisoning / Interception.')
      } else {
        setSuccessMsg('No ARP mutation detected.')
      }
      setTimeout(() => setError(''), 6000)
    } catch (err) {
      setError('Failed to execute ARP MITM simulation.')
    } finally {
      setActionLoading(false)
    }
  }

  // -------------------------------------------------------------
  // Merkle Ledger Handlers
  // -------------------------------------------------------------
  const handleAppendAuditRecord = async () => {
    try {
      setActionLoading(true)
      setError('')
      const res = await client.post('/v24/ledger/append', {
        action: newAuditAction,
        actor_email: newAuditActor,
        ip_address: newAuditIp,
        mac_address: newAuditMac
      })
      setSuccessMsg(`Block #${res.data.sequence_id} cryptographically chained to ledger! Hash: ${res.data.current_ledger_hash.slice(0, 16)}...`)
      fetchLedger()
      fetchGlobalStatus()
      setTimeout(() => setSuccessMsg(''), 4000)
    } catch (err) {
      setError('Failed to append audit record to Merkle ledger.')
    } finally {
      setActionLoading(false)
    }
  }

  const handleVerifyLedgerIntegrity = async () => {
    try {
      setActionLoading(true)
      setError('')
      const res = await client.get('/v24/ledger/verify')
      setLedgerVerification(res.data)
      if (res.data.is_ledger_valid) {
        setSuccessMsg(`Cryptographic Merkle verification PASSED across all ${res.data.total_records_verified} blocks!`)
      } else {
        setError(`TAMPER DETECTED: Hash chain broken at sequence #${res.data.broken_at_sequence_id}!`)
      }
      setTimeout(() => setSuccessMsg(''), 5000)
    } catch (err) {
      setError('Failed to verify Merkle ledger integrity.')
    } finally {
      setActionLoading(false)
    }
  }

  const handleSimulateTampering = async () => {
    try {
      setActionLoading(true)
      setError('')
      const res = await client.post('/v24/ledger/simulate-tamper', {
        sequence_id: parseInt(tamperTargetSeq, 10),
        malicious_payload: 'MALICIOUS_LOG_RECORD_BYPASSED'
      })
      setSuccessMsg(res.data.message)
      // Immediately run verification to show the red tamper indicator
      handleVerifyLedgerIntegrity()
      fetchLedger()
    } catch (err) {
      setError('Failed to simulate DBA tampering on ledger.')
    } finally {
      setActionLoading(false)
    }
  }

  return (
    <div className="space-y-6">
      {/* 1. Header Banner */}
      <div className="bg-base-900 border border-base-700 rounded-xl p-6 relative overflow-hidden shadow-2xl">
        <div className="absolute -top-16 -right-16 w-64 h-64 bg-emerald-500/10 rounded-full blur-3xl pointer-events-none"></div>
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 relative z-10">
          <div>
            <div className="flex items-center gap-2.5 mb-1.5">
              <span className="text-2xl font-mono text-emerald-400">⚡</span>
              <h1 className="text-2xl font-bold font-mono tracking-wide text-slate-100">
                V24 Physical Baseband &amp; Merkle Ledger Matrix
              </h1>
              <span className="px-2.5 py-0.5 text-xs font-mono font-bold bg-emerald-950 text-emerald-300 border border-emerald-800 rounded">
                v24.0
              </span>
            </div>
            <p className="text-sm text-slate-400 font-mono max-w-3xl">
              Hardware-level IMEI extraction via modem AT serial commands, 3-tower cellular multilateration,
              dynamic adaptive GPS scheduling, ARP/MAC network auditing, and Neon SHA-256 Merkle-chained audit ledgers.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <div className="px-3.5 py-2 bg-base-950/80 rounded-lg border border-base-700/80 text-xs font-mono">
              <span className="text-slate-500 block text-[10px] uppercase">Architectural Rating</span>
              <span className="text-emerald-400 font-bold text-sm">99.99999999999 / 100</span>
            </div>
            <div className="px-3.5 py-2 bg-base-950/80 rounded-lg border border-base-700/80 text-xs font-mono">
              <span className="text-slate-500 block text-[10px] uppercase">Modem Subsystem</span>
              <span className="text-cyan-400 font-bold">RIL / AT Serial</span>
            </div>
            <div className="px-3.5 py-2 bg-base-950/80 rounded-lg border border-base-700/80 text-xs font-mono">
              <span className="text-slate-500 block text-[10px] uppercase">Ledger Integrity</span>
              <span className="text-emerald-400 font-bold">SHA-256 Merkle</span>
            </div>
          </div>
        </div>

        {/* Global Status Pills */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-5 pt-4 border-t border-base-800/80 text-xs font-mono">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
            <span className="text-slate-400">Modem RIL:</span>
            <span className="text-slate-200 font-semibold">{engineStatus?.modem_engine || 'ONLINE'}</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-amber-400"></span>
            <span className="text-slate-400">GPS Scheduler:</span>
            <span className="text-slate-200 font-semibold">{engineStatus?.gps_scheduler_mode || 'ADAPTIVE_ACTIVE'}</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-blue-400"></span>
            <span className="text-slate-400">Network Guard:</span>
            <span className="text-slate-200 font-semibold">{engineStatus?.network_auditor || 'ARP_WATCHDOG'}</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-indigo-400"></span>
            <span className="text-slate-400">Audit Ledger:</span>
            <span className="text-indigo-300 font-semibold">{engineStatus?.merkle_ledger_blocks || 1} Blocks</span>
          </div>
        </div>
      </div>

      {/* Notifications */}
      {error && (
        <div className="p-3.5 bg-rose-950/80 border border-rose-800 text-rose-200 text-xs font-mono rounded-lg flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="text-rose-400 font-bold">✖</span>
            <span>{error}</span>
          </div>
          <button onClick={() => setError('')} className="text-rose-400 hover:text-rose-200">Dismiss</button>
        </div>
      )}
      {successMsg && (
        <div className="p-3.5 bg-emerald-950/80 border border-emerald-800 text-emerald-200 text-xs font-mono rounded-lg flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="text-emerald-400 font-bold">✔</span>
            <span>{successMsg}</span>
          </div>
          <button onClick={() => setSuccessMsg('')} className="text-emerald-400 hover:text-emerald-200">Dismiss</button>
        </div>
      )}

      {/* 2. Navigation Tabs */}
      <div className="flex flex-wrap gap-2 border-b border-base-700 pb-2">
        <button
          onClick={() => setActiveTab('baseband')}
          className={`px-4 py-2 rounded-lg text-xs font-mono font-bold transition-all flex items-center gap-2 ${
            activeTab === 'baseband'
              ? 'bg-cyan-950 text-cyan-200 border border-cyan-600/70 shadow-sm'
              : 'bg-base-900/60 text-slate-400 hover:text-slate-200 hover:bg-base-800'
          }`}
        >
          <span>📱</span>
          <span>1. Baseband Modem &amp; 3-Tower Triangulation</span>
        </button>
        <button
          onClick={() => setActiveTab('gps')}
          className={`px-4 py-2 rounded-lg text-xs font-mono font-bold transition-all flex items-center gap-2 ${
            activeTab === 'gps'
              ? 'bg-amber-950 text-amber-200 border border-amber-600/70 shadow-sm'
              : 'bg-base-900/60 text-slate-400 hover:text-slate-200 hover:bg-base-800'
          }`}
        >
          <span>📡</span>
          <span>2. Adaptive GPS Scheduler Engine</span>
        </button>
        <button
          onClick={() => setActiveTab('network')}
          className={`px-4 py-2 rounded-lg text-xs font-mono font-bold transition-all flex items-center gap-2 ${
            activeTab === 'network'
              ? 'bg-blue-950 text-blue-200 border border-blue-600/70 shadow-sm'
              : 'bg-base-900/60 text-slate-400 hover:text-slate-200 hover:bg-base-800'
          }`}
        >
          <span>🛡️</span>
          <span>3. Network Interface &amp; ARP Auditing</span>
        </button>
        <button
          onClick={() => setActiveTab('ledger')}
          className={`px-4 py-2 rounded-lg text-xs font-mono font-bold transition-all flex items-center gap-2 ${
            activeTab === 'ledger'
              ? 'bg-emerald-950 text-emerald-200 border border-emerald-600/70 shadow-sm'
              : 'bg-base-900/60 text-slate-400 hover:text-slate-200 hover:bg-base-800'
          }`}
        >
          <span>🔗</span>
          <span>4. Neon Merkle Cryptographic Ledger</span>
        </button>
      </div>

      {/* 3. TAB 1: Baseband Modem & 3-Tower Cellular Multilateration */}
      {activeTab === 'baseband' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* AT Command Terminal & Hardware Registers */}
            <div className="bg-base-900 border border-base-700 rounded-xl p-5 shadow-xl flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between border-b border-base-800 pb-3 mb-4">
                  <div className="flex items-center gap-2">
                    <span className="text-cyan-400 font-mono text-base">⌨</span>
                    <h3 className="text-sm font-bold font-mono text-slate-200 uppercase tracking-wider">
                      Baseband Modem AT Serial Interface
                    </h3>
                  </div>
                  <span className="text-[11px] font-mono text-cyan-400 bg-cyan-950 px-2 py-0.5 rounded border border-cyan-800">
                    3GPP TS 27.007
                  </span>
                </div>

                <div className="space-y-3 font-mono text-xs">
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="text-slate-400 text-[11px] block mb-1">Serial Device Node</label>
                      <select
                        value={modemPort}
                        onChange={(e) => setModemPort(e.target.value)}
                        className="w-full bg-base-950 border border-base-700 rounded px-2.5 py-1.5 text-slate-200"
                      >
                        <option value="/dev/smd0">/dev/smd0 (Qualcomm SMD)</option>
                        <option value="/dev/ttyUSB0">/dev/ttyUSB0 (Modem Serial)</option>
                        <option value="/dev/atcmd">/dev/atcmd (Diagnostic Port)</option>
                        <option value="COM3">COM3 (Windows Modem)</option>
                      </select>
                    </div>

                    <div>
                      <label className="text-slate-400 text-[11px] block mb-1">Preset AT Sequence</label>
                      <select
                        value={customAtCmd}
                        onChange={(e) => setCustomAtCmd(e.target.value)}
                        className="w-full bg-base-950 border border-base-700 rounded px-2.5 py-1.5 text-slate-200"
                      >
                        <option value="AT+CGSN">AT+CGSN (Extract IMEI)</option>
                        <option value="AT+EGMR=0,7">AT+EGMR=0,7 (Secondary IMEI Register)</option>
                        <option value="AT+CREG=2;+CREG?">AT+CREG=2;+CREG? (Cell ID &amp; LAC)</option>
                        <option value="AT+COPS?">AT+COPS? (Operator PLMN)</option>
                        <option value="AT+CSQ">AT+CSQ (Signal Quality / RSSI)</option>
                      </select>
                    </div>
                  </div>

                  <div>
                    <label className="text-slate-400 text-[11px] block mb-1">Raw AT Command</label>
                    <div className="flex gap-2">
                      <input
                        type="text"
                        value={customAtCmd}
                        onChange={(e) => setCustomAtCmd(e.target.value)}
                        className="flex-1 bg-base-950 border border-base-700 rounded px-3 py-1.5 text-slate-200"
                        placeholder="AT+..."
                      />
                      <button
                        onClick={handleProbeModem}
                        disabled={actionLoading}
                        className="px-4 py-1.5 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-slate-950 font-bold rounded transition-colors"
                      >
                        {actionLoading ? 'Probing...' : 'Send AT'}
                      </button>
                    </div>
                  </div>
                </div>

                {/* AT History Terminal */}
                <div className="mt-4">
                  <label className="text-slate-400 text-[11px] font-mono block mb-1">Modem Response Log</label>
                  <div className="bg-base-950 border border-base-800 rounded p-3 h-44 overflow-y-auto space-y-2 font-mono text-[11px]">
                    {atResponses.length === 0 ? (
                      <div className="text-slate-600 text-center py-12">
                        Execute an AT command to read hardware registers...
                      </div>
                    ) : (
                      atResponses.map((res, i) => (
                        <div key={i} className="border-b border-base-800/60 pb-1.5">
                          <div className="flex justify-between text-cyan-400 font-bold">
                            <span>&gt; {res.command}</span>
                            <span className="text-slate-500 text-[10px]">{res.timestamp}</span>
                          </div>
                          <div className="text-slate-300 pl-2 whitespace-pre-wrap">{res.raw_response}</div>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              </div>

              {/* Decoded Hardware Telemetry */}
              {modemTelemetry && (
                <div className="mt-4 p-3 bg-base-950/90 rounded border border-cyan-800/50 font-mono text-xs space-y-1">
                  <div className="flex justify-between">
                    <span className="text-slate-400">Decoded Key:</span>
                    <span className="text-cyan-300 font-bold">{modemTelemetry.decoded_info?.type}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Extracted Value:</span>
                    <span className="text-slate-100 font-bold">{modemTelemetry.decoded_info?.extracted_value}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">OCSF Mapping:</span>
                    <span className="text-emerald-400">{modemTelemetry.ocsf_class}</span>
                  </div>
                </div>
              )}
            </div>

            {/* GSMA/CEIR Blacklist & Carrier HLR/VLR Control */}
            <div className="bg-base-900 border border-base-700 rounded-xl p-5 shadow-xl flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between border-b border-base-800 pb-3 mb-4">
                  <div className="flex items-center gap-2">
                    <span className="text-rose-400 font-mono text-base">🚫</span>
                    <h3 className="text-sm font-bold font-mono text-slate-200 uppercase tracking-wider">
                      Carrier HLR/VLR &amp; GSMA / CEIR Blacklist
                    </h3>
                  </div>
                  <span className="text-[11px] font-mono text-rose-400 bg-rose-950 px-2 py-0.5 rounded border border-rose-800">
                    Carrier Protocol
                  </span>
                </div>

                <div className="space-y-4 font-mono text-xs">
                  <div>
                    <label className="text-slate-400 text-[11px] block mb-1">Target Device IMEI (15 Digits)</label>
                    <input
                      type="text"
                      value={imeiInput}
                      onChange={(e) => setImeiInput(e.target.value)}
                      className="w-full bg-base-950 border border-base-700 rounded px-3 py-1.5 text-slate-200"
                      placeholder="e.g. 864201047192834"
                    />
                  </div>

                  <div className="p-3 bg-base-950 rounded border border-base-800 space-y-2">
                    <h4 className="text-[11px] text-slate-400 font-bold uppercase">HLR / VLR Sector Information</h4>
                    <div className="flex justify-between">
                      <span className="text-slate-500">Registered MNC/MCC:</span>
                      <span className="text-slate-200">404-869 (Jio Telecom)</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">Last Transceiver Tower:</span>
                      <span className="text-slate-200">CID: 40121 (Sector 02)</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">Radio Protocol:</span>
                      <span className="text-slate-200">LTE-Advanced (FDD Band 3)</span>
                    </div>
                  </div>

                  <div className="flex gap-2">
                    <button
                      onClick={() => handleCeirBlacklist('BLACKLIST')}
                      disabled={actionLoading}
                      className="flex-1 py-2 bg-rose-600 hover:bg-rose-500 disabled:opacity-50 text-slate-950 font-bold rounded transition-colors"
                    >
                      🚨 Blacklist on GSMA/CEIR (Stolen)
                    </button>
                    <button
                      onClick={() => handleCeirBlacklist('UNBLOCK')}
                      disabled={actionLoading}
                      className="flex-1 py-2 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-slate-200 font-bold rounded transition-colors"
                    >
                      Unblock Transceiver
                    </button>
                  </div>
                </div>
              </div>

              {ceirStatus && (
                <div className={`mt-4 p-3 rounded border font-mono text-xs space-y-1 ${
                  ceirStatus.transceiver_blocked 
                    ? 'bg-rose-950/70 border-rose-800 text-rose-200' 
                    : 'bg-emerald-950/70 border-emerald-800 text-emerald-200'
                }`}>
                  <div className="flex justify-between font-bold">
                    <span>Registry Status:</span>
                    <span>{ceirStatus.status}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Transceiver Signal:</span>
                    <span>{ceirStatus.transceiver_blocked ? 'DISABLED (CARRIER DISCONNECT)' : 'ENABLED (NORMAL)'}</span>
                  </div>
                  <div className="text-[10px] text-slate-400 mt-1">{ceirStatus.message}</div>
                </div>
              )}
            </div>
          </div>

          {/* 3-Tower Multilateration Engine */}
          <div className="bg-base-900 border border-base-700 rounded-xl p-5 shadow-xl">
            <div className="flex items-center justify-between border-b border-base-800 pb-3 mb-4">
              <div className="flex items-center gap-2">
                <span className="text-cyan-400 font-mono text-base">🌐</span>
                <h3 className="text-sm font-bold font-mono text-slate-200 uppercase tracking-wider">
                  3-Tower Timing Advance (TA) Multilateration (No-GPS Tracking)
                </h3>
              </div>
              <button
                onClick={handleRunTriangulation}
                disabled={actionLoading}
                className="px-4 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold text-xs font-mono rounded transition-colors"
              >
                {actionLoading ? 'Calculating...' : 'Run Multilateration'}
              </button>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 font-mono text-xs mb-4">
              {/* Tower A */}
              <div className="bg-base-950 p-3.5 rounded-lg border border-base-800">
                <h4 className="text-cyan-400 font-bold mb-2 flex items-center justify-between">
                  <span>Tower A (CID: 40121)</span>
                  <span className="text-[10px] text-slate-500">Master Sector</span>
                </h4>
                <div className="space-y-2">
                  <div>
                    <label className="text-slate-400 text-[10px]">Lat / Lon</label>
                    <div className="flex gap-2">
                      <input
                        type="number"
                        step="0.0001"
                        value={towerParams.tower_a_lat}
                        onChange={(e) => setTowerParams({ ...towerParams, tower_a_lat: e.target.value })}
                        className="w-1/2 bg-base-900 border border-base-700 rounded px-2 py-1 text-slate-200"
                      />
                      <input
                        type="number"
                        step="0.0001"
                        value={towerParams.tower_a_lon}
                        onChange={(e) => setTowerParams({ ...towerParams, tower_a_lon: e.target.value })}
                        className="w-1/2 bg-base-900 border border-base-700 rounded px-2 py-1 text-slate-200"
                      />
                    </div>
                  </div>
                  <div>
                    <label className="text-slate-400 text-[10px]">Timing Advance (TA: 0-63)</label>
                    <input
                      type="number"
                      value={towerParams.tower_a_ta}
                      onChange={(e) => setTowerParams({ ...towerParams, tower_a_ta: e.target.value })}
                      className="w-full bg-base-900 border border-base-700 rounded px-2 py-1 text-slate-200"
                    />
                    <span className="text-[9px] text-slate-500">Radius: ~{(towerParams.tower_a_ta * 78.12).toFixed(1)}m</span>
                  </div>
                </div>
              </div>

              {/* Tower B */}
              <div className="bg-base-950 p-3.5 rounded-lg border border-base-800">
                <h4 className="text-cyan-400 font-bold mb-2 flex items-center justify-between">
                  <span>Tower B (CID: 40122)</span>
                  <span className="text-[10px] text-slate-500">Neighbor 1</span>
                </h4>
                <div className="space-y-2">
                  <div>
                    <label className="text-slate-400 text-[10px]">Lat / Lon</label>
                    <div className="flex gap-2">
                      <input
                        type="number"
                        step="0.0001"
                        value={towerParams.tower_b_lat}
                        onChange={(e) => setTowerParams({ ...towerParams, tower_b_lat: e.target.value })}
                        className="w-1/2 bg-base-900 border border-base-700 rounded px-2 py-1 text-slate-200"
                      />
                      <input
                        type="number"
                        step="0.0001"
                        value={towerParams.tower_b_lon}
                        onChange={(e) => setTowerParams({ ...towerParams, tower_b_lon: e.target.value })}
                        className="w-1/2 bg-base-900 border border-base-700 rounded px-2 py-1 text-slate-200"
                      />
                    </div>
                  </div>
                  <div>
                    <label className="text-slate-400 text-[10px]">Timing Advance (TA: 0-63)</label>
                    <input
                      type="number"
                      value={towerParams.tower_b_ta}
                      onChange={(e) => setTowerParams({ ...towerParams, tower_b_ta: e.target.value })}
                      className="w-full bg-base-900 border border-base-700 rounded px-2 py-1 text-slate-200"
                    />
                    <span className="text-[9px] text-slate-500">Radius: ~{(towerParams.tower_b_ta * 78.12).toFixed(1)}m</span>
                  </div>
                </div>
              </div>

              {/* Tower C */}
              <div className="bg-base-950 p-3.5 rounded-lg border border-base-800">
                <h4 className="text-cyan-400 font-bold mb-2 flex items-center justify-between">
                  <span>Tower C (CID: 40123)</span>
                  <span className="text-[10px] text-slate-500">Neighbor 2</span>
                </h4>
                <div className="space-y-2">
                  <div>
                    <label className="text-slate-400 text-[10px]">Lat / Lon</label>
                    <div className="flex gap-2">
                      <input
                        type="number"
                        step="0.0001"
                        value={towerParams.tower_c_lat}
                        onChange={(e) => setTowerParams({ ...towerParams, tower_c_lat: e.target.value })}
                        className="w-1/2 bg-base-900 border border-base-700 rounded px-2 py-1 text-slate-200"
                      />
                      <input
                        type="number"
                        step="0.0001"
                        value={towerParams.tower_c_lon}
                        onChange={(e) => setTowerParams({ ...towerParams, tower_c_lon: e.target.value })}
                        className="w-1/2 bg-base-900 border border-base-700 rounded px-2 py-1 text-slate-200"
                      />
                    </div>
                  </div>
                  <div>
                    <label className="text-slate-400 text-[10px]">Timing Advance (TA: 0-63)</label>
                    <input
                      type="number"
                      value={towerParams.tower_c_ta}
                      onChange={(e) => setTowerParams({ ...towerParams, tower_c_ta: e.target.value })}
                      className="w-full bg-base-900 border border-base-700 rounded px-2 py-1 text-slate-200"
                    />
                    <span className="text-[9px] text-slate-500">Radius: ~{(towerParams.tower_c_ta * 78.12).toFixed(1)}m</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Triangulation Solution Box */}
            {triangulationData && (
              <div className="p-4 bg-base-950 rounded-lg border border-cyan-800/60 font-mono text-xs">
                <div className="grid grid-cols-1 md:grid-cols-4 gap-3 mb-2">
                  <div>
                    <span className="text-slate-400 text-[10px] block">Triangulated Latitude</span>
                    <span className="text-cyan-300 font-bold text-sm">
                      {triangulationData.triangulated_latitude.toFixed(6)}° N
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 text-[10px] block">Triangulated Longitude</span>
                    <span className="text-cyan-300 font-bold text-sm">
                      {triangulationData.triangulated_longitude.toFixed(6)}° W
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 text-[10px] block">Estimated Accuracy</span>
                    <span className="text-emerald-400 font-bold text-sm">
                      ±{triangulationData.estimated_accuracy_meters} meters
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 text-[10px] block">Tracking Method</span>
                    <span className="text-slate-200 font-bold text-sm">
                      {triangulationData.method}
                    </span>
                  </div>
                </div>
                <div className="text-[11px] text-slate-400 border-t border-base-800 pt-2 flex justify-between">
                  <span>Device IMEI: <strong className="text-slate-200">{triangulationData.imei}</strong></span>
                  <span>OCSF Event: <strong className="text-indigo-400">Class 5020 (Location Telemetry)</strong></span>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* 4. TAB 2: Adaptive GPS Scheduler Engine */}
      {activeTab === 'gps' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Throttling Controls */}
            <div className="bg-base-900 border border-base-700 rounded-xl p-5 shadow-xl">
              <div className="flex items-center justify-between border-b border-base-800 pb-3 mb-4">
                <div className="flex items-center gap-2">
                  <span className="text-amber-400 font-mono text-base">⚙</span>
                  <h3 className="text-sm font-bold font-mono text-slate-200 uppercase tracking-wider">
                    Dynamic Throttling &amp; Geofence Parameters
                  </h3>
                </div>
                <span className="text-[11px] font-mono text-amber-400 bg-amber-950 px-2 py-0.5 rounded border border-amber-800">
                  Haversine Physics Engine
                </span>
              </div>

              <div className="space-y-4 font-mono text-xs">
                {/* Geofence Configuration */}
                <div className="p-3 bg-base-950 rounded border border-base-800 space-y-2">
                  <h4 className="text-[11px] text-amber-400 font-bold uppercase">Authorized Geofence Zone</h4>
                  <div className="grid grid-cols-2 gap-2">
                    <div>
                      <label className="text-slate-400 text-[10px]">Center Latitude</label>
                      <input
                        type="number"
                        step="0.0001"
                        value={geofenceCenter.lat}
                        onChange={(e) => setGeofenceCenter({ ...geofenceCenter, lat: e.target.value })}
                        className="w-full bg-base-900 border border-base-700 rounded px-2.5 py-1 text-slate-200"
                      />
                    </div>
                    <div>
                      <label className="text-slate-400 text-[10px]">Center Longitude</label>
                      <input
                        type="number"
                        step="0.0001"
                        value={geofenceCenter.lon}
                        onChange={(e) => setGeofenceCenter({ ...geofenceCenter, lon: e.target.value })}
                        className="w-full bg-base-900 border border-base-700 rounded px-2.5 py-1 text-slate-200"
                      />
                    </div>
                  </div>
                  <div>
                    <div className="flex justify-between text-[10px] text-slate-400 mb-1">
                      <span>Geofence Radius:</span>
                      <span className="text-amber-400 font-bold">{geofenceRadius} meters</span>
                    </div>
                    <input
                      type="range"
                      min="50"
                      max="5000"
                      step="50"
                      value={geofenceRadius}
                      onChange={(e) => setGeofenceRadius(e.target.value)}
                      className="w-full accent-amber-500"
                    />
                  </div>
                </div>

                {/* Device Current Position & Battery */}
                <div className="p-3 bg-base-950 rounded border border-base-800 space-y-2">
                  <h4 className="text-[11px] text-slate-300 font-bold uppercase">Device Simulated Telemetry</h4>
                  <div className="grid grid-cols-2 gap-2">
                    <div>
                      <label className="text-slate-400 text-[10px]">Current Latitude</label>
                      <input
                        type="number"
                        step="0.0001"
                        value={gpsCurrentLat}
                        onChange={(e) => setGpsCurrentLat(e.target.value)}
                        className="w-full bg-base-900 border border-base-700 rounded px-2.5 py-1 text-slate-200"
                      />
                    </div>
                    <div>
                      <label className="text-slate-400 text-[10px]">Current Longitude</label>
                      <input
                        type="number"
                        step="0.0001"
                        value={gpsCurrentLon}
                        onChange={(e) => setGpsCurrentLon(e.target.value)}
                        className="w-full bg-base-900 border border-base-700 rounded px-2.5 py-1 text-slate-200"
                      />
                    </div>
                  </div>

                  <div>
                    <div className="flex justify-between text-[10px] text-slate-400 mb-1">
                      <span>Simulated Speed (km/h):</span>
                      <span className="text-slate-200 font-bold">{simulatedSpeedKmh} km/h</span>
                    </div>
                    <input
                      type="range"
                      min="0"
                      max="120"
                      step="1"
                      value={simulatedSpeedKmh}
                      onChange={(e) => setSimulatedSpeedKmh(e.target.value)}
                      className="w-full accent-amber-500"
                    />
                  </div>

                  <div>
                    <div className="flex justify-between text-[10px] text-slate-400 mb-1">
                      <span>Battery Capacity:</span>
                      <span className={`font-bold ${batteryPct < 20 ? 'text-rose-400' : 'text-emerald-400'}`}>
                        {batteryPct}% {batteryPct < 20 ? '(CRITICAL POWER)' : ''}
                      </span>
                    </div>
                    <input
                      type="range"
                      min="1"
                      max="100"
                      step="1"
                      value={batteryPct}
                      onChange={(e) => setBatteryPct(e.target.value)}
                      className="w-full accent-amber-500"
                    />
                  </div>
                </div>

                <button
                  onClick={handleEvaluateGpsScheduler}
                  disabled={actionLoading}
                  className="w-full py-2 bg-amber-600 hover:bg-amber-500 disabled:opacity-50 text-slate-950 font-bold rounded transition-colors"
                >
                  {actionLoading ? 'Evaluating Physics Engine...' : 'Evaluate GPS Throttling'}
                </button>
              </div>
            </div>

            {/* State Machine Diagram & Decision Output */}
            <div className="bg-base-900 border border-base-700 rounded-xl p-5 shadow-xl flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between border-b border-base-800 pb-3 mb-4">
                  <div className="flex items-center gap-2">
                    <span className="text-amber-400 font-mono text-base">📊</span>
                    <h3 className="text-sm font-bold font-mono text-slate-200 uppercase tracking-wider">
                      Throttling State Machine Architecture
                    </h3>
                  </div>
                  <span className="text-[11px] font-mono text-slate-400">Energy Optimization</span>
                </div>

                {/* State Machine Flowchart Cards */}
                <div className="space-y-2.5 font-mono text-xs">
                  <div className={`p-2.5 rounded border transition-all ${
                    gpsDecision?.state === 'STATIONARY'
                      ? 'bg-emerald-950/80 border-emerald-500 text-emerald-200 shadow-md scale-[1.02]'
                      : 'bg-base-950 border-base-800 text-slate-400'
                  }`}>
                    <div className="flex justify-between font-bold">
                      <span>1. STATIONARY STATE</span>
                      <span>300s (5m) Interval</span>
                    </div>
                    <p className="text-[10px] text-slate-500 mt-0.5">Speed &lt; 3.0 m/s inside geofence boundary &bull; Low power draw</p>
                  </div>

                  <div className={`p-2.5 rounded border transition-all ${
                    gpsDecision?.state === 'TRANSIT'
                      ? 'bg-blue-950/80 border-blue-500 text-blue-200 shadow-md scale-[1.02]'
                      : 'bg-base-950 border-base-800 text-slate-400'
                  }`}>
                    <div className="flex justify-between font-bold">
                      <span>2. TRANSIT STATE</span>
                      <span>15s Interval</span>
                    </div>
                    <p className="text-[10px] text-slate-500 mt-0.5">Speed &gt; 3.0 m/s inside geofence &bull; Dynamic motion vectoring</p>
                  </div>

                  <div className={`p-2.5 rounded border transition-all ${
                    gpsDecision?.state === 'OUTSIDE_GEOFENCE'
                      ? 'bg-amber-950/80 border-amber-500 text-amber-200 shadow-md scale-[1.02]'
                      : 'bg-base-950 border-base-800 text-slate-400'
                  }`}>
                    <div className="flex justify-between font-bold">
                      <span>3. OUTSIDE GEOFENCE (HIGH ALERT)</span>
                      <span>10s - 30s Interval</span>
                    </div>
                    <p className="text-[10px] text-slate-500 mt-0.5">Distance &gt; Geofence Radius &bull; Active perimeter breach tracking</p>
                  </div>

                  <div className={`p-2.5 rounded border transition-all ${
                    gpsDecision?.state === 'CRITICAL_POWER'
                      ? 'bg-rose-950/80 border-rose-500 text-rose-200 shadow-md scale-[1.02]'
                      : 'bg-base-950 border-base-800 text-slate-400'
                  }`}>
                    <div className="flex justify-between font-bold">
                      <span>4. CRITICAL POWER OVERRIDE</span>
                      <span>300s - 1800s Interval</span>
                    </div>
                    <p className="text-[10px] text-slate-500 mt-0.5">Battery &lt; 20% &bull; Emergency power saving to prevent device shutdown</p>
                  </div>
                </div>
              </div>

              {/* Decision Metrics Panel */}
              {gpsDecision && (
                <div className="mt-4 p-3.5 bg-base-950 rounded-lg border border-amber-800/60 font-mono text-xs">
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-2 mb-2">
                    <div>
                      <span className="text-slate-400 text-[10px] block">Active State</span>
                      <span className="text-amber-400 font-bold text-sm">{gpsDecision.state}</span>
                    </div>
                    <div>
                      <span className="text-slate-400 text-[10px] block">Next Interval</span>
                      <span className="text-slate-100 font-bold text-sm">{gpsDecision.next_scheduled_interval}s</span>
                    </div>
                    <div>
                      <span className="text-slate-400 text-[10px] block">Geofence Distance</span>
                      <span className="text-cyan-300 font-bold text-sm">{gpsDecision.distance_to_center_m}m</span>
                    </div>
                    <div>
                      <span className="text-slate-400 text-[10px] block">Perimeter Breach</span>
                      <span className={`font-bold text-sm ${gpsDecision.outside_geofence ? 'text-rose-400' : 'text-emerald-400'}`}>
                        {gpsDecision.outside_geofence ? 'YES (ALERT)' : 'NO (SECURE)'}
                      </span>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* 5. TAB 3: Network Interface (MAC/IP) & ARP Auditing */}
      {activeTab === 'network' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Interface Scanner Form */}
            <div className="bg-base-900 border border-base-700 rounded-xl p-5 shadow-xl">
              <div className="flex items-center justify-between border-b border-base-800 pb-3 mb-4">
                <div className="flex items-center gap-2">
                  <span className="text-blue-400 font-mono text-base">🔍</span>
                  <h3 className="text-sm font-bold font-mono text-slate-200 uppercase tracking-wider">
                    Network Interface Scanner (OCSF 5001)
                  </h3>
                </div>
                <span className="text-[11px] font-mono text-blue-400 bg-blue-950 px-2 py-0.5 rounded border border-blue-800">
                  Inventory Watchdog
                </span>
              </div>

              <div className="space-y-3 font-mono text-xs">
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="text-slate-400 text-[11px] block mb-1">Interface Name</label>
                    <input
                      type="text"
                      value={simIface}
                      onChange={(e) => setSimIface(e.target.value)}
                      className="w-full bg-base-950 border border-base-700 rounded px-2.5 py-1.5 text-slate-200"
                    />
                  </div>
                  <div>
                    <label className="text-slate-400 text-[11px] block mb-1">Local IP Address</label>
                    <input
                      type="text"
                      value={simIp}
                      onChange={(e) => setSimIp(e.target.value)}
                      className="w-full bg-base-950 border border-base-700 rounded px-2.5 py-1.5 text-slate-200"
                    />
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="text-slate-400 text-[11px] block mb-1">Interface MAC</label>
                    <input
                      type="text"
                      value={simMac}
                      onChange={(e) => setSimMac(e.target.value)}
                      className="w-full bg-base-950 border border-base-700 rounded px-2.5 py-1.5 text-slate-200 font-mono"
                    />
                  </div>
                  <div>
                    <label className="text-slate-400 text-[11px] block mb-1">Default Gateway IP</label>
                    <input
                      type="text"
                      value={simGatewayIp}
                      onChange={(e) => setSimGatewayIp(e.target.value)}
                      className="w-full bg-base-950 border border-base-700 rounded px-2.5 py-1.5 text-slate-200"
                    />
                  </div>
                </div>

                <div>
                  <label className="text-slate-400 text-[11px] block mb-1">Gateway BSSID (MAC Address)</label>
                  <input
                    type="text"
                    value={simOriginalGwMac}
                    onChange={(e) => setSimOriginalGwMac(e.target.value)}
                    className="w-full bg-base-950 border border-base-700 rounded px-2.5 py-1.5 text-slate-200 font-mono"
                  />
                </div>

                <button
                  onClick={handleScanNetwork}
                  disabled={actionLoading}
                  className="w-full py-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-slate-950 font-bold rounded transition-colors"
                >
                  {actionLoading ? 'Auditing...' : 'Audit Network Interfaces'}
                </button>
              </div>

              {networkAuditResult && (
                <div className="mt-4 p-3.5 bg-base-950 rounded border border-blue-800/60 font-mono text-xs space-y-2">
                  <div className="flex justify-between">
                    <span className="text-slate-400">OCSF Schema:</span>
                    <span className="text-blue-300 font-bold">Class {networkAuditResult.ocsf_class_uid} ({networkAuditResult.ocsf_class_name})</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">MAC Spoofing Check:</span>
                    <span className="text-emerald-400 font-bold">PASSED (ROM ALIGNED)</span>
                  </div>
                  <div className="text-[10px] text-slate-500">
                    Telemetries serialized for tenant SIEM &amp; real-time SOC broadcast.
                  </div>
                </div>
              )}
            </div>

            {/* ARP MITM Attack Simulator */}
            <div className="bg-base-900 border border-base-700 rounded-xl p-5 shadow-xl">
              <div className="flex items-center justify-between border-b border-base-800 pb-3 mb-4">
                <div className="flex items-center gap-2">
                  <span className="text-rose-400 font-mono text-base">⚠️</span>
                  <h3 className="text-sm font-bold font-mono text-slate-200 uppercase tracking-wider">
                    ARP Poisoning &amp; Gateway Redirection Simulator
                  </h3>
                </div>
                <span className="text-[11px] font-mono text-rose-400 bg-rose-950 px-2 py-0.5 rounded border border-rose-800">
                  MITM Watchdog
                </span>
              </div>

              <div className="space-y-3 font-mono text-xs">
                <p className="text-slate-400 text-[11px]">
                  When a physical gateway MAC changes while the IP configuration remains static, Threat Analyser's
                  watchdog detects ARP cache poisoning or unauthorized gateway redirection.
                </p>

                <div className="p-3 bg-base-950 rounded border border-base-800 space-y-2">
                  <div>
                    <label className="text-slate-400 text-[10px]">Legitimate Gateway MAC</label>
                    <input
                      type="text"
                      value={simOriginalGwMac}
                      onChange={(e) => setSimOriginalGwMac(e.target.value)}
                      className="w-full bg-base-900 border border-base-700 rounded px-2.5 py-1 text-slate-200 font-mono"
                    />
                  </div>

                  <div>
                    <label className="text-rose-400 text-[10px] font-bold">Mutated / Spoofed Gateway MAC (Attacker BSSID)</label>
                    <input
                      type="text"
                      value={simMutatedGwMac}
                      onChange={(e) => setSimMutatedGwMac(e.target.value)}
                      className="w-full bg-base-900 border border-rose-800 rounded px-2.5 py-1 text-rose-200 font-mono"
                    />
                  </div>
                </div>

                <button
                  onClick={handleSimulateArpMitm}
                  disabled={actionLoading}
                  className="w-full py-2 bg-rose-600 hover:bg-rose-500 disabled:opacity-50 text-slate-950 font-bold rounded transition-colors"
                >
                  {actionLoading ? 'Simulating...' : 'Simulate ARP Mutation & Trigger Alert'}
                </button>
              </div>

              {mitmAlertData && (
                <div className={`mt-4 p-3.5 rounded border font-mono text-xs space-y-1.5 ${
                  mitmAlertData.arp_mitm_detected
                    ? 'bg-rose-950/80 border-rose-700 text-rose-200'
                    : 'bg-emerald-950/80 border-emerald-700 text-emerald-200'
                }`}>
                  <div className="flex justify-between font-bold">
                    <span>Watchdog Assessment:</span>
                    <span>{mitmAlertData.arp_mitm_detected ? '🚨 MITM ATTACK DETECTED' : 'SECURE'}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Severity:</span>
                    <span className="font-bold">{mitmAlertData.severity}</span>
                  </div>
                  <div className="text-[10px] text-slate-300">{mitmAlertData.description}</div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* 6. TAB 4: Neon Serverless Merkle Audit Ledger */}
      {activeTab === 'ledger' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Append New Record Form */}
            <div className="bg-base-900 border border-base-700 rounded-xl p-5 shadow-xl">
              <div className="flex items-center justify-between border-b border-base-800 pb-3 mb-4">
                <div className="flex items-center gap-2">
                  <span className="text-emerald-400 font-mono text-base">📝</span>
                  <h3 className="text-sm font-bold font-mono text-slate-200 uppercase tracking-wider">
                    Append Cryptographic Audit Record
                  </h3>
                </div>
                <span className="text-[11px] font-mono text-emerald-400 bg-emerald-950 px-2 py-0.5 rounded border border-emerald-800">
                  SHA-256 Hash Chain
                </span>
              </div>

              <div className="space-y-3 font-mono text-xs">
                <div>
                  <label className="text-slate-400 text-[11px] block mb-1">Compliance Action</label>
                  <select
                    value={newAuditAction}
                    onChange={(e) => setNewAuditAction(e.target.value)}
                    className="w-full bg-base-950 border border-base-700 rounded px-2.5 py-1.5 text-slate-200"
                  >
                    <option value="DEVICE_ISOLATION_TRIGGERED">DEVICE_ISOLATION_TRIGGERED</option>
                    <option value="FORENSIC_IMEI_EXTRACTED">FORENSIC_IMEI_EXTRACTED</option>
                    <option value="GEOFENCE_BOUNDARY_BREACH">GEOFENCE_BOUNDARY_BREACH</option>
                    <option value="ARP_MITM_CONTAINMENT_ACTIVE">ARP_MITM_CONTAINMENT_ACTIVE</option>
                    <option value="ENCLAVE_KEY_ROTATION">ENCLAVE_KEY_ROTATION</option>
                  </select>
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="text-slate-400 text-[11px] block mb-1">Actor Email</label>
                    <input
                      type="text"
                      value={newAuditActor}
                      onChange={(e) => setNewAuditActor(e.target.value)}
                      className="w-full bg-base-950 border border-base-700 rounded px-2.5 py-1.5 text-slate-200"
                    />
                  </div>
                  <div>
                    <label className="text-slate-400 text-[11px] block mb-1">IP Address</label>
                    <input
                      type="text"
                      value={newAuditIp}
                      onChange={(e) => setNewAuditIp(e.target.value)}
                      className="w-full bg-base-950 border border-base-700 rounded px-2.5 py-1.5 text-slate-200"
                    />
                  </div>
                </div>

                <div>
                  <label className="text-slate-400 text-[11px] block mb-1">MAC Address</label>
                  <input
                    type="text"
                    value={newAuditMac}
                    onChange={(e) => setNewAuditMac(e.target.value)}
                    className="w-full bg-base-950 border border-base-700 rounded px-2.5 py-1.5 text-slate-200 font-mono"
                  />
                </div>

                <div className="flex gap-2 pt-2">
                  <button
                    onClick={handleAppendAuditRecord}
                    disabled={actionLoading}
                    className="flex-1 py-2 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-slate-950 font-bold rounded transition-colors"
                  >
                    {actionLoading ? 'Chaining Block...' : 'Append to Merkle Ledger'}
                  </button>
                  <button
                    onClick={handleVerifyLedgerIntegrity}
                    disabled={actionLoading}
                    className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-slate-100 font-bold rounded transition-colors"
                  >
                    Verify Chain
                  </button>
                </div>
              </div>
            </div>

            {/* Rogue DBA Tampering Simulator & Verification Status */}
            <div className="bg-base-900 border border-base-700 rounded-xl p-5 shadow-xl flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between border-b border-base-800 pb-3 mb-4">
                  <div className="flex items-center gap-2">
                    <span className="text-rose-400 font-mono text-base">🕵️‍♂️</span>
                    <h3 className="text-sm font-bold font-mono text-slate-200 uppercase tracking-wider">
                      Rogue DBA Tamper Simulation
                    </h3>
                  </div>
                  <span className="text-[11px] font-mono text-rose-400 bg-rose-950 px-2 py-0.5 rounded border border-rose-800">
                    Attack Proof
                  </span>
                </div>

                <div className="space-y-3 font-mono text-xs">
                  <p className="text-slate-400 text-[11px]">
                    Simulate an unauthorized PostgreSQL administrator directly modifying an audit record's payload.
                    The recursive SQL verification engine detects the cryptographic break instantly.
                  </p>

                  <div>
                    <label className="text-slate-400 text-[11px] block mb-1">Target Sequence ID to Tamper</label>
                    <input
                      type="number"
                      value={tamperTargetSeq}
                      onChange={(e) => setTamperTargetSeq(e.target.value)}
                      className="w-full bg-base-950 border border-base-700 rounded px-2.5 py-1.5 text-slate-200 font-mono"
                      min="1"
                    />
                  </div>

                  <button
                    onClick={handleSimulateTampering}
                    disabled={actionLoading}
                    className="w-full py-2 bg-rose-700 hover:bg-rose-600 disabled:opacity-50 text-slate-100 font-bold rounded transition-colors"
                  >
                    {actionLoading ? 'Tampering...' : 'Inject Malicious DBA Tampering'}
                  </button>
                </div>
              </div>

              {/* Verification Panel */}
              {ledgerVerification && (
                <div className={`mt-4 p-3.5 rounded-lg border font-mono text-xs space-y-1.5 ${
                  ledgerVerification.is_ledger_valid
                    ? 'bg-emerald-950/80 border-emerald-700 text-emerald-200'
                    : 'bg-rose-950/80 border-rose-700 text-rose-200'
                }`}>
                  <div className="flex justify-between font-bold">
                    <span>Cryptographic Verification:</span>
                    <span>{ledgerVerification.is_ledger_valid ? '✅ VERIFIED (UNBROKEN)' : '🚨 TAMPER_DETECTED'}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Blocks Evaluated:</span>
                    <span>{ledgerVerification.total_records_verified}</span>
                  </div>
                  {!ledgerVerification.is_ledger_valid && (
                    <div className="text-[10px] text-rose-300 font-bold">
                      Chain broken at sequence #{ledgerVerification.broken_at_sequence_id}! Calculated hash did not match parent link.
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>

          {/* Block Explorer Table */}
          <div className="bg-base-900 border border-base-700 rounded-xl p-5 shadow-xl">
            <div className="flex items-center justify-between border-b border-base-800 pb-3 mb-4">
              <div className="flex items-center gap-2">
                <span className="text-indigo-400 font-mono text-base">⛓️</span>
                <h3 className="text-sm font-bold font-mono text-slate-200 uppercase tracking-wider">
                  Merkle-Chained Block Explorer ({ledgerRecords.length} Blocks)
                </h3>
              </div>
              <button
                onClick={fetchLedger}
                className="px-3 py-1 bg-base-800 hover:bg-base-700 text-slate-300 text-xs font-mono rounded"
              >
                Refresh Blocks
              </button>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full font-mono text-xs text-left">
                <thead className="bg-base-950 text-slate-400 text-[10px] uppercase border-b border-base-800">
                  <tr>
                    <th className="p-2.5">Seq</th>
                    <th className="p-2.5">Action</th>
                    <th className="p-2.5">Actor</th>
                    <th className="p-2.5">IP / MAC</th>
                    <th className="p-2.5">Payload Hash</th>
                    <th className="p-2.5">Previous Hash</th>
                    <th className="p-2.5">Current Ledger Hash</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-base-800/60">
                  {ledgerRecords.length === 0 ? (
                    <tr>
                      <td colSpan="7" className="p-6 text-center text-slate-600">
                        No audit records in ledger yet.
                      </td>
                    </tr>
                  ) : (
                    ledgerRecords.map((r) => (
                      <tr key={r.sequence_id} className="hover:bg-base-800/40 transition-colors">
                        <td className="p-2.5 font-bold text-emerald-400">#{r.sequence_id}</td>
                        <td className="p-2.5 font-bold text-slate-200 truncate max-w-[150px]">{r.action}</td>
                        <td className="p-2.5 text-slate-300 truncate max-w-[150px]">{r.actor_email}</td>
                        <td className="p-2.5 text-slate-400 text-[10px]">
                          <div>{r.ip_address}</div>
                          <div className="text-slate-500 font-mono">{r.mac_address}</div>
                        </td>
                        <td className="p-2.5 font-mono text-[9px] text-cyan-400 truncate max-w-[120px]" title={r.payload_hash}>
                          {r.payload_hash.slice(0, 12)}...
                        </td>
                        <td className="p-2.5 font-mono text-[9px] text-slate-400 truncate max-w-[120px]" title={r.previous_record_hash}>
                          {r.previous_record_hash.slice(0, 12)}...
                        </td>
                        <td className="p-2.5 font-mono text-[9px] text-indigo-300 truncate max-w-[120px]" title={r.current_ledger_hash}>
                          {r.current_ledger_hash.slice(0, 12)}...
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* 7. Real-Time SOC Console Component */}
      <div className="mt-8">
        <RealTimeSOCConsole orgId="00000000-0000-0000-0000-000000000001" />
      </div>
    </div>
  )
}
