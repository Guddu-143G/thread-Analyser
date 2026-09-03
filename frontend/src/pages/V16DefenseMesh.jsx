import React, { useState, useEffect, useRef } from 'react'
import client from '../api/client'
import { useAuth } from '../context/AuthContext'

export default function V16DefenseMesh() {
  const { user } = useAuth()
  const token = localStorage.getItem('ta_token') || localStorage.getItem('token')

  const [activeTab, setActiveTab] = useState('geo') // geo | email | url | ws
  const [feedback, setFeedback] = useState(null)
  const [stats, setStats] = useState(null)

  // 1. Geo & Heartbeat State
  const [geoFleet, setGeoFleet] = useState([])
  const [impossibleAlerts, setImpossibleAlerts] = useState([])
  const [loadingFleet, setLoadingFleet] = useState(false)
  const [hbDeviceUid, setHbDeviceUid] = useState('dev_win_laptop_89a')
  const [hbHostname, setHbHostname] = useState('win-laptop-89a')
  const [hbPublicIp, setHbPublicIp] = useState('185.190.140.2')
  const [hbCpuLoad, setHbCpuLoad] = useState(24.5)
  const [hbMemMb, setHbMemMb] = useState(5120.0)
  const [lastHeartbeatRes, setLastHeartbeatRes] = useState(null)
  const [simulatingTravel, setSimulatingTravel] = useState(false)

  // 2. Email Guard State
  const [emailInputMode, setEmailInputMode] = useState('text') // text | eml
  const [emailFrom, setEmailFrom] = useState('"CEO John Doe" <urgent-payroll@support-update-corp.xyz>')
  const [emailTo, setEmailTo] = useState('accounting@corp.internal')
  const [emailSubject, setEmailSubject] = useState('URGENT ACTION: Immediate Wire Transfer Confirmation')
  const [emailBody, setEmailBody] = useState(`Dear Finance Team,\n\nPlease execute an urgent wire transfer of $85,000 for invoice attached.\nClick here to verify password and confirm routing details immediately:\nhttps://verify-office365-security.com/login.php\n\nRegards,\nExecutive Office`)
  const [emailSenderIp, setEmailSenderIp] = useState('185.220.101.5')
  const [rawEmlText, setRawEmlText] = useState('')
  const [emailScanResult, setEmailScanResult] = useState(null)
  const [emailAudits, setEmailAudits] = useState([])
  const [scanningEmail, setScanningEmail] = useState(false)

  // 3. URL Sandbox State
  const [urlInput, setUrlInput] = useState('https://verify-office365-security.com/verify-login?session=active')
  const [forceSandbox, setForceSandbox] = useState(true)
  const [urlScanResult, setUrlScanResult] = useState(null)
  const [urlHistory, setUrlHistory] = useState([])
  const [scanningUrl, setScanningUrl] = useState(false)

  // 4. WebSocket Stream State
  const [wsLogs, setWsLogs] = useState([])
  const [wsConnected, setWsConnected] = useState(false)
  const [wsPaused, setWsPaused] = useState(false)
  const [selectedWsEvent, setSelectedWsEvent] = useState(null)
  const wsRef = useRef(null)

  // Fetch initial data
  const fetchStats = async () => {
    try {
      const res = await client.get('/v16/stats')
      setStats(res.data)
    } catch (err) {
      console.error('Error fetching V16 stats:', err)
    }
  }

  const fetchGeoFleet = async () => {
    setLoadingFleet(true)
    try {
      const [fleetRes, alertsRes] = await Promise.all([
        client.get('/v16/devices/geo-fleet'),
        client.get('/v16/impossible-travel/alerts')
      ])
      setGeoFleet(fleetRes.data)
      setImpossibleAlerts(alertsRes.data)
    } catch (err) {
      console.error('Error fetching fleet geo:', err)
    } finally {
      setLoadingFleet(false)
    }
  }

  const fetchEmailAudits = async () => {
    try {
      const res = await client.get('/v16/email/audits')
      setEmailAudits(res.data)
    } catch (err) {
      console.error('Error fetching email audits:', err)
    }
  }

  const fetchUrlHistory = async () => {
    try {
      const res = await client.get('/v16/url/history')
      setUrlHistory(res.data)
    } catch (err) {
      console.error('Error fetching url history:', err)
    }
  }

  useEffect(() => {
    fetchStats()
    fetchGeoFleet()
    fetchEmailAudits()
    fetchUrlHistory()
  }, [])

  // Setup WebSocket connection
  useEffect(() => {
    if (!token) return

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const host = window.location.host
    const wsUrl = `${protocol}//${host}/api/ws/stream?token=${token}`

    const socket = new WebSocket(wsUrl)
    wsRef.current = socket

    socket.onopen = () => {
      setWsConnected(true)
      // Request initial status
      socket.send(JSON.stringify({ action: 'GET_METRICS' }))
    }

    socket.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data)
        if (!wsPaused) {
          setWsLogs((prev) => [
            {
              id: Math.random().toString(36).substring(2, 9),
              time: new Date().toLocaleTimeString(),
              raw: data,
            },
            ...prev.slice(0, 99),
          ])
        }
      } catch (err) {
        console.error('WS Parse Error:', err)
      }
    }

    socket.onclose = () => {
      setWsConnected(false)
    }

    return () => {
      socket.close()
    }
  }, [token, wsPaused])

  // Handlers
  const handlePushHeartbeat = async (presetIp = null, presetName = null) => {
    try {
      const ip = presetIp || hbPublicIp
      const host = presetName || hbHostname
      const res = await client.post('/v16/heartbeat', {
        device_uid: hbDeviceUid,
        hostname: host,
        device_type: 'laptop',
        os_name: 'Windows 11 Enterprise',
        os_version: '10.0.22631',
        public_ip: ip,
        cpu_load_percent: hbCpuLoad,
        memory_used_mb: hbMemMb,
        active_tcp_sockets: 18,
      })
      setLastHeartbeatRes(res.data)
      setFeedback({ type: 'success', msg: `Heartbeat state vector ingested for ${host} (${res.data.location?.city || 'Resolved'})` })
      fetchGeoFleet()
      fetchStats()
    } catch (err) {
      setFeedback({ type: 'error', msg: `Heartbeat push failed: ${err.response?.data?.detail || err.message}` })
    }
  }

  const handleSimulateImpossibleTravel = async () => {
    setSimulatingTravel(true)
    try {
      const res = await client.post('/v16/impossible-travel/simulate', {
        device_uid: 'dev_exec_thinkpad_x1',
        hostname: 'exec-thinkpad-x1',
        origin_ip: '185.190.140.2',     // London
        destination_ip: '203.0.113.88',   // Tokyo
        time_delta_minutes: 10.0,
      })
      setFeedback({
        type: 'warning',
        msg: `🚨 IMPOSSIBLE TRAVEL TRIGGERED: ${res.data.origin} ➔ ${res.data.destination} (${res.data.velocity_kmh.toLocaleString()} km/h). Alert broadcasted to SOC!`,
      })
      fetchGeoFleet()
      fetchStats()
    } catch (err) {
      setFeedback({ type: 'error', msg: `Simulation failed: ${err.response?.data?.detail || err.message}` })
    } finally {
      setSimulatingTravel(false)
    }
  }

  const handleScanEmail = async () => {
    setScanningEmail(true)
    try {
      const payload = emailInputMode === 'eml' && rawEmlText
        ? { raw_eml: rawEmlText, sender_ip: emailSenderIp }
        : {
            sender: emailFrom,
            recipient: emailTo,
            subject: emailSubject,
            body_text: emailBody,
            sender_ip: emailSenderIp,
          }

      const res = await client.post('/v16/email/scan', payload)
      setEmailScanResult(res.data)
      setFeedback({
        type: res.data.is_phishing_or_spam ? 'error' : 'success',
        msg: res.data.is_phishing_or_spam
          ? `⚠️ PHISHING/SPAM DETECTED: Risk Score ${res.data.risk_score * 100}% | SPF: ${res.data.spf_status}`
          : `✅ Clean Email Verified: Risk Score ${res.data.risk_score * 100}% | SPF: ${res.data.spf_status}`,
      })
      fetchEmailAudits()
      fetchStats()
    } catch (err) {
      setFeedback({ type: 'error', msg: `Email scan failed: ${err.response?.data?.detail || err.message}` })
    } finally {
      setScanningEmail(false)
    }
  }

  const handleScanUrl = async (targetUrl = null) => {
    setScanningUrl(true)
    const scanTarget = targetUrl || urlInput
    try {
      const res = await client.post('/v16/url/scan', {
        url: scanTarget,
        force_sandbox: forceSandbox,
      })
      setUrlScanResult(res.data)
      setFeedback({
        type: res.data.is_malicious ? 'error' : 'success',
        msg: res.data.is_malicious
          ? `🛡️ URL ISOLATED BY SANDBOX: ${res.data.domain} (${res.data.tier_matched})`
          : `✅ URL Verified Clean: ${res.data.domain}`,
      })
      fetchUrlHistory()
      fetchStats()
    } catch (err) {
      setFeedback({ type: 'error', msg: `URL scan failed: ${err.response?.data?.detail || err.message}` })
    } finally {
      setScanningUrl(false)
    }
  }

  const applyEmailPreset = (preset) => {
    if (preset === 'ceo_spoof') {
      setEmailFrom('"CEO John Doe" <urgent-payroll@support-update-corp.xyz>')
      setEmailSubject('URGENT ACTION: Immediate Wire Transfer Confirmation')
      setEmailBody('Dear Finance Team,\nPlease execute an urgent wire transfer of $85,000 for invoice attached.\nClick here to verify password and confirm routing details immediately:\nhttps://verify-office365-security.com/login.php')
      setEmailSenderIp('185.220.101.5')
    } else if (preset === 'gift_card') {
      setEmailFrom('"Director Alice Smith" <director.alice@gmail.com>')
      setEmailSubject('Quick favor - in a meeting don\'t call')
      setEmailBody('Hi, I need you to purchase 5x $100 Apple gift cards for a client presentation today. Please send the codes as soon as possible.')
      setEmailSenderIp('198.51.100.54')
    } else if (preset === 'clean_meeting') {
      setEmailFrom('sarah.jenkins@company.internal')
      setEmailSubject('Q3 Detection Engineering Sprint Review')
      setEmailBody('Hi Team,\nPlease find the agenda for our upcoming quarterly sprint planning attached. Let\'s sync at 2 PM.')
      setEmailSenderIp('192.168.1.50')
    }
  }

  return (
    <div className="space-y-6 animate-fadeIn pb-12">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-5 bg-gradient-to-r from-base-900 via-cyan-950/40 to-base-900 border border-cyan-800/50 rounded-xl shadow-xl">
        <div className="space-y-1">
          <div className="flex items-center gap-3">
            <span className="text-2xl text-cyan-400 font-mono">🌐</span>
            <h1 className="text-xl font-bold font-mono text-slate-100 tracking-wide">
              REAL-TIME DEFENSE MATRIX &amp; URL SANDBOX MESH
            </h1>
            <span className="text-xs bg-cyan-900/80 text-cyan-300 font-mono px-2.5 py-0.5 rounded border border-cyan-600/70 font-semibold uppercase tracking-wider">
              Version 16.0
            </span>
          </div>
          <p className="text-xs text-slate-400 max-w-3xl">
            Autonomous Device Geolocation Radar (OCSF 5001/4001), Impossible Travel Velocity Anomaly Evaluator, Serverless Email Anti-Spoofing (OCSF 4009), and 3-Tier Non-Destructive Ephemeral Headless URL Sandbox (OCSF 4002).
          </p>
        </div>

        <div className="flex items-center gap-3 shrink-0">
          <div className="px-3.5 py-2 bg-base-950/80 border border-cyan-700/60 rounded-lg text-center">
            <div className="text-[10px] text-slate-400 font-mono uppercase">Target Score</div>
            <div className="text-sm font-bold text-cyan-300 font-mono">{stats?.mesh_integrity_score || '99.999999/100'}</div>
          </div>
          <div className="px-3.5 py-2 bg-base-950/80 border border-emerald-700/60 rounded-lg text-center">
            <div className="text-[10px] text-slate-400 font-mono uppercase">WebSocket Bus</div>
            <div className="text-sm font-bold font-mono flex items-center gap-1.5 justify-center">
              <span className={`w-2 h-2 rounded-full ${wsConnected ? 'bg-emerald-400 animate-pulse' : 'bg-rose-500'}`} />
              <span className={wsConnected ? 'text-emerald-400' : 'text-rose-400'}>
                {wsConnected ? 'STREAMING' : 'DISCONNECTED'}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Global Feedback Alert */}
      {feedback && (
        <div
          className={`p-4 rounded-lg text-xs font-mono border flex items-center justify-between transition-all ${
            feedback.type === 'success'
              ? 'bg-emerald-950/70 border-emerald-600/80 text-emerald-200'
              : feedback.type === 'warning'
              ? 'bg-amber-950/70 border-amber-600/80 text-amber-200'
              : 'bg-rose-950/70 border-rose-600/80 text-rose-200'
          }`}
        >
          <span>{feedback.msg}</span>
          <button
            onClick={() => setFeedback(null)}
            className="text-slate-400 hover:text-white px-2 py-0.5 rounded hover:bg-white/10"
          >
            ✕
          </button>
        </div>
      )}

      {/* Quick Metrics Bar */}
      <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
        <div className="p-3.5 bg-base-900/90 border border-base-700 rounded-lg">
          <div className="text-[10px] text-slate-400 uppercase font-mono">Geo Fleet Assets</div>
          <div className="text-lg font-bold text-cyan-400 font-mono mt-0.5">{stats?.active_devices_count || geoFleet.length || 0}</div>
        </div>
        <div className="p-3.5 bg-base-900/90 border border-base-700 rounded-lg">
          <div className="text-[10px] text-slate-400 uppercase font-mono">Impossible Travel</div>
          <div className="text-lg font-bold text-rose-400 font-mono mt-0.5">{stats?.impossible_travel_alerts_count || impossibleAlerts.length || 0}</div>
        </div>
        <div className="p-3.5 bg-base-900/90 border border-base-700 rounded-lg">
          <div className="text-[10px] text-slate-400 uppercase font-mono">Emails Audited</div>
          <div className="text-lg font-bold text-purple-400 font-mono mt-0.5">{stats?.emails_scanned_count || emailAudits.length || 0}</div>
        </div>
        <div className="p-3.5 bg-base-900/90 border border-base-700 rounded-lg">
          <div className="text-[10px] text-slate-400 uppercase font-mono">Phishing Neutralized</div>
          <div className="text-lg font-bold text-amber-400 font-mono mt-0.5">{stats?.phishing_blocked_count || 0}</div>
        </div>
        <div className="p-3.5 bg-base-900/90 border border-base-700 rounded-lg">
          <div className="text-[10px] text-slate-400 uppercase font-mono">URLs Audited</div>
          <div className="text-lg font-bold text-blue-400 font-mono mt-0.5">{stats?.urls_inspected_count || urlHistory.length || 0}</div>
        </div>
        <div className="p-3.5 bg-base-900/90 border border-base-700 rounded-lg">
          <div className="text-[10px] text-slate-400 uppercase font-mono">Malicious Isolated</div>
          <div className="text-lg font-bold text-red-400 font-mono mt-0.5">{stats?.malicious_urls_isolated || 0}</div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex border-b border-base-700 gap-2 overflow-x-auto pb-1">
        <button
          onClick={() => setActiveTab('geo')}
          className={`px-4 py-2.5 rounded-t-lg font-mono text-xs font-semibold tracking-wide transition-all ${
            activeTab === 'geo'
              ? 'bg-cyan-950 text-cyan-300 border-t-2 border-cyan-400 border-x border-base-700'
              : 'text-slate-400 hover:text-slate-200 hover:bg-base-800'
          }`}
        >
          🌐 Device Geolocation &amp; Impossible Travel (OCSF 5001)
        </button>
        <button
          onClick={() => setActiveTab('email')}
          className={`px-4 py-2.5 rounded-t-lg font-mono text-xs font-semibold tracking-wide transition-all ${
            activeTab === 'email'
              ? 'bg-purple-950 text-purple-300 border-t-2 border-purple-400 border-x border-base-700'
              : 'text-slate-400 hover:text-slate-200 hover:bg-base-800'
          }`}
        >
          ✉️ Serverless Email &amp; Anti-Spoofing ML (OCSF 4009)
        </button>
        <button
          onClick={() => setActiveTab('url')}
          className={`px-4 py-2.5 rounded-t-lg font-mono text-xs font-semibold tracking-wide transition-all ${
            activeTab === 'url'
              ? 'bg-blue-950 text-blue-300 border-t-2 border-blue-400 border-x border-base-700'
              : 'text-slate-400 hover:text-slate-200 hover:bg-base-800'
          }`}
        >
          🛡️ Non-Destructive URL Sandbox (OCSF 4002)
        </button>
        <button
          onClick={() => setActiveTab('ws')}
          className={`px-4 py-2.5 rounded-t-lg font-mono text-xs font-semibold tracking-wide transition-all ${
            activeTab === 'ws'
              ? 'bg-emerald-950 text-emerald-300 border-t-2 border-emerald-400 border-x border-base-700'
              : 'text-slate-400 hover:text-slate-200 hover:bg-base-800'
          }`}
        >
          ⚡ Live WebSocket Anomaly Stream (OCSF 2004)
        </button>
      </div>

      {/* ========================================================================= */}
      {/* TAB 1: FLEET GEOLOCATION & IMPOSSIBLE TRAVEL */}
      {/* ========================================================================= */}
      {activeTab === 'geo' && (
        <div className="space-y-6">
          {/* Top Control & Simulator */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
            {/* Heartbeat Ingestion Vector */}
            <div className="p-4 bg-base-900/80 border border-base-700 rounded-xl space-y-3">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-mono font-bold text-slate-200 flex items-center gap-2">
                  <span className="text-cyan-400">📡</span> Agent State Vector Ingestion
                </h3>
                <span className="text-[10px] text-cyan-400 font-mono">30s Heartbeat</span>
              </div>

              <div className="space-y-2 text-xs font-mono">
                <div>
                  <label className="text-[10px] text-slate-400">Device UID &amp; Hostname</label>
                  <div className="grid grid-cols-2 gap-2 mt-1">
                    <input
                      type="text"
                      value={hbDeviceUid}
                      onChange={(e) => setHbDeviceUid(e.target.value)}
                      className="bg-base-950 border border-base-700 rounded p-1.5 text-slate-200 text-xs"
                      placeholder="dev_uid"
                    />
                    <input
                      type="text"
                      value={hbHostname}
                      onChange={(e) => setHbHostname(e.target.value)}
                      className="bg-base-950 border border-base-700 rounded p-1.5 text-slate-200 text-xs"
                      placeholder="hostname"
                    />
                  </div>
                </div>

                <div>
                  <label className="text-[10px] text-slate-400">Public IP (GeoIP Resolved)</label>
                  <input
                    type="text"
                    value={hbPublicIp}
                    onChange={(e) => setHbPublicIp(e.target.value)}
                    className="w-full mt-1 bg-base-950 border border-base-700 rounded p-1.5 text-cyan-300 text-xs"
                  />
                </div>

                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <label className="text-[10px] text-slate-400">CPU Load %</label>
                    <input
                      type="number"
                      value={hbCpuLoad}
                      onChange={(e) => setHbCpuLoad(parseFloat(e.target.value))}
                      className="w-full mt-1 bg-base-950 border border-base-700 rounded p-1.5 text-slate-200 text-xs"
                    />
                  </div>
                  <div>
                    <label className="text-[10px] text-slate-400">Memory (MB)</label>
                    <input
                      type="number"
                      value={hbMemMb}
                      onChange={(e) => setHbMemMb(parseFloat(e.target.value))}
                      className="w-full mt-1 bg-base-950 border border-base-700 rounded p-1.5 text-slate-200 text-xs"
                    />
                  </div>
                </div>

                <div className="pt-2">
                  <button
                    onClick={() => handlePushHeartbeat()}
                    className="w-full py-2 bg-cyan-900/70 hover:bg-cyan-800 text-cyan-200 border border-cyan-600/60 rounded font-semibold text-xs tracking-wider transition-all"
                  >
                    PUSH HEARTBEAT STATE VECTOR
                  </button>
                </div>
              </div>
            </div>

            {/* Hub Quick Teleport Presets */}
            <div className="p-4 bg-base-900/80 border border-base-700 rounded-xl space-y-3">
              <h3 className="text-xs font-mono font-bold text-slate-200 flex items-center gap-2">
                <span className="text-purple-400">⚡</span> Global Check-in Teleport Presets
              </h3>
              <p className="text-[11px] text-slate-400">
                Trigger immediate check-in pings from verified enterprise gateway nodes:
              </p>

              <div className="grid grid-cols-2 gap-2 pt-1">
                <button
                  onClick={() => handlePushHeartbeat('185.190.140.2', 'london-thinkpad')}
                  className="p-2 bg-base-950 hover:bg-base-800 border border-base-700 rounded text-left text-xs font-mono transition-all"
                >
                  <div className="text-cyan-300 font-bold">🇬🇧 London, UK</div>
                  <div className="text-[10px] text-slate-400">185.190.140.2</div>
                </button>
                <button
                  onClick={() => handlePushHeartbeat('198.51.100.54', 'nyc-workstation')}
                  className="p-2 bg-base-950 hover:bg-base-800 border border-base-700 rounded text-left text-xs font-mono transition-all"
                >
                  <div className="text-cyan-300 font-bold">🇺🇸 New York, US</div>
                  <div className="text-[10px] text-slate-400">198.51.100.54</div>
                </button>
                <button
                  onClick={() => handlePushHeartbeat('203.0.113.88', 'tokyo-server')}
                  className="p-2 bg-base-950 hover:bg-base-800 border border-base-700 rounded text-left text-xs font-mono transition-all"
                >
                  <div className="text-cyan-300 font-bold">🇯🇵 Tokyo, Japan</div>
                  <div className="text-[10px] text-slate-400">203.0.113.88</div>
                </button>
                <button
                  onClick={() => handlePushHeartbeat('139.130.4.5', 'sydney-laptop')}
                  className="p-2 bg-base-950 hover:bg-base-800 border border-base-700 rounded text-left text-xs font-mono transition-all"
                >
                  <div className="text-cyan-300 font-bold">🇦🇺 Sydney, AU</div>
                  <div className="text-[10px] text-slate-400">139.130.4.5</div>
                </button>
              </div>

              <div className="pt-2 border-t border-base-800 flex items-center justify-between text-[11px] font-mono text-slate-400">
                <span>Haversine Speed Threshold:</span>
                <span className="text-rose-400 font-bold">&gt; 800 km/h</span>
              </div>
            </div>

            {/* Impossible Travel Attack Simulator */}
            <div className="p-4 bg-gradient-to-br from-rose-950/40 via-base-900 to-base-950 border border-rose-800/60 rounded-xl space-y-3">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-mono font-bold text-rose-200 flex items-center gap-2">
                  <span>🚨</span> Impossible Travel Attack Simulation
                </h3>
                <span className="text-[10px] bg-rose-900 text-rose-300 px-2 py-0.5 rounded font-mono font-bold">
                  HIGH SEVERITY
                </span>
              </div>
              <p className="text-[11px] text-slate-300">
                Simulates a device account compromised across distant geographical coordinates in under 10 minutes:
              </p>

              <div className="p-2.5 bg-base-950/80 border border-rose-900/60 rounded text-xs font-mono space-y-1">
                <div className="flex items-center justify-between text-slate-300">
                  <span>Route:</span>
                  <span className="text-rose-300 font-bold">London ➔ Tokyo</span>
                </div>
                <div className="flex items-center justify-between text-slate-400">
                  <span>Separation Distance:</span>
                  <span>~9,560 km</span>
                </div>
                <div className="flex items-center justify-between text-slate-400">
                  <span>Simulated Delta:</span>
                  <span>10.0 minutes</span>
                </div>
                <div className="flex items-center justify-between text-rose-400 font-bold">
                  <span>Calculated Velocity:</span>
                  <span>~57,360 km/h</span>
                </div>
              </div>

              <button
                disabled={simulatingTravel}
                onClick={handleSimulateImpossibleTravel}
                className="w-full py-2 bg-rose-900/80 hover:bg-rose-800 text-rose-100 border border-rose-600 rounded font-semibold text-xs tracking-wider transition-all disabled:opacity-50"
              >
                {simulatingTravel ? 'SIMULATING ATTACK...' : 'TRIGGER IMPOSSIBLE TRAVEL ATTACK'}
              </button>
            </div>
          </div>

          {/* Active Fleet Geolocation Grid */}
          <div className="p-5 bg-base-900/80 border border-base-700 rounded-xl space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-mono font-bold text-slate-100 flex items-center gap-2">
                <span className="text-cyan-400">🌍</span> Live Geographical Asset Grid (OCSF Class 5001)
              </h3>
              <button
                onClick={fetchGeoFleet}
                className="px-3 py-1 bg-base-800 hover:bg-base-700 text-slate-300 rounded text-xs font-mono"
              >
                ↻ Refresh Nodes
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {geoFleet.length === 0 ? (
                <div className="col-span-3 p-8 text-center text-slate-500 font-mono text-xs">
                  No active heartbeats recorded yet. Push a heartbeat above to register fleet nodes.
                </div>
              ) : (
                geoFleet.map((node) => (
                  <div key={node.id} className="p-4 bg-base-950 border border-base-700/80 rounded-lg space-y-2.5">
                    <div className="flex items-center justify-between">
                      <div className="font-mono font-bold text-cyan-300 text-xs flex items-center gap-2">
                        <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                        {node.hostname}
                      </div>
                      <span className="text-[10px] bg-base-800 text-slate-300 font-mono px-2 py-0.5 rounded">
                        {node.device_type}
                      </span>
                    </div>

                    <div className="text-xs font-mono text-slate-300 space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="text-slate-400">Location:</span>
                        <span className="text-slate-100 font-semibold">{node.city}, {node.country}</span>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-slate-400">Coordinates:</span>
                        <span className="text-slate-300">{node.latitude?.toFixed(2)}°, {node.longitude?.toFixed(2)}°</span>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-slate-400">Public IP / ASN:</span>
                        <span className="text-cyan-400">{node.public_ip} (AS{node.asn})</span>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-slate-400">OS:</span>
                        <span className="text-slate-300">{node.os_name}</span>
                      </div>
                    </div>

                    <div className="pt-2 border-t border-base-800 space-y-1">
                      <div className="flex items-center justify-between text-[10px] font-mono text-slate-400">
                        <span>CPU Load: {node.cpu_load_percent}%</span>
                        <span>Memory: {node.memory_used_mb} MB</span>
                      </div>
                      <div className="w-full h-1.5 bg-base-800 rounded-full overflow-hidden">
                        <div
                          className="h-full bg-cyan-400 rounded-full"
                          style={{ width: `${Math.min(node.cpu_load_percent, 100)}%` }}
                        />
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Impossible Travel Anomalies Table */}
          {impossibleAlerts.length > 0 && (
            <div className="p-5 bg-rose-950/20 border border-rose-800/50 rounded-xl space-y-3">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-mono font-bold text-rose-300 flex items-center gap-2">
                  <span>🚨</span> Impossible Travel Anomaly Detection Logs
                </h3>
                <span className="text-[10px] bg-rose-900/80 text-rose-200 px-2.5 py-0.5 rounded font-mono font-bold">
                  {impossibleAlerts.length} Active Anomalies
                </span>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left font-mono text-xs">
                  <thead className="bg-base-950 text-slate-400 uppercase text-[10px] border-b border-base-800">
                    <tr>
                      <th className="p-2.5">Hostname</th>
                      <th className="p-2.5">Previous Location</th>
                      <th className="p-2.5">Current Location</th>
                      <th className="p-2.5">Distance</th>
                      <th className="p-2.5">Delta</th>
                      <th className="p-2.5">Velocity</th>
                      <th className="p-2.5">Severity</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-base-800 text-slate-200">
                    {impossibleAlerts.map((a) => (
                      <tr key={a.id} className="hover:bg-rose-950/30 transition-all">
                        <td className="p-2.5 text-cyan-300 font-bold">{a.hostname}</td>
                        <td className="p-2.5">{a.prev_location} ({a.prev_ip})</td>
                        <td className="p-2.5 text-rose-300 font-semibold">{a.current_location} ({a.current_ip})</td>
                        <td className="p-2.5">{a.distance_km?.toFixed(0)} km</td>
                        <td className="p-2.5">{a.time_diff_minutes?.toFixed(1)} min</td>
                        <td className="p-2.5 text-rose-400 font-bold">{a.velocity_kmh?.toFixed(0)} km/h</td>
                        <td className="p-2.5">
                          <span className="bg-rose-900 text-rose-200 text-[10px] px-2 py-0.5 rounded font-bold uppercase">
                            {a.severity}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 2: SERVERLESS EMAIL SECURITY & SPAM ML */}
      {/* ========================================================================= */}
      {activeTab === 'email' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
            {/* Email Inspection Inputs */}
            <div className="lg:col-span-2 p-5 bg-base-900/80 border border-base-700 rounded-xl space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-mono font-bold text-purple-300 flex items-center gap-2">
                  <span>✉️</span> Serverless Email Payload &amp; Header Scanner
                </h3>
                <div className="flex gap-1.5">
                  <button
                    onClick={() => applyEmailPreset('ceo_spoof')}
                    className="px-2 py-1 bg-purple-950 hover:bg-purple-900 border border-purple-800 text-purple-200 rounded text-[10px] font-mono"
                  >
                    CEO Spoof
                  </button>
                  <button
                    onClick={() => applyEmailPreset('gift_card')}
                    className="px-2 py-1 bg-purple-950 hover:bg-purple-900 border border-purple-800 text-purple-200 rounded text-[10px] font-mono"
                  >
                    Gift Card Scam
                  </button>
                  <button
                    onClick={() => applyEmailPreset('clean_meeting')}
                    className="px-2 py-1 bg-base-800 hover:bg-base-700 text-slate-300 rounded text-[10px] font-mono"
                  >
                    Clean Email
                  </button>
                </div>
              </div>

              <div className="space-y-3 text-xs font-mono">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  <div>
                    <label className="text-[10px] text-slate-400">Header "From:"</label>
                    <input
                      type="text"
                      value={emailFrom}
                      onChange={(e) => setEmailFrom(e.target.value)}
                      className="w-full mt-1 bg-base-950 border border-base-700 rounded p-2 text-slate-200 text-xs"
                    />
                  </div>
                  <div>
                    <label className="text-[10px] text-slate-400">Sending Host IP</label>
                    <input
                      type="text"
                      value={emailSenderIp}
                      onChange={(e) => setEmailSenderIp(e.target.value)}
                      className="w-full mt-1 bg-base-950 border border-base-700 rounded p-2 text-cyan-300 text-xs"
                    />
                  </div>
                </div>

                <div>
                  <label className="text-[10px] text-slate-400">Subject</label>
                  <input
                    type="text"
                    value={emailSubject}
                    onChange={(e) => setEmailSubject(e.target.value)}
                    className="w-full mt-1 bg-base-950 border border-base-700 rounded p-2 text-slate-200 text-xs"
                  />
                </div>

                <div>
                  <label className="text-[10px] text-slate-400">Email Body Content</label>
                  <textarea
                    rows={4}
                    value={emailBody}
                    onChange={(e) => setEmailBody(e.target.value)}
                    className="w-full mt-1 bg-base-950 border border-base-700 rounded p-2 text-slate-200 text-xs font-mono resize-none"
                  />
                </div>

                <button
                  disabled={scanningEmail}
                  onClick={handleScanEmail}
                  className="w-full py-2.5 bg-purple-900/80 hover:bg-purple-800 text-purple-100 border border-purple-600 rounded font-semibold text-xs tracking-wider transition-all disabled:opacity-50"
                >
                  {scanningEmail ? 'AUDITING EMAIL HEADERS & BODY...' : 'SCAN EMAIL FOR PHISHING & SPOOFING (OCSF 4009)'}
                </button>
              </div>
            </div>

            {/* Live Scan Results Panel */}
            <div className="p-5 bg-base-900/80 border border-base-700 rounded-xl space-y-4">
              <h3 className="text-xs font-mono font-bold text-slate-200 flex items-center gap-2">
                <span className="text-cyan-400">🔬</span> Email Security Verdict
              </h3>

              {emailScanResult ? (
                <div className="space-y-3 font-mono text-xs">
                  {/* Verdict Badge */}
                  <div
                    className={`p-3 rounded-lg border text-center font-bold ${
                      emailScanResult.is_phishing_or_spam
                        ? 'bg-rose-950/80 border-rose-600 text-rose-300'
                        : 'bg-emerald-950/80 border-emerald-600 text-emerald-300'
                    }`}
                  >
                    {emailScanResult.is_phishing_or_spam
                      ? '⚠️ PHISHING / SOCIAL ENGINEERING DETECTED'
                      : '✅ EMAIL VERIFIED CLEAN'}
                  </div>

                  {/* Authentication Protocol Grid */}
                  <div className="grid grid-cols-3 gap-2 text-center text-[10px]">
                    <div className="p-2 bg-base-950 border border-base-800 rounded">
                      <div className="text-slate-400">SPF</div>
                      <div className={`font-bold mt-0.5 ${emailScanResult.spf_status === 'PASS' ? 'text-emerald-400' : 'text-rose-400'}`}>
                        {emailScanResult.spf_status}
                      </div>
                    </div>
                    <div className="p-2 bg-base-950 border border-base-800 rounded">
                      <div className="text-slate-400">DKIM</div>
                      <div className={`font-bold mt-0.5 ${emailScanResult.dkim_status === 'PASS' ? 'text-emerald-400' : 'text-amber-400'}`}>
                        {emailScanResult.dkim_status}
                      </div>
                    </div>
                    <div className="p-2 bg-base-950 border border-base-800 rounded">
                      <div className="text-slate-400">DMARC</div>
                      <div className={`font-bold mt-0.5 ${emailScanResult.dmarc_status === 'PASS' ? 'text-emerald-400' : 'text-rose-400'}`}>
                        {emailScanResult.dmarc_status}
                      </div>
                    </div>
                  </div>

                  {/* Risk Score Meter */}
                  <div className="space-y-1">
                    <div className="flex items-center justify-between text-[11px]">
                      <span className="text-slate-400">Composite Risk Score:</span>
                      <span className="font-bold text-slate-100">{emailScanResult.risk_score * 100}%</span>
                    </div>
                    <div className="w-full h-2 bg-base-950 rounded-full overflow-hidden">
                      <div
                        className={`h-full ${emailScanResult.risk_score >= 0.5 ? 'bg-rose-500' : 'bg-emerald-500'}`}
                        style={{ width: `${emailScanResult.risk_score * 100}%` }}
                      />
                    </div>
                  </div>

                  {/* Phishing Indicators */}
                  {emailScanResult.phishing_indicators?.length > 0 && (
                    <div className="space-y-1">
                      <div className="text-[10px] uppercase text-slate-400">Matched Threat Patterns:</div>
                      <div className="space-y-1">
                        {emailScanResult.phishing_indicators.map((ind, i) => (
                          <div key={i} className="p-2 bg-base-950 border border-rose-900/60 rounded text-[11px] text-rose-300">
                            • {ind.description} ({ind.matched_count} matches)
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Extracted URLs */}
                  {emailScanResult.urls_found?.length > 0 && (
                    <div className="space-y-1">
                      <div className="text-[10px] uppercase text-slate-400">Extracted Inbound URLs:</div>
                      {emailScanResult.urls_found.map((u, i) => (
                        <div key={i} className="p-2 bg-base-950 border border-blue-900/60 rounded text-[11px] flex items-center justify-between">
                          <span className="text-blue-300 truncate max-w-[180px]">{u}</span>
                          <button
                            onClick={() => {
                              setUrlInput(u)
                              setActiveTab('url')
                              handleScanUrl(u)
                            }}
                            className="px-2 py-0.5 bg-blue-900 hover:bg-blue-800 text-blue-200 rounded text-[10px]"
                          >
                            Sandbox ➔
                          </button>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              ) : (
                <div className="p-8 text-center text-slate-500 font-mono text-xs">
                  Run an email scan to inspect SPF/DKIM/DMARC headers and linguistic spam score.
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 3: NON-DESTRUCTIVE URL SANDBOX */}
      {/* ========================================================================= */}
      {activeTab === 'url' && (
        <div className="space-y-6">
          {/* URL Input Bar */}
          <div className="p-5 bg-base-900/80 border border-base-700 rounded-xl space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-mono font-bold text-blue-300 flex items-center gap-2">
                <span>🛡️</span> Multi-Tier Remote Headless URL Sandbox (OCSF 4002)
              </h3>
              <div className="flex gap-2">
                <button
                  onClick={() => {
                    setUrlInput('https://verify-office365-security.com/verify-login')
                    handleScanUrl('https://verify-office365-security.com/verify-login')
                  }}
                  className="px-2.5 py-1 bg-blue-950 hover:bg-blue-900 border border-blue-800 text-blue-200 rounded text-[10px] font-mono"
                >
                  Phishing Login Target
                </button>
                <button
                  onClick={() => {
                    setUrlInput('https://phish-bank-login.xyz/auth.php')
                    handleScanUrl('https://phish-bank-login.xyz/auth.php')
                  }}
                  className="px-2.5 py-1 bg-rose-950 hover:bg-rose-900 border border-rose-800 text-rose-200 rounded text-[10px] font-mono"
                >
                  Known Threat Intel IOC
                </button>
                <button
                  onClick={() => {
                    setUrlInput('https://github.com/security/advisories')
                    handleScanUrl('https://github.com/security/advisories')
                  }}
                  className="px-2.5 py-1 bg-base-800 hover:bg-base-700 text-slate-300 rounded text-[10px] font-mono"
                >
                  Clean URL
                </button>
              </div>
            </div>

            <div className="flex gap-2">
              <input
                type="text"
                value={urlInput}
                onChange={(e) => setUrlInput(e.target.value)}
                placeholder="https://suspicious-target-url.com/login"
                className="flex-1 bg-base-950 border border-base-700 rounded-lg p-3 text-cyan-300 font-mono text-xs focus:outline-none focus:border-cyan-500"
              />
              <button
                disabled={scanningUrl}
                onClick={() => handleScanUrl()}
                className="px-6 py-3 bg-blue-900/80 hover:bg-blue-800 text-blue-100 border border-blue-600 rounded-lg font-mono font-bold text-xs tracking-wider transition-all disabled:opacity-50"
              >
                {scanningUrl ? 'INSPECTING IN ISOLATED SANDBOX...' : 'SAFE INSPECT URL'}
              </button>
            </div>
          </div>

          {/* URL Inspection Breakdown & Visual Preview Canvas */}
          {urlScanResult && (
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
              {/* Inspection Breakdown */}
              <div className="p-5 bg-base-900/80 border border-base-700 rounded-xl space-y-4 font-mono text-xs">
                <h4 className="text-xs font-bold text-slate-200">🔍 Multi-Tier Safety Evaluation</h4>

                <div
                  className={`p-3 rounded-lg border text-center font-bold ${
                    urlScanResult.is_malicious
                      ? 'bg-rose-950/80 border-rose-600 text-rose-300'
                      : 'bg-emerald-950/80 border-emerald-600 text-emerald-300'
                  }`}
                >
                  {urlScanResult.is_malicious ? '⚠️ BLOCKED MALICIOUS URL' : '✅ CLEAN REPUTATION VERIFIED'}
                </div>

                <div className="space-y-2 text-slate-300">
                  <div className="flex items-center justify-between">
                    <span className="text-slate-400">Target Host:</span>
                    <span className="text-cyan-300 font-semibold">{urlScanResult.domain}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-slate-400">Inspection Tier:</span>
                    <span className="text-purple-300 font-semibold">{urlScanResult.tier_matched}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-slate-400">SHA-256 Hash:</span>
                    <span className="text-slate-400 text-[10px] truncate max-w-[160px]">{urlScanResult.url_hash}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-slate-400">Sandbox Emulation:</span>
                    <span className={urlScanResult.emulation_triggered ? 'text-cyan-400 font-bold' : 'text-slate-400'}>
                      {urlScanResult.emulation_triggered ? 'ISOLATED CONTAINER ACTIVE' : 'PASSIVE'}
                    </span>
                  </div>
                </div>

                <div className="p-3 bg-base-950 border border-base-800 rounded space-y-1">
                  <div className="text-[10px] text-slate-400 uppercase">Detection Rationale:</div>
                  <div className="text-[11px] text-slate-200">{urlScanResult.detection_reason}</div>
                </div>

                {urlScanResult.dom_metadata && (
                  <div className="p-3 bg-base-950 border border-base-800 rounded space-y-1 text-[11px]">
                    <div className="text-[10px] text-slate-400 uppercase">DOM Security Analysis:</div>
                    <div className="text-slate-300">• Page Title: <span className="text-white">{urlScanResult.dom_metadata.title}</span></div>
                    <div className="text-slate-300">• HTTP Status: <span className="text-emerald-400">{urlScanResult.dom_metadata.http_status}</span></div>
                    <div className="text-slate-300">• Scripts Blocked: <span className="text-rose-400 font-bold">{urlScanResult.dom_metadata.scripts_blocked_count}</span></div>
                  </div>
                )}
              </div>

              {/* Safe Visual Sandbox Preview Canvas */}
              <div className="lg:col-span-2 p-5 bg-base-900/80 border border-base-700 rounded-xl space-y-3">
                <div className="flex items-center justify-between">
                  <h4 className="text-xs font-mono font-bold text-slate-200 flex items-center gap-2">
                    <span className="text-cyan-400">🖥️</span> Remote Server-Side Visual Snapshot (Zero Device Execution)
                  </h4>
                  <span className="text-[10px] bg-cyan-950 text-cyan-300 font-mono px-2 py-0.5 rounded border border-cyan-800">
                    Safe DOM Render
                  </span>
                </div>

                <div className="border border-base-700 rounded-lg overflow-hidden bg-base-950 flex items-center justify-center p-2">
                  <img
                    src={`/api/v16/url/render/${urlScanResult.url_hash}`}
                    alt="Isolated URL Sandbox Visual Preview"
                    className="w-full h-auto max-h-[380px] object-contain rounded"
                  />
                </div>

                <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
                  <span>🔒 Rendered in ephemeral server-side Chromium sandbox.</span>
                  <span className="text-cyan-400">No client-side JavaScript executed.</span>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 4: REAL-TIME WEBSOCKET ANOMALY STREAM */}
      {/* ========================================================================= */}
      {activeTab === 'ws' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between p-4 bg-base-900 border border-base-700 rounded-xl">
            <div className="flex items-center gap-3">
              <span className={`w-3 h-3 rounded-full ${wsConnected ? 'bg-emerald-400 animate-pulse' : 'bg-rose-500'}`} />
              <div className="font-mono text-xs">
                <div className="font-bold text-slate-100">
                  {wsConnected ? 'Redis Pub/Sub WebSocket Stream Active' : 'Connecting to Redis Pub/Sub Event Stream...'}
                </div>
                <div className="text-[10px] text-slate-400">
                  Sub-millisecond push for OCSF Class 2004 Security Findings &amp; Class 5001 Device Heartbeats.
                </div>
              </div>
            </div>

            <div className="flex gap-2">
              <button
                onClick={() => setWsPaused(!wsPaused)}
                className={`px-3 py-1 rounded text-xs font-mono border transition-all ${
                  wsPaused
                    ? 'bg-amber-950 border-amber-600 text-amber-200'
                    : 'bg-base-800 border-base-700 text-slate-300 hover:bg-base-700'
                }`}
              >
                {wsPaused ? '▶ Resume Stream' : '⏸ Pause Stream'}
              </button>
              <button
                onClick={() => setWsLogs([])}
                className="px-3 py-1 bg-base-800 hover:bg-base-700 border border-base-700 text-slate-300 rounded text-xs font-mono"
              >
                Clear Stream
              </button>
            </div>
          </div>

          {/* Terminal Stream Feed */}
          <div className="p-4 bg-base-950 border border-base-800 rounded-xl font-mono text-xs space-y-2 h-96 overflow-y-auto">
            {wsLogs.length === 0 ? (
              <div className="text-slate-500 text-center py-24">
                Listening for real-time telemetry frames and anomaly alerts on Redis channel...
              </div>
            ) : (
              wsLogs.map((log) => (
                <div
                  key={log.id}
                  onClick={() => setSelectedWsEvent(log.raw)}
                  className="p-2.5 bg-base-900/60 hover:bg-base-900 border border-base-800 rounded cursor-pointer transition-all flex items-start justify-between"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="text-slate-500 text-[10px]">{log.time}</span>
                      <span className="text-cyan-400 font-bold uppercase">{log.raw?.event || 'ALERT'}</span>
                      {log.raw?.severity && (
                        <span className="text-[9px] bg-rose-900 text-rose-200 px-1.5 rounded uppercase font-bold">
                          {log.raw.severity}
                        </span>
                      )}
                    </div>
                    <div className="text-slate-300 text-[11px]">
                      {log.raw?.hostname && <span className="text-cyan-300 font-bold">[{log.raw.hostname}] </span>}
                      {log.raw?.payload?.title || log.raw?.details?.current_location || log.raw?.from || JSON.stringify(log.raw?.payload || log.raw)}
                    </div>
                  </div>
                  <span className="text-[10px] text-slate-500">Inspect ➔</span>
                </div>
              ))
            )}
          </div>

          {/* Event JSON Modal / Drawer */}
          {selectedWsEvent && (
            <div className="p-4 bg-base-900 border border-cyan-800/80 rounded-xl space-y-2 font-mono text-xs">
              <div className="flex items-center justify-between">
                <span className="text-cyan-300 font-bold">Selected Real-Time Payload Inspector</span>
                <button
                  onClick={() => setSelectedWsEvent(null)}
                  className="text-slate-400 hover:text-white"
                >
                  ✕ Close
                </button>
              </div>
              <pre className="p-3 bg-base-950 border border-base-800 rounded text-slate-300 text-[11px] overflow-x-auto max-h-60">
                {JSON.stringify(selectedWsEvent, null, 2)}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
