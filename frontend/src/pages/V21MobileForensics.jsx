import React, { useState, useEffect } from 'react'
import client from '../api/client'
import MobileAuditConsole from '../components/MobileAuditConsole'

export default function V21MobileForensics() {
  const [engineStatus, setEngineStatus] = useState(null)
  const [sessions, setSessions] = useState([])
  const [activeSession, setActiveSession] = useState(null)
  const [loading, setLoading] = useState(true)
  const [actionLoading, setActionLoading] = useState(false)
  const [error, setError] = useState('')
  const [successMsg, setSuccessMsg] = useState('')

  // Device Discovery State
  const [usbPort, setUsbPort] = useState('/dev/bus/usb/001/004')
  const [probedDevice, setProbedDevice] = useState({
    device_id: 'usb_mob_default',
    manufacturer: 'Google',
    model: 'Pixel 8 Pro',
    serial_number: 'G8P9X0214872X',
    udid: '00008101-001C34A90A2E001A',
    os_name: 'Android',
    os_version: '14 (SnoopOS API 34)',
    battery_level: 85,
    is_encrypted: true,
    connection_type: 'USB_OTG_HID',
    usb_vid: '0x18d1',
    usb_pid: '0x4ee1',
    status: 'DETECTED_PHYSICALLY'
  })

  // New Session State
  const [passcodeType, setPasscodeType] = useState('PATTERN')
  const [targetSecret, setTargetSecret] = useState('01258')

  const fetchStatusAndSessions = async (isQuiet = false) => {
    try {
      if (!isQuiet) setLoading(true)
      const [statusRes, sessionsRes] = await Promise.all([
        client.get('/v21/forensics/status'),
        client.get('/v21/forensics/sessions?limit=25')
      ])
      setEngineStatus(statusRes.data)
      setSessions(sessionsRes.data || [])
      if (sessionsRes.data && sessionsRes.data.length > 0 && !activeSession) {
        setActiveSession(sessionsRes.data[0])
      }
    } catch (err) {
      console.error('Error fetching V21 forensics data:', err)
      if (!isQuiet) setError('Failed to fetch forensic engine status or sessions.')
    } finally {
      if (!isQuiet) setLoading(false)
    }
  }

  useEffect(() => {
    fetchStatusAndSessions()
    const interval = setInterval(() => {
      fetchStatusAndSessions(true)
    }, 4000)
    return () => clearInterval(interval)
  }, [])

  const handleProbeDevice = async () => {
    try {
      setActionLoading(true)
      setError('')
      const res = await client.post('/v21/forensics/device/discover', {
        usb_port_path: usbPort,
        probe_protocol: 'AUTO'
      })
      setProbedDevice(res.data)
      setSuccessMsg(`Discovered ${res.data.manufacturer} ${res.data.model} on ${usbPort}`)
      setTimeout(() => setSuccessMsg(''), 4000)
    } catch (err) {
      setError('Device discovery failed.')
    } finally {
      setActionLoading(false)
    }
  }

  const handleStartSession = async (e) => {
    e.preventDefault()
    try {
      setActionLoading(true)
      setError('')
      const res = await client.post('/v21/forensics/sessions/start', {
        device_name: probedDevice.manufacturer,
        device_model: probedDevice.model,
        serial_number: probedDevice.serial_number,
        udid: probedDevice.udid,
        os_name: probedDevice.os_name,
        os_version: probedDevice.os_version,
        connection_type: 'USB_OTG_HID',
        passcode_type: passcodeType,
        target_mock_passcode: targetSecret
      })
      setActiveSession(res.data)
      setSessions((prev) => [res.data, ...prev])
      setSuccessMsg(`Forensic Session ${res.data.session_id.slice(0, 8)} initialized successfully.`)
      setTimeout(() => setSuccessMsg(''), 4000)
    } catch (err) {
      setError('Failed to start forensic session.')
    } finally {
      setActionLoading(false)
    }
  }

  const handleRunBatchAudit = async () => {
    if (!activeSession) return
    try {
      setActionLoading(true)
      setError('')
      const res = await client.post(`/v21/forensics/sessions/${activeSession.session_id}/run-audit`, {
        max_attempts: 15,
        target_secret_override: targetSecret
      })
      setSuccessMsg(`Batch audit executed: ${res.data.total_attempts_run} attempts processed. Status: ${res.data.status}`)
      fetchStatusAndSessions()
      setTimeout(() => setSuccessMsg(''), 4000)
    } catch (err) {
      setError('Batch audit execution encountered an error.')
    } finally {
      setActionLoading(false)
    }
  }

  const handleSingleStepAttempt = async () => {
    if (!activeSession) return
    try {
      setActionLoading(true)
      setError('')
      let cand = '1234'
      let coords = null
      if (activeSession.passcode_type === 'PATTERN') {
        coords = [0, 1, 2, 5, 8]
        cand = '01258'
      } else if (activeSession.passcode_type === 'PIN_6') {
        cand = '123456'
      }
      await client.post(`/v21/forensics/sessions/${activeSession.session_id}/attempt`, {
        candidate_passcode: cand,
        pattern_path: coords,
        passcode_type: activeSession.passcode_type
      })
      fetchStatusAndSessions()
    } catch (err) {
      setError('Single attempt dispatch failed.')
    } finally {
      setActionLoading(false)
    }
  }

  const handleTerminateSession = async () => {
    if (!activeSession) return
    try {
      setActionLoading(true)
      await client.post(`/v21/forensics/sessions/${activeSession.session_id}/stop`)
      setSuccessMsg('Session terminated.')
      fetchStatusAndSessions()
      setTimeout(() => setSuccessMsg(''), 3000)
    } catch (err) {
      setError('Failed to terminate session.')
    } finally {
      setActionLoading(false)
    }
  }

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12 font-sans">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-base-700/80 pb-5">
        <div>
          <div className="flex items-center gap-3">
            <span className="text-2xl font-mono text-teal-400">📱</span>
            <div>
              <h1 className="text-xl font-bold text-slate-100 tracking-wide font-mono flex items-center gap-2">
                Physical Mobile Forensics &amp; Passcode Auditing Mesh
                <span className="text-xs bg-teal-950 text-teal-300 px-2 py-0.5 rounded-full border border-teal-700/60 font-semibold">
                  v21.0
                </span>
              </h1>
              <p className="text-xs text-slate-400 mt-0.5 font-mono">
                Hardware-Assisted USB OTG-HID Emulation, Pattern Guessing &amp; OCSF 3002 Forensics
              </p>
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2.5">
          <button
            onClick={fetchStatusAndSessions}
            disabled={loading || actionLoading}
            className="px-3.5 py-1.5 rounded-lg bg-base-800 hover:bg-base-700 border border-base-600/80 text-xs font-mono text-slate-300 flex items-center gap-1.5 transition-all"
          >
            <span>↻</span> Refresh Telemetry
          </button>
        </div>
      </div>

      {/* Error / Success Notifications */}
      {error && (
        <div className="p-3 bg-rose-950/70 border border-rose-600/80 text-rose-200 text-xs font-mono rounded-xl flex items-center justify-between">
          <span>⚠️ {error}</span>
          <button onClick={() => setError('')} className="text-rose-400 hover:text-rose-200 font-bold">×</button>
        </div>
      )}
      {successMsg && (
        <div className="p-3 bg-emerald-950/70 border border-emerald-600/80 text-emerald-200 text-xs font-mono rounded-xl flex items-center justify-between">
          <span>✓ {successMsg}</span>
          <button onClick={() => setSuccessMsg('')} className="text-emerald-400 hover:text-emerald-200 font-bold">×</button>
        </div>
      )}

      {/* KPI Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-base-900 border border-base-700/80 p-4 rounded-xl shadow-sm">
          <div className="text-[11px] font-mono text-slate-400 uppercase">Active Sessions</div>
          <div className="text-2xl font-bold font-mono text-teal-400 mt-1">
            {engineStatus?.active_sessions_count ?? 0}
          </div>
          <div className="text-[10px] text-slate-500 mt-0.5">Total: {engineStatus?.total_forensic_sessions ?? 0}</div>
        </div>

        <div className="bg-base-900 border border-base-700/80 p-4 rounded-xl shadow-sm">
          <div className="text-[11px] font-mono text-slate-400 uppercase">Total Attempts Evaluated</div>
          <div className="text-2xl font-bold font-mono text-cyan-400 mt-1">
            {engineStatus?.total_passcode_attempts ?? 0}
          </div>
          <div className="text-[10px] text-slate-500 mt-0.5">Zero Plaintext Storage</div>
        </div>

        <div className="bg-base-900 border border-base-700/80 p-4 rounded-xl shadow-sm">
          <div className="text-[11px] font-mono text-slate-400 uppercase">Lockout Incidents Throttled</div>
          <div className="text-2xl font-bold font-mono text-amber-400 mt-1">
            {engineStatus?.lockout_events_detected ?? 0}
          </div>
          <div className="text-[10px] text-slate-500 mt-0.5">Adaptive 30s Cooldowns</div>
        </div>

        <div className="bg-base-900 border border-base-700/80 p-4 rounded-xl shadow-sm">
          <div className="text-[11px] font-mono text-slate-400 uppercase">Forensics Protocol</div>
          <div className="text-sm font-bold font-mono text-emerald-400 mt-2 truncate">
            OCSF Class 3002
          </div>
          <div className="text-[10px] text-slate-500 mt-0.5">Teensy/RP2040 OTG-HID</div>
        </div>
      </div>

      {/* Main Two-Column Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Device Probe & Session Configuration (5 cols) */}
        <div className="lg:col-span-5 space-y-6">
          {/* Hardware Discovery Card */}
          <div className="bg-base-900 border border-base-700/80 rounded-2xl p-5 shadow-lg">
            <h2 className="text-sm font-bold text-slate-200 font-mono flex items-center gap-2 mb-3">
              <span className="text-teal-400">🔌</span> Physical USB Subsystem Discovery
            </h2>
            <div className="space-y-3 font-mono text-xs">
              <div>
                <label className="text-slate-400 block mb-1 text-[11px]">Target Port / Bus Path</label>
                <div className="flex items-center gap-2 w-full">
                  <select
                    value={usbPort}
                    onChange={(e) => setUsbPort(e.target.value)}
                    className="flex-1 min-w-0 w-full bg-base-950 border border-base-700 rounded-lg px-2.5 py-1.5 text-slate-200 text-xs focus:outline-none focus:border-teal-500 truncate"
                  >
                    <option value="/dev/bus/usb/001/004">/dev/bus/usb/001/004 (Google Pixel 8 Pro - VID 0x18d1)</option>
                    <option value="/dev/bus/usb/002/001">/dev/bus/usb/002/001 (Apple iPhone 15 Pro - VID 0x05ac)</option>
                    <option value="/dev/bus/usb/003/002">/dev/bus/usb/003/002 (Samsung Galaxy S24 - VID 0x04e8)</option>
                    <option value="COM3_SERIAL_OTG">COM3 (RP2040 OTG-HID Microcontroller)</option>
                  </select>
                  <button
                    onClick={handleProbeDevice}
                    disabled={actionLoading}
                    className="shrink-0 px-3.5 py-1.5 bg-teal-950 hover:bg-teal-900 border border-teal-600/60 text-teal-300 font-bold rounded-lg transition-all text-xs"
                  >
                    Probe
                  </button>
                </div>
              </div>

              {probedDevice && (
                <div className="bg-base-950/80 border border-base-800 p-3.5 rounded-xl space-y-1.5 text-[11px]">
                  <div className="flex justify-between">
                    <span className="text-slate-500">Device:</span>
                    <span className="text-slate-200 font-bold">{probedDevice.manufacturer} {probedDevice.model}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Serial No:</span>
                    <span className="text-teal-400 font-mono font-bold">{probedDevice.serial_number}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Hardware UDID:</span>
                    <span className="text-slate-400 font-mono truncate max-w-[180px]">{probedDevice.udid}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">OS Build:</span>
                    <span className="text-slate-300">{probedDevice.os_version}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Battery Level:</span>
                    <span className="text-emerald-400 font-bold">{probedDevice.battery_level}% (USB Powered)</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">USB VID/PID:</span>
                    <span className="text-slate-400">{probedDevice.usb_vid}:{probedDevice.usb_pid}</span>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* New Session Config Card */}
          <div className="bg-base-900 border border-base-700/80 rounded-2xl p-5 shadow-lg">
            <h2 className="text-sm font-bold text-slate-200 font-mono flex items-center gap-2 mb-3">
              <span className="text-amber-400">🔑</span> Launch Forensic Audit Session
            </h2>
            <form onSubmit={handleStartSession} className="space-y-3 font-mono text-xs">
              <div>
                <label className="text-slate-400 block mb-1 text-[11px]">Passcode Attack Vector</label>
                <select
                  value={passcodeType}
                  onChange={(e) => {
                    setPasscodeType(e.target.value)
                    if (e.target.value === 'PATTERN') setTargetSecret('01258')
                    else if (e.target.value === 'PIN_4') setTargetSecret('1994')
                    else if (e.target.value === 'PIN_6') setTargetSecret('199401')
                    else setTargetSecret('Admin!1')
                  }}
                  className="w-full bg-base-950 border border-base-700 rounded-lg px-2.5 py-1.5 text-slate-200 text-xs focus:outline-none focus:border-amber-500"
                >
                  <option value="PATTERN">3x3 Android Gesture Pattern (Factorial Permutations)</option>
                  <option value="PIN_4">4-Digit Numeric PIN (Statistical / Probabilistic)</option>
                  <option value="PIN_6">6-Digit Numeric PIN (Deep Entropy)</option>
                  <option value="ALPHANUMERIC">Alphanumeric Heuristic (Leetspeak Mutation)</option>
                </select>
              </div>

              <div>
                <label className="text-slate-400 block mb-1 text-[11px]">Target Mock Secret (Verification Key)</label>
                <input
                  type="text"
                  value={targetSecret}
                  onChange={(e) => setTargetSecret(e.target.value)}
                  placeholder="e.g. 1994 or 01258"
                  className="w-full bg-base-950 border border-base-700 rounded-lg px-2.5 py-1.5 text-slate-200 text-xs focus:outline-none focus:border-amber-500"
                />
                <span className="text-[10px] text-slate-500 mt-0.5 block">
                  Simulates the target device's physical lock key for evaluation.
                </span>
              </div>

              <button
                type="submit"
                disabled={actionLoading}
                className="w-full mt-2 py-2 bg-gradient-to-r from-teal-600 to-cyan-600 hover:from-teal-500 hover:to-cyan-500 text-slate-950 font-bold rounded-lg transition-all shadow-md font-mono text-xs"
              >
                Start Physical Forensic Session
              </button>
            </form>
          </div>
        </div>

        {/* Right Column: Live Console & Controls (7 cols) */}
        <div className="lg:col-span-7 space-y-6">
          {/* Active Console Panel */}
          {activeSession ? (
            <div className="space-y-4">
              <MobileAuditConsole session={activeSession} onAttemptUpdated={() => fetchStatusAndSessions()} />

              {/* Action Buttons */}
              <div className="flex flex-wrap items-center gap-3">
                <button
                  onClick={handleRunBatchAudit}
                  disabled={actionLoading}
                  className="flex-1 px-4 py-2.5 bg-gradient-to-r from-teal-600/90 to-emerald-600/90 hover:from-teal-500 hover:to-emerald-500 text-slate-950 font-bold text-xs font-mono rounded-xl shadow-md transition-all flex items-center justify-center gap-2"
                >
                  <span>⚡</span> Run Automated Batch Audit (15 Steps)
                </button>
                <button
                  onClick={handleSingleStepAttempt}
                  disabled={actionLoading}
                  className="px-4 py-2.5 bg-base-800 hover:bg-base-700 border border-base-600 text-slate-200 font-bold text-xs font-mono rounded-xl transition-all"
                >
                  Step 1 Guess
                </button>
                <button
                  onClick={handleTerminateSession}
                  disabled={actionLoading}
                  className="px-4 py-2.5 bg-rose-950/60 hover:bg-rose-900 border border-rose-600/60 text-rose-300 font-bold text-xs font-mono rounded-xl transition-all"
                >
                  Terminate
                </button>
              </div>
            </div>
          ) : (
            <div className="bg-base-900 border border-base-700/80 rounded-2xl p-12 text-center text-slate-500 font-mono text-sm">
              <span className="text-4xl block mb-3">📱</span>
              No active forensic session selected. Launch a new session on the left panel.
            </div>
          )}
        </div>
      </div>

      {/* Historical Sessions Table */}
      <div className="bg-base-900 border border-base-700/80 rounded-2xl p-6 shadow-xl">
        <h2 className="text-sm font-bold text-slate-200 font-mono flex items-center gap-2 mb-4">
          <span className="text-teal-400">📜</span> Multi-Tenant Forensic Session Registry (Neon RLS Isolated)
        </h2>
        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-xs text-slate-300">
            <thead className="bg-base-950/80 text-slate-400 uppercase text-[10px] border-b border-base-800">
              <tr>
                <th className="py-2.5 px-3">Session ID</th>
                <th className="py-2.5 px-3">Device / Model</th>
                <th className="py-2.5 px-3">Serial / UDID</th>
                <th className="py-2.5 px-3">Vector</th>
                <th className="py-2.5 px-3">Entropy</th>
                <th className="py-2.5 px-3">Attempts</th>
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-base-800/60">
              {sessions.length > 0 ? (
                sessions.map((s) => (
                  <tr
                    key={s.session_id}
                    className={`hover:bg-base-800/40 transition-colors ${
                      activeSession?.session_id === s.session_id ? 'bg-teal-950/20 border-l-2 border-teal-400' : ''
                    }`}
                  >
                    <td className="py-3 px-3 font-semibold text-slate-200">{s.session_id.slice(0, 8)}...</td>
                    <td className="py-3 px-3">{s.device_name} {s.device_model}</td>
                    <td className="py-3 px-3 text-slate-400">{s.serial_number}</td>
                    <td className="py-3 px-3">
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-base-950 border border-base-800 text-amber-400">
                        {s.passcode_type}
                      </span>
                    </td>
                    <td className="py-3 px-3 text-amber-400 font-bold">{s.max_estimated_entropy} bits</td>
                    <td className="py-3 px-3">{s.total_attempts_count || 0}</td>
                    <td className="py-3 px-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          s.is_unlocked || s.status === 'COMPLETED'
                            ? 'bg-emerald-950 text-emerald-300 border border-emerald-700/60'
                            : s.status === 'LOCKED_OUT'
                            ? 'bg-rose-950 text-rose-300 border border-rose-700/60'
                            : 'bg-teal-950 text-teal-300 border border-teal-700/60'
                        }`}
                      >
                        {s.is_unlocked ? 'UNLOCKED' : s.status}
                      </span>
                    </td>
                    <td className="py-3 px-3">
                      <button
                        onClick={() => setActiveSession(s)}
                        className="px-2.5 py-1 rounded bg-base-800 hover:bg-base-700 border border-base-700 text-slate-300 text-[11px] transition-all"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={8} className="py-6 text-center text-slate-500">
                    No forensic sessions recorded. Launch a new physical audit session above.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
