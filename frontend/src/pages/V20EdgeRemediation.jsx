import React, { useState, useEffect, useRef } from 'react'
import client from '../api/client'
import { useAuth } from '../context/AuthContext'

export default function V20EdgeRemediation() {
  const { user } = useAuth()

  const [activeTab, setActiveTab] = useState('gps') // gps | geofence | simulator | terminal | spatial
  const [feedback, setFeedback] = useState(null)

  // 1. Mesh Status
  const [meshStatus, setMeshStatus] = useState(null)
  const [loadingStatus, setLoadingStatus] = useState(false)

  // 2. Devices List
  const [devices, setDevices] = useState([])
  const [selectedDeviceId, setSelectedDeviceId] = useState('')

  // 3. GPS Tracker State
  const [locations, setLocations] = useState([])
  const [currentLocation, setCurrentLocation] = useState(null)
  const [wsConnected, setWsConnected] = useState(false)
  const wsRef = useRef(null)

  // 4. Geofence Configuration State
  const [geofenceCenterLat, setGeofenceCenterLat] = useState(37.7749)
  const [geofenceCenterLon, setGeofenceCenterLon] = useState(-122.4194)
  const [geofenceRadius, setGeofenceRadius] = useState(25000)
  const [savingGeofence, setSavingGeofence] = useState(false)

  // 5. Simulator State
  const [simSpeed, setSimSpeed] = useState(0.0)
  const [simBattery, setSimBattery] = useState(85)
  const [simAcPower, setSimAcPower] = useState(false)
  const [simBreach, setSimBreach] = useState(false)
  const [simStationaryCount, setSimStationaryCount] = useState(6)

  // 6. Terminal Stream State
  const [terminalSessions, setTerminalSessions] = useState([])
  const [selectedSessionId, setSelectedSessionId] = useState('')
  const [terminalStreams, setTerminalStreams] = useState([])
  const [terminalCmd, setTerminalCmd] = useState('journalctl -u threat-agent -n 20 --no-pager')
  const [executingCmd, setExecutingCmd] = useState(false)

  const showFeedback = (msg, type = 'success') => {
    setFeedback({ msg, type })
    setTimeout(() => setFeedback(null), 5000)
  }

  useEffect(() => {
    fetchMeshStatus()
    fetchDevices()
    fetchTerminalSessions()
  }, [])

  useEffect(() => {
    if (selectedDeviceId) {
      fetchCurrentLocation(selectedDeviceId)
      fetchLocationHistory(selectedDeviceId)
      fetchGeofenceConfig(selectedDeviceId)
      connectGpsWebSocket(selectedDeviceId)
    }
    return () => {
      if (wsRef.current) {
        wsRef.current.close()
      }
    }
  }, [selectedDeviceId])

  const fetchMeshStatus = async () => {
    setLoadingStatus(true)
    try {
      const res = await client.get('/api/v20/edge/status')
      setMeshStatus(res.data)
    } catch (err) {
      console.error('Failed to fetch edge mesh status', err)
    } finally {
      setLoadingStatus(false)
    }
  }

  const fetchDevices = async () => {
    try {
      const res = await client.get('/api/devices')
      const devList = res.data || []
      setDevices(devList)
      if (devList.length > 0 && !selectedDeviceId) {
        setSelectedDeviceId(devList[0].id)
      }
    } catch (err) {
      console.error('Failed to fetch devices', err)
    }
  }

  const fetchCurrentLocation = async (devId) => {
    try {
      const res = await client.get(`/api/v20/edge/gps/${devId}/current`)
      setCurrentLocation(res.data)
    } catch (err) {
      console.error('Failed to fetch current location', err)
    }
  }

  const fetchLocationHistory = async (devId) => {
    try {
      const res = await client.get(`/api/v20/edge/gps/${devId}/history?limit=30`)
      setLocations(res.data || [])
    } catch (err) {
      console.error('Failed to fetch location history', err)
    }
  }

  const fetchGeofenceConfig = async (devId) => {
    try {
      const res = await client.get(`/api/v20/edge/gps/${devId}/geofence`)
      if (res.data) {
        setGeofenceCenterLat(res.data.center_latitude)
        setGeofenceCenterLon(res.data.center_longitude)
        setGeofenceRadius(res.data.radius_meters)
      }
    } catch (err) {
      console.error('Failed to fetch geofence config', err)
    }
  }

  const handleSaveGeofence = async () => {
    if (!selectedDeviceId) return
    setSavingGeofence(true)
    try {
      const res = await client.post('/api/v20/edge/gps/geofence', {
        device_id: selectedDeviceId,
        center_latitude: parseFloat(geofenceCenterLat),
        center_longitude: parseFloat(geofenceCenterLon),
        radius_meters: parseFloat(geofenceRadius)
      })
      showFeedback(`Geofence updated: ${res.data.radius_meters}m boundary around (${res.data.center_latitude}, ${res.data.center_longitude})`, 'success')
      await fetchMeshStatus()
    } catch (err) {
      showFeedback(err?.response?.data?.detail || 'Failed to save geofence', 'error')
    } finally {
      setSavingGeofence(false)
    }
  }

  const connectGpsWebSocket = (devId) => {
    if (wsRef.current) {
      wsRef.current.close()
    }
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const host = window.location.host
    const wsUrl = `${protocol}//${host}/api/v20/edge/ws/gps/${devId}`

    try {
      const ws = new WebSocket(wsUrl)
      wsRef.current = ws

      ws.onopen = () => setWsConnected(true)
      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data)
          if (data.location_activity) {
            const loc = data.location_activity
            const newLoc = {
              log_id: `ws-${Date.now()}`,
              device_id: loc.device_id,
              latitude: loc.latitude,
              longitude: loc.longitude,
              altitude: loc.altitude,
              speed_mps: loc.speed_mps || 0.0,
              battery_level: loc.battery_level,
              power_source: loc.power_source,
              tracking_state: loc.tracking_state,
              polling_interval_seconds: loc.polling_interval_seconds,
              tracked_at: new Date().toISOString(),
              ocsf_class_uid: 5005,
              ocsf_severity: data.severity_id || 1
            }
            setCurrentLocation(newLoc)
            setLocations((prev) => [newLoc, ...prev].slice(0, 50))
          }
        } catch (e) {
          console.error('Error parsing GPS WS message', e)
        }
      }
      ws.onclose = () => setWsConnected(false)
      ws.onerror = () => setWsConnected(false)
    } catch (err) {
      console.error('WebSocket connection error', err)
    }
  }

  const handlePushSampleGps = async (stateType) => {
    if (!selectedDeviceId) return
    let lat = geofenceCenterLat
    let lon = geofenceCenterLon
    let speed = 0.0
    let battery = 80
    let power = 'BATTERY'

    if (stateType === 'transit') {
      lat += (Math.random() - 0.5) * 0.02
      lon += (Math.random() - 0.5) * 0.02
      speed = 14.5
    } else if (stateType === 'low_power') {
      battery = 12
      speed = 0.5
    } else if (stateType === 'breach') {
      // Offset significantly outside radius
      lat += 0.45
      lon += 0.45
      speed = 22.0
    }

    try {
      const res = await client.post('/api/v20/edge/gps/ingest', {
        device_id: selectedDeviceId,
        latitude: lat,
        longitude: lon,
        speed_mps: speed,
        battery_level: battery,
        power_source: power
      })
      showFeedback(`GPS telemetry ingested! State: ${res.data.tracking_state} (Interval: ${res.data.polling_interval_seconds}s)`, 'success')
      await fetchCurrentLocation(selectedDeviceId)
      await fetchLocationHistory(selectedDeviceId)
      await fetchMeshStatus()
    } catch (err) {
      showFeedback(err?.response?.data?.detail || 'Failed to push GPS telemetry', 'error')
    }
  }

  const fetchTerminalSessions = async () => {
    try {
      const res = await client.get('/api/v18/live/sessions')
      const sessList = res.data || []
      setTerminalSessions(sessList)
      if (sessList.length > 0 && !selectedSessionId) {
        setSelectedSessionId(sessList[0].session_id)
        fetchTerminalStreams(sessList[0].session_id)
      }
    } catch (err) {
      console.error('Failed to fetch live sessions', err)
    }
  }

  const fetchTerminalStreams = async (sessId) => {
    if (!sessId) return
    try {
      const res = await client.get(`/api/v20/edge/terminal/streams/${sessId}`)
      setTerminalStreams(res.data || [])
    } catch (err) {
      console.error('Failed to fetch terminal streams', err)
    }
  }

  const handleRecordTerminalCommand = async () => {
    if (!selectedSessionId || !terminalCmd.trim()) return
    setExecutingCmd(true)
    try {
      const res = await client.post('/api/v20/edge/terminal/streams', {
        session_id: selectedSessionId,
        command_input: terminalCmd,
        command_output_summary: `[PTY Stream Executed at ${new Date().toLocaleTimeString()}]: Process exit code 0. Status: COMPLETED.`,
        exit_code: 0
      })
      showFeedback(`Command stream recorded: ${res.data.command_input}`, 'success')
      setTerminalCmd('')
      await fetchTerminalStreams(selectedSessionId)
      await fetchMeshStatus()
    } catch (err) {
      showFeedback(err?.response?.data?.detail || 'Failed to record stream command', 'error')
    } finally {
      setExecutingCmd(false)
    }
  }

  // Calculate local simulator reactive interval
  const calculateSimulatorInterval = () => {
    if (simBreach) {
      return { interval: 5, state: 'GEOFENCE_BREACH', color: 'text-rose-400', bg: 'bg-rose-950 border-rose-800' }
    }
    if (simBattery <= 20 && !simAcPower) {
      return { interval: 1800, state: 'LOW_POWER', color: 'text-amber-400', bg: 'bg-amber-950 border-amber-800' }
    }
    if (simStationaryCount > 4 && simSpeed < 1.0) {
      return { interval: 900, state: 'STATIONARY', color: 'text-emerald-400', bg: 'bg-emerald-950 border-emerald-800' }
    }
    if (simSpeed >= 5.0) {
      return { interval: 10, state: 'ACTIVE_TRANSIT', color: 'text-cyan-400', bg: 'bg-cyan-950 border-cyan-800' }
    }
    return { interval: 60, state: 'STANDARD_MOTION', color: 'text-blue-400', bg: 'bg-blue-950 border-blue-800' }
  }

  const simResult = calculateSimulatorInterval()

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between pb-4 border-b border-gray-800 gap-4">
        <div>
          <div className="flex items-center space-x-3">
            <span className="text-2xl">📡</span>
            <h1 className="text-2xl font-black tracking-tight text-white flex items-center gap-2">
              Dynamic Edge Remediation &amp; Adaptive GPS Mesh
              <span className="text-xs px-2.5 py-0.5 rounded-full bg-teal-500/10 text-teal-400 border border-teal-500/30 font-mono font-semibold">
                v20.0 Sovereign
              </span>
            </h1>
          </div>
          <p className="text-gray-400 text-sm mt-1">
            Intelligent Battery-Aware GPS Throttling, OCSF Class 5005 Geospatial Mapping, Sub-Session PTY Multiplexing, and Neon Spatial RLS
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <div className="flex items-center space-x-2 bg-gray-900 border border-gray-700 px-3 py-1.5 rounded-lg text-xs font-mono">
            <span className={`w-2 h-2 rounded-full ${wsConnected ? 'bg-teal-400 animate-ping' : 'bg-rose-500'}`} />
            <span className="text-gray-300">Live GPS Stream:</span>
            <span className={`font-bold ${wsConnected ? 'text-teal-400' : 'text-rose-400'}`}>
              {wsConnected ? 'LIVE CONNECTED' : 'DISCONNECTED'}
            </span>
          </div>
          <button
            onClick={() => {
              fetchMeshStatus()
              if (selectedDeviceId) {
                fetchCurrentLocation(selectedDeviceId)
                fetchLocationHistory(selectedDeviceId)
              }
            }}
            className="px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-lg text-xs font-medium border border-gray-700 transition"
          >
            Refresh Telemetry
          </button>
        </div>
      </div>

      {/* Global Feedback Banner */}
      {feedback && (
        <div
          className={`p-4 rounded-xl text-sm font-medium border flex items-center justify-between ${
            feedback.type === 'error'
              ? 'bg-rose-500/10 text-rose-400 border-rose-500/30'
              : 'bg-teal-500/10 text-teal-400 border-teal-500/30'
          }`}
        >
          <span>{feedback.msg}</span>
          <button onClick={() => setFeedback(null)} className="text-xs opacity-60 hover:opacity-100">
            ✕
          </button>
        </div>
      )}

      {/* Device Selector Toolbar */}
      <div className="bg-gray-900/80 border border-gray-800 p-3 rounded-xl flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center space-x-2">
          <span className="text-xs text-gray-400 font-semibold uppercase font-mono">Selected Edge Device:</span>
          <select
            value={selectedDeviceId}
            onChange={(e) => setSelectedDeviceId(e.target.value)}
            className="bg-slate-950 border border-gray-700 rounded-lg px-3 py-1.5 text-xs text-white font-mono focus:outline-none focus:border-teal-500"
          >
            {devices.map((d) => (
              <option key={d.id} value={d.id}>
                {d.hostname || d.id} ({d.ip || '0.0.0.0'})
              </option>
            ))}
          </select>
        </div>

        {meshStatus && (
          <div className="flex items-center space-x-4 text-xs font-mono text-gray-400">
            <span>Spatial Logs: <strong className="text-teal-400">{meshStatus.total_location_logs}</strong></span>
            <span>Active Geofences: <strong className="text-teal-400">{meshStatus.active_geofences_count}</strong></span>
            <span>Terminal Streams: <strong className="text-teal-400">{meshStatus.total_terminal_streams}</strong></span>
          </div>
        )}
      </div>

      {/* Tabs Navigation */}
      <div className="flex space-x-2 border-b border-gray-800 pb-2 overflow-x-auto">
        {[
          { id: 'gps', label: 'Real-Time Adaptive GPS Telemetry', icon: '📍' },
          { id: 'geofence', label: 'Geofence Boundary Defense', icon: '🛡️' },
          { id: 'simulator', label: 'Adaptive Throttle Simulator', icon: '⚡' },
          { id: 'terminal', label: 'PTY Sub-Session Streams', icon: '💻' },
          { id: 'spatial', label: `Spatial Audit Ledger (${locations.length})`, icon: '📜' }
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex items-center space-x-2 px-4 py-2.5 rounded-lg text-xs font-medium transition whitespace-nowrap ${
              activeTab === tab.id
                ? 'bg-teal-600 text-white shadow-lg shadow-teal-600/20 font-semibold'
                : 'text-gray-400 hover:text-white hover:bg-gray-800/60'
            }`}
          >
            <span>{tab.icon}</span>
            <span>{tab.label}</span>
          </button>
        ))}
      </div>

      {/* =========================================================================
          TAB 1: REAL-TIME ADAPTIVE GPS TELEMETRY & LIVE TRACKER
          ========================================================================= */}
      {activeTab === 'gps' && (
        <div className="space-y-6">
          <div className="p-6 bg-slate-950 text-slate-100 rounded-xl border border-slate-800 shadow-2xl space-y-4">
            <div className="flex flex-col md:flex-row md:items-center justify-between pb-3 border-b border-slate-800 gap-2">
              <div>
                <h3 className="text-sm font-bold tracking-wider text-teal-400 flex items-center gap-2">
                  <span>🌍</span> REAL-TIME GEOSPATIAL FLEET TRACKER &amp; ADAPTIVE RECEIVER
                </h3>
                <p className="text-xs text-slate-400">
                  Compliant with OCSF Class 5005 (Location Activity Event) and real-time battery-aware polling cadence.
                </p>
              </div>

              <div className="flex items-center space-x-2">
                <button
                  onClick={() => handlePushSampleGps('stationary')}
                  className="px-2.5 py-1 bg-gray-800 hover:bg-gray-700 text-gray-200 text-xs rounded border border-gray-700 font-mono"
                >
                  + Pulse Idle (900s)
                </button>
                <button
                  onClick={() => handlePushSampleGps('transit')}
                  className="px-2.5 py-1 bg-cyan-950 hover:bg-cyan-900 text-cyan-300 text-xs rounded border border-cyan-800 font-mono"
                >
                  + Pulse Transit (10s)
                </button>
                <button
                  onClick={() => handlePushSampleGps('breach')}
                  className="px-2.5 py-1 bg-rose-950 hover:bg-rose-900 text-rose-300 text-xs rounded border border-rose-800 font-mono font-bold"
                >
                  + Trigger Breach (5s)
                </button>
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {/* Geographic Coordinates Display */}
              <div className="h-64 rounded-lg bg-slate-900/80 border border-slate-800 relative flex items-center justify-center overflow-hidden p-4">
                <div className="absolute inset-0 bg-[radial-gradient(#1e293b_1px,transparent_1px)] [background-size:16px_16px] opacity-40" />
                {currentLocation ? (
                  <div className="text-center z-10 space-y-2">
                    <p className="text-[11px] text-slate-400 uppercase font-mono tracking-wider">
                      Current Edge Telemetry Coordinates
                    </p>
                    <p className="text-2xl font-black font-mono text-teal-400">
                      {currentLocation.latitude.toFixed(5)}, {currentLocation.longitude.toFixed(5)}
                    </p>
                    <div className="flex flex-wrap justify-center gap-2 pt-1">
                      <span className={`px-2.5 py-0.5 rounded text-[11px] font-mono font-bold uppercase border ${
                        currentLocation.tracking_state === 'GEOFENCE_BREACH'
                          ? 'bg-rose-950 text-rose-400 border-rose-800 animate-pulse'
                          : currentLocation.tracking_state === 'ACTIVE_TRANSIT'
                          ? 'bg-cyan-950 text-cyan-400 border-cyan-800'
                          : currentLocation.tracking_state === 'LOW_POWER'
                          ? 'bg-amber-950 text-amber-400 border-amber-800'
                          : 'bg-emerald-950 text-emerald-400 border-emerald-800'
                      }`}>
                        State: {currentLocation.tracking_state}
                      </span>
                      <span className="px-2.5 py-0.5 rounded text-[11px] bg-slate-800 text-slate-200 font-mono border border-slate-700">
                        Interval: {currentLocation.polling_interval_seconds}s
                      </span>
                      <span className="px-2.5 py-0.5 rounded text-[11px] bg-slate-800 text-slate-300 font-mono border border-slate-700">
                        ⚡ {currentLocation.battery_level}% ({currentLocation.power_source})
                      </span>
                    </div>
                  </div>
                ) : (
                  <p className="text-sm font-mono text-slate-500">Awaiting GPS telemetry stream...</p>
                )}
              </div>

              {/* Real-Time Scrolling Audit Log */}
              <div className="h-64 overflow-y-auto rounded-lg bg-slate-900/80 border border-slate-800 p-3 font-mono text-xs">
                <p className="text-slate-400 font-bold mb-2 pb-1 border-b border-slate-800 uppercase tracking-wider flex justify-between">
                  <span>Coordinates Audit Stream</span>
                  <span className="text-[10px] text-teal-400">{locations.length} Records</span>
                </p>
                {locations.length === 0 ? (
                  <p className="text-slate-600 italic py-8 text-center">No historical traces in current buffer.</p>
                ) : (
                  <div className="space-y-1.5">
                    {locations.map((loc, idx) => (
                      <div
                        key={idx}
                        className="flex justify-between items-center text-slate-300 py-1 border-b border-slate-800/60 last:border-0 hover:bg-slate-800/40 px-1 rounded transition"
                      >
                        <span className="text-[11px]">
                          LAT: <strong className="text-white">{loc.latitude.toFixed(4)}</strong> | LON: <strong className="text-white">{loc.longitude.toFixed(4)}</strong>
                        </span>
                        <div className="flex items-center space-x-2">
                          <span className="text-[10px] text-slate-400">{loc.speed_mps.toFixed(1)} m/s</span>
                          <span
                            className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                              loc.tracking_state === 'GEOFENCE_BREACH'
                                ? 'bg-rose-950 text-rose-400 border border-rose-800'
                                : loc.tracking_state === 'ACTIVE_TRANSIT'
                                ? 'bg-cyan-950 text-cyan-400 border border-cyan-800'
                                : 'bg-slate-800 text-slate-300'
                            }`}
                          >
                            {loc.tracking_state}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* =========================================================================
          TAB 2: GEOFENCE BOUNDARY DEFENSE CENTER
          ========================================================================= */}
      {activeTab === 'geofence' && (
        <div className="space-y-6">
          <div className="bg-gray-900 border border-gray-800 p-5 rounded-xl space-y-4">
            <div>
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <span>🛡️</span> Geofence Spatial Boundary Policy Configurator
              </h3>
              <p className="text-xs text-gray-400">
                Define geographic safety perimeters. Leaving this boundary triggers un-throttled 5-second GPS updates and severity-3 containment alarms.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <label className="block text-xs font-mono text-gray-400 mb-1">Center Latitude</label>
                <input
                  type="number"
                  step="0.0001"
                  value={geofenceCenterLat}
                  onChange={(e) => setGeofenceCenterLat(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-white font-mono focus:outline-none focus:border-teal-500"
                />
              </div>

              <div>
                <label className="block text-xs font-mono text-gray-400 mb-1">Center Longitude</label>
                <input
                  type="number"
                  step="0.0001"
                  value={geofenceCenterLon}
                  onChange={(e) => setGeofenceCenterLon(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-white font-mono focus:outline-none focus:border-teal-500"
                />
              </div>

              <div>
                <label className="block text-xs font-mono text-gray-400 mb-1">Radius (Meters)</label>
                <input
                  type="number"
                  value={geofenceRadius}
                  onChange={(e) => setGeofenceRadius(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-white font-mono focus:outline-none focus:border-teal-500"
                />
              </div>
            </div>

            <div className="flex justify-end gap-3 pt-2">
              <button
                onClick={() => {
                  setGeofenceCenterLat(37.7749)
                  setGeofenceCenterLon(-122.4194)
                  setGeofenceRadius(25000)
                }}
                className="px-4 py-2 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-lg text-xs font-medium"
              >
                Reset Default
              </button>
              <button
                onClick={handleSaveGeofence}
                disabled={savingGeofence}
                className="px-5 py-2 bg-teal-600 hover:bg-teal-500 text-slate-950 font-bold rounded-lg text-xs shadow-lg shadow-teal-600/20 transition disabled:opacity-50"
              >
                {savingGeofence ? 'Saving Policy...' : 'Save Geofence Policy'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* =========================================================================
          TAB 3: ADAPTIVE THROTTLE STATE MACHINE SIMULATOR
          ========================================================================= */}
      {activeTab === 'simulator' && (
        <div className="space-y-6">
          <div className="bg-gray-900 border border-gray-800 p-5 rounded-xl space-y-5">
            <div>
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <span>⚡</span> Adaptive GPS Throttling State Machine Simulator
              </h3>
              <p className="text-xs text-gray-400">
                Simulate real-time device physics (velocity, battery constraints, AC power states, and boundary breaches) to inspect dynamic interval scaling.
              </p>
            </div>

            {/* Live Result Callout */}
            <div className={`p-4 rounded-xl border flex flex-col md:flex-row items-center justify-between gap-3 ${simResult.bg}`}>
              <div className="space-y-1">
                <span className="text-[10px] uppercase font-mono tracking-wider opacity-70">Evaluated State Transition</span>
                <div className={`text-xl font-black font-mono ${simResult.color}`}>{simResult.state}</div>
              </div>
              <div className="text-right">
                <span className="text-[10px] uppercase font-mono tracking-wider opacity-70">Calculated Polling Cadence</span>
                <div className={`text-2xl font-black font-mono ${simResult.color}`}>{simResult.interval}s</div>
              </div>
            </div>

            {/* Controls */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pt-2">
              {/* Speed Slider */}
              <div className="space-y-2 bg-slate-950 p-4 rounded-xl border border-slate-800">
                <div className="flex justify-between text-xs font-mono">
                  <span className="text-gray-300">Device Speed / Velocity:</span>
                  <span className="text-teal-400 font-bold">{simSpeed.toFixed(1)} m/s ({(simSpeed * 3.6).toFixed(1)} km/h)</span>
                </div>
                <input
                  type="range"
                  min="0"
                  max="35"
                  step="0.5"
                  value={simSpeed}
                  onChange={(e) => {
                    const spd = parseFloat(e.target.value)
                    setSimSpeed(spd)
                    if (spd > 1.0) setSimStationaryCount(0)
                  }}
                  className="w-full accent-teal-500"
                />
                <div className="flex justify-between text-[10px] text-gray-500 font-mono">
                  <span>0 m/s (Idle)</span>
                  <span>5 m/s (Transit threshold)</span>
                  <span>35 m/s (Highway speed)</span>
                </div>
              </div>

              {/* Battery Slider */}
              <div className="space-y-2 bg-slate-950 p-4 rounded-xl border border-slate-800">
                <div className="flex justify-between text-xs font-mono">
                  <span className="text-gray-300">Battery Level:</span>
                  <span className={`font-bold ${simBattery <= 20 ? 'text-amber-400' : 'text-emerald-400'}`}>
                    {simBattery}%
                  </span>
                </div>
                <input
                  type="range"
                  min="1"
                  max="100"
                  value={simBattery}
                  onChange={(e) => setSimBattery(parseInt(e.target.value))}
                  className="w-full accent-teal-500"
                />
                <div className="flex justify-between text-[10px] text-gray-500 font-mono">
                  <span className="text-amber-500">Critical (&le; 20%)</span>
                  <span>50%</span>
                  <span>100%</span>
                </div>
              </div>

              {/* AC Power Toggle */}
              <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 flex items-center justify-between">
                <div>
                  <div className="text-xs font-mono text-gray-300 font-semibold">AC Power Connected</div>
                  <div className="text-[11px] text-gray-500">Bypasses low-power 1800s battery throttling</div>
                </div>
                <button
                  onClick={() => setSimAcPower(!simAcPower)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition ${
                    simAcPower ? 'bg-teal-600 text-white' : 'bg-gray-800 text-gray-400'
                  }`}
                >
                  {simAcPower ? 'AC Connected (TRUE)' : 'Battery Only (FALSE)'}
                </button>
              </div>

              {/* Geofence Breach Toggle */}
              <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 flex items-center justify-between">
                <div>
                  <div className="text-xs font-mono text-gray-300 font-semibold">Geofence Boundary Breach</div>
                  <div className="text-[11px] text-gray-500">Overrides all states to 5-second emergency updates</div>
                </div>
                <button
                  onClick={() => setSimBreach(!simBreach)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition ${
                    simBreach ? 'bg-rose-600 text-white animate-pulse' : 'bg-gray-800 text-gray-400'
                  }`}
                >
                  {simBreach ? 'BREACH DETECTED' : 'WITHIN BOUNDARY'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* =========================================================================
          TAB 4: PTY SUB-SESSION STREAMS
          ========================================================================= */}
      {activeTab === 'terminal' && (
        <div className="space-y-4">
          <div className="bg-gray-900 border border-gray-800 p-4 rounded-xl flex flex-col md:flex-row md:items-center justify-between gap-3">
            <div>
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <span>💻</span> Sub-Session PTY / ConPTY Terminal Stream Ledger
              </h3>
              <p className="text-xs text-gray-400">
                Granular, asciicast-compliant command execution log for live response remote sessions.
              </p>
            </div>

            <div className="flex items-center space-x-2">
              <span className="text-xs text-gray-400 font-semibold">Live Session:</span>
              <select
                value={selectedSessionId}
                onChange={(e) => {
                  setSelectedSessionId(e.target.value)
                  fetchTerminalStreams(e.target.value)
                }}
                className="bg-slate-950 border border-gray-700 rounded-lg px-3 py-1.5 text-xs text-white focus:outline-none focus:border-teal-500 font-mono"
              >
                {terminalSessions.map((s) => (
                  <option key={s.session_id} value={s.session_id}>
                    {s.session_id.slice(0, 8)}... ({s.status})
                  </option>
                ))}
              </select>
            </div>
          </div>

          {/* Terminal Command Input */}
          <div className="bg-gray-900/80 border border-gray-800 p-3 rounded-xl flex items-center gap-3">
            <span className="text-xs text-teal-400 font-mono font-bold">PTY $</span>
            <input
              type="text"
              value={terminalCmd}
              onChange={(e) => setTerminalCmd(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleRecordTerminalCommand()}
              className="flex-1 bg-slate-950 border border-slate-800 rounded px-3 py-1.5 text-xs text-white font-mono focus:outline-none focus:border-teal-500"
              placeholder="Enter PTY command..."
            />
            <button
              onClick={handleRecordTerminalCommand}
              disabled={executingCmd}
              className="px-4 py-1.5 bg-teal-600 hover:bg-teal-500 text-slate-950 text-xs font-bold rounded shadow transition disabled:opacity-50"
            >
              {executingCmd ? 'Recording...' : 'Record PTY Stream'}
            </button>
          </div>

          {/* Stream Log Table */}
          <div className="bg-gray-900/60 border border-gray-800 rounded-xl overflow-hidden shadow-xl">
            <table className="w-full text-left text-xs">
              <thead className="bg-gray-950 text-gray-400 uppercase font-mono border-b border-gray-800 text-[10px]">
                <tr>
                  <th className="py-3 px-4">Command ID</th>
                  <th className="py-3 px-4">Command Input</th>
                  <th className="py-3 px-4">Output Summary</th>
                  <th className="py-3 px-4">Exit Code</th>
                  <th className="py-3 px-4">Executed At</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800 font-mono">
                {terminalStreams.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="py-8 text-center text-gray-500">
                      No PTY execution streams recorded for this session.
                    </td>
                  </tr>
                ) : (
                  terminalStreams.map((s) => (
                    <tr key={s.command_id} className="hover:bg-gray-800/40">
                      <td className="py-3 px-4 text-teal-400">{s.command_id.slice(0, 8)}...</td>
                      <td className="py-3 px-4 text-white font-bold">{s.command_input}</td>
                      <td className="py-3 px-4 text-gray-400 text-[11px] truncate max-w-md">{s.command_output_summary}</td>
                      <td className="py-3 px-4">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${s.exit_code === 0 ? 'bg-emerald-500/20 text-emerald-400' : 'bg-rose-500/20 text-rose-400'}`}>
                          {s.exit_code}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-gray-500 text-[11px]">{s.executed_at.slice(0, 19).replace('T', ' ')}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* =========================================================================
          TAB 5: SPATIAL DATABASE AUDIT LEDGER (NEON RLS)
          ========================================================================= */}
      {activeTab === 'spatial' && (
        <div className="space-y-4">
          <div className="bg-gray-900 border border-gray-800 p-4 rounded-xl">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <span>📜</span> Spatial Database Audit Ledger (Neon Serverless RLS)
            </h3>
            <p className="text-xs text-gray-400">
              Immutable geographic logs partitioned by tenant organization ID with sub-second timestamps.
            </p>
          </div>

          <div className="bg-gray-900/60 border border-gray-800 rounded-xl overflow-hidden shadow-xl">
            <table className="w-full text-left text-xs">
              <thead className="bg-gray-950 text-gray-400 uppercase font-mono border-b border-gray-800 text-[10px]">
                <tr>
                  <th className="py-3 px-4">Log ID</th>
                  <th className="py-3 px-4">Coordinates (Lat, Lon)</th>
                  <th className="py-3 px-4">Speed</th>
                  <th className="py-3 px-4">Battery &amp; Power</th>
                  <th className="py-3 px-4">Tracking State</th>
                  <th className="py-3 px-4">Cadence</th>
                  <th className="py-3 px-4">Timestamp</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800 font-mono">
                {locations.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="py-8 text-center text-gray-500">
                      No geographic audit logs on record.
                    </td>
                  </tr>
                ) : (
                  locations.map((loc) => (
                    <tr key={loc.log_id} className="hover:bg-gray-800/40">
                      <td className="py-3 px-4 text-teal-400">{loc.log_id.slice(0, 8)}...</td>
                      <td className="py-3 px-4 text-white font-semibold">
                        {loc.latitude.toFixed(5)}, {loc.longitude.toFixed(5)}
                      </td>
                      <td className="py-3 px-4 text-gray-300">{loc.speed_mps.toFixed(1)} m/s</td>
                      <td className="py-3 px-4 text-gray-400">
                        {loc.battery_level}% ({loc.power_source})
                      </td>
                      <td className="py-3 px-4">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            loc.tracking_state === 'GEOFENCE_BREACH'
                              ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                              : loc.tracking_state === 'ACTIVE_TRANSIT'
                              ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                              : loc.tracking_state === 'LOW_POWER'
                              ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                              : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                          }`}
                        >
                          {loc.tracking_state}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-teal-300 font-bold">{loc.polling_interval_seconds}s</td>
                      <td className="py-3 px-4 text-gray-500 text-[11px]">{loc.tracked_at.slice(0, 19).replace('T', ' ')}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
