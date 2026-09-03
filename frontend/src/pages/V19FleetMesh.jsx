import React, { useState, useEffect } from 'react'
import client from '../api/client'
import { useAuth } from '../context/AuthContext'

export default function V19FleetMesh() {
  const { user } = useAuth()

  const [activeTab, setActiveTab] = useState('map') // map | osquery | processes | files | audit
  const [feedback, setFeedback] = useState(null)

  // 1. Fleet Mesh Status
  const [meshStatus, setMeshStatus] = useState(null)
  const [loadingStatus, setLoadingStatus] = useState(false)

  // 2. GIS Fleet Map
  const [mapDevices, setMapDevices] = useState([])
  const [loadingMap, setLoadingMap] = useState(false)
  const [selectedMapDevice, setSelectedMapDevice] = useState(null)

  // 3. Osquery Engine State
  const [sqlQuery, setSqlQuery] = useState('SELECT pid, name, path, cpu_usage, memory_usage, username FROM processes WHERE cpu_usage > 10;')
  const [queryTargetDeviceId, setQueryTargetDeviceId] = useState('')
  const [dispatchingQuery, setDispatchingQuery] = useState(false)
  const [queryRuns, setQueryRuns] = useState([])
  const [currentQueryResults, setCurrentQueryResults] = useState([])
  const [selectedRunId, setSelectedRunId] = useState(null)

  // 4. Remote Process Manager
  const [selectedProcessDevice, setSelectedProcessDevice] = useState('')
  const [processesList, setProcessesList] = useState([])
  const [loadingProcesses, setLoadingProcesses] = useState(false)
  const [terminatingPid, setTerminatingPid] = useState(null)

  // 5. Remote File Explorer
  const [selectedFileDevice, setSelectedFileDevice] = useState('')
  const [filePath, setFilePath] = useState('/var/log')
  const [fileList, setFileList] = useState([])
  const [loadingFiles, setLoadingFiles] = useState(false)
  const [transferringFile, setTransferringFile] = useState(false)

  // 6. Action Audit Ledger
  const [actionLogs, setActionLogs] = useState([])
  const [fileTransfers, setFileTransfers] = useState([])
  const [loadingAudit, setLoadingAudit] = useState(false)

  const showFeedback = (msg, type = 'success') => {
    setFeedback({ msg, type })
    setTimeout(() => setFeedback(null), 5000)
  }

  useEffect(() => {
    fetchMeshStatus()
    fetchFleetMap()
    fetchQueryRuns()
    fetchAuditLogs()
  }, [])

  // Auto-select first device for processes and files when mapDevices loads
  useEffect(() => {
    if (mapDevices.length > 0) {
      if (!selectedProcessDevice) {
        setSelectedProcessDevice(mapDevices[0].device_id)
        fetchDeviceProcesses(mapDevices[0].device_id)
      }
      if (!selectedFileDevice) {
        setSelectedFileDevice(mapDevices[0].device_id)
        fetchDeviceFiles(mapDevices[0].device_id, '/var/log')
      }
    }
  }, [mapDevices])

  const fetchMeshStatus = async () => {
    setLoadingStatus(true)
    try {
      const res = await client.get('/api/v19/fleet/status')
      setMeshStatus(res.data)
    } catch (err) {
      console.error('Failed to fetch fleet mesh status', err)
    } finally {
      setLoadingStatus(false)
    }
  }

  const fetchFleetMap = async () => {
    setLoadingMap(true)
    try {
      const res = await client.get('/api/v19/fleet/map')
      setMapDevices(res.data || [])
    } catch (err) {
      console.error('Failed to fetch fleet map', err)
    } finally {
      setLoadingMap(false)
    }
  }

  const fetchQueryRuns = async () => {
    try {
      const res = await client.get('/api/v19/fleet/query/runs')
      setQueryRuns(res.data || [])
      if (res.data && res.data.length > 0 && !selectedRunId) {
        fetchRunResults(res.data[0].query_run_id)
      }
    } catch (err) {
      console.error('Failed to fetch query runs', err)
    }
  }

  const fetchRunResults = async (runId) => {
    setSelectedRunId(runId)
    try {
      const res = await client.get(`/api/v19/fleet/query/runs/${runId}/results`)
      setCurrentQueryResults(res.data || [])
    } catch (err) {
      console.error('Failed to fetch run results', err)
    }
  }

  const handleDispatchQuery = async () => {
    if (!sqlQuery.trim()) return
    setDispatchingQuery(true)
    try {
      const targetFilter = queryTargetDeviceId ? { device_id: queryTargetDeviceId } : {}
      const res = await client.post('/api/v19/fleet/query/dispatch', {
        sql_statement: sqlQuery,
        target_filter: targetFilter
      })
      showFeedback(`Query executed across ${res.data.target_devices_count} fleet hosts!`, 'success')
      await fetchQueryRuns()
      await fetchRunResults(res.data.query_run_id)
    } catch (err) {
      showFeedback(err?.response?.data?.detail || 'Failed to dispatch fleet query', 'error')
    } finally {
      setDispatchingQuery(false)
    }
  }

  const fetchDeviceProcesses = async (devId) => {
    if (!devId) return
    setLoadingProcesses(true)
    try {
      const res = await client.post('/api/v19/fleet/query/dispatch', {
        sql_statement: 'SELECT * FROM processes;',
        target_filter: { device_id: devId }
      })
      const resultsRes = await client.get(`/api/v19/fleet/query/runs/${res.data.query_run_id}/results`)
      if (resultsRes.data && resultsRes.data.length > 0) {
        setProcessesList(resultsRes.data[0].returned_data || [])
      }
    } catch (err) {
      console.error('Failed to load processes', err)
    } finally {
      setLoadingProcesses(false)
    }
  }

  const handleKillProcess = async (pid, procName) => {
    if (!selectedProcessDevice) return
    setTerminatingPid(pid)
    try {
      const res = await client.post('/api/v19/fleet/actions/dispatch', {
        device_id: selectedProcessDevice,
        action_type: 'KILL_PROCESS',
        target_parameters: { pid, process_name: procName }
      })
      showFeedback(`[SUCCESS] SIGKILL sent to PID ${pid} (${procName})`, 'success')
      setProcessesList((prev) => prev.filter((p) => p.pid !== pid))
      await fetchAuditLogs()
      await fetchMeshStatus()
    } catch (err) {
      showFeedback(err?.response?.data?.detail || 'Failed to terminate process', 'error')
    } finally {
      setTerminatingPid(null)
    }
  }

  const handleIsolateDevice = async (devId, isolate) => {
    try {
      const res = await client.post('/api/v19/fleet/actions/dispatch', {
        device_id: devId,
        action_type: isolate ? 'ISOLATE_HOST' : 'UNISOLATE_HOST',
        target_parameters: { reason: 'Analyst manual action' }
      })
      showFeedback(`Host ${isolate ? 'ISOLATED' : 'RECONNECTED'} via eBPF lockdown!`, 'success')
      await fetchFleetMap()
      await fetchAuditLogs()
    } catch (err) {
      showFeedback(err?.response?.data?.detail || 'Failed to toggle isolation', 'error')
    }
  }

  const fetchDeviceFiles = async (devId, path) => {
    if (!devId) return
    setLoadingFiles(true)
    try {
      const res = await client.post('/api/v19/fleet/files/explore', {
        device_id: devId,
        path: path || filePath
      })
      setFileList(res.data || [])
    } catch (err) {
      console.error('Failed to explore files', err)
    } finally {
      setLoadingFiles(false)
    }
  }

  const handleDownloadFile = async (remotePath) => {
    if (!selectedFileDevice) return
    setTransferringFile(true)
    try {
      const res = await client.post('/api/v19/fleet/files/transfer', {
        device_id: selectedFileDevice,
        direction: 'DOWNLOAD',
        local_file_path: remotePath,
        file_content: `[Forensic Snapshot of ${remotePath} retrieved by Threat Analyser Live Response Engine]`
      })
      showFeedback(`File ${remotePath} transferred! SHA-256: ${res.data.sha256_hash.slice(0, 16)}...`, 'success')
      await fetchAuditLogs()
      await fetchMeshStatus()
    } catch (err) {
      showFeedback(err?.response?.data?.detail || 'Failed to transfer file', 'error')
    } finally {
      setTransferringFile(false)
    }
  }

  const fetchAuditLogs = async () => {
    setLoadingAudit(true)
    try {
      const [actionsRes, transfersRes] = await Promise.all([
        client.get('/api/v19/fleet/actions/logs'),
        client.get('/api/v19/fleet/files/transfers')
      ])
      setActionLogs(actionsRes.data || [])
      setFileTransfers(transfersRes.data || [])
    } catch (err) {
      console.error('Failed to fetch audit logs', err)
    } finally {
      setLoadingAudit(false)
    }
  }

  // Convert map coordinates to SVG coordinates (Miller cylindrical projection approximation)
  const getSvgCoordinates = (lat, lon) => {
    const x = ((lon + 180) / 360) * 800
    const y = ((90 - lat) / 180) * 400
    return { x: Math.max(20, Math.min(780, x)), y: Math.max(20, Math.min(380, y)) }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between pb-4 border-b border-gray-800 gap-4">
        <div>
          <div className="flex items-center space-x-3">
            <span className="text-2xl">🌐</span>
            <h1 className="text-2xl font-black tracking-tight text-white flex items-center gap-2">
              Fleet Command &amp; Control &amp; Live OSQuery
              <span className="text-xs px-2.5 py-0.5 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 font-mono font-semibold">
                v19.0 Sovereign
              </span>
            </h1>
          </div>
          <p className="text-gray-400 text-sm mt-1">
            Multiplexed Reverse WSS Control Socket, Distributed SQL-on-the-Edge OSQuery, Interactive Process Kill Switch, and Live GIS Topology
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <div className="flex items-center space-x-2 bg-gray-900 border border-gray-700 px-3 py-1.5 rounded-lg text-xs font-mono">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
            <span className="text-gray-300">Fleet Control Socket:</span>
            <span className="text-cyan-400 font-bold">ONLINE</span>
          </div>
          <button
            onClick={() => {
              fetchMeshStatus()
              fetchFleetMap()
              fetchQueryRuns()
              fetchAuditLogs()
            }}
            className="px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-lg text-xs font-medium border border-gray-700 transition"
          >
            Refresh Fleet
          </button>
        </div>
      </div>

      {/* Global Feedback Banner */}
      {feedback && (
        <div
          className={`p-4 rounded-xl text-sm font-medium border flex items-center justify-between ${
            feedback.type === 'error'
              ? 'bg-rose-500/10 text-rose-400 border-rose-500/30'
              : feedback.type === 'info'
              ? 'bg-blue-500/10 text-blue-400 border-blue-500/30'
              : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
          }`}
        >
          <span>{feedback.msg}</span>
          <button onClick={() => setFeedback(null)} className="text-xs opacity-60 hover:opacity-100">
            ✕
          </button>
        </div>
      )}

      {/* Tabs Navigation */}
      <div className="flex space-x-2 border-b border-gray-800 pb-2 overflow-x-auto">
        {[
          { id: 'map', label: `Live GIS Fleet Map (${mapDevices.length})`, icon: '🗺️' },
          { id: 'osquery', label: 'Osquery SQL Engine', icon: '⚡' },
          { id: 'processes', label: 'Process Tree & Kill Switch', icon: '⚙️' },
          { id: 'files', label: 'Remote File Explorer', icon: '📁' },
          { id: 'audit', label: `Fleet Action Ledger (${actionLogs.length})`, icon: '📜' }
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex items-center space-x-2 px-4 py-2.5 rounded-lg text-xs font-medium transition whitespace-nowrap ${
              activeTab === tab.id
                ? 'bg-cyan-600 text-white shadow-lg shadow-cyan-600/20 font-semibold'
                : 'text-gray-400 hover:text-white hover:bg-gray-800/60'
            }`}
          >
            <span>{tab.icon}</span>
            <span>{tab.label}</span>
          </button>
        ))}
      </div>

      {/* =========================================================================
          TAB 1: LIVE INTERACTIVE GIS FLEET MAP & LATENCY GRID
          ========================================================================= */}
      {activeTab === 'map' && (
        <div className="space-y-6">
          {/* Vector World Map Container */}
          <div className="bg-slate-950 border border-slate-800 rounded-xl p-5 shadow-2xl relative overflow-hidden">
            <div className="flex items-center justify-between mb-3">
              <div>
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <span>🌍</span> Global Fleet Distribution &amp; Real-Time Latency Topology
                </h3>
                <p className="text-xs text-gray-400">
                  Continuous GeoIP coordinate resolution and WebSocket RTT ping latency classification
                </p>
              </div>

              <div className="flex items-center space-x-4 text-xs font-mono">
                <span className="flex items-center gap-1.5 text-emerald-400">
                  <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 inline-block" /> &lt;100ms
                </span>
                <span className="flex items-center gap-1.5 text-amber-400">
                  <span className="w-2.5 h-2.5 rounded-full bg-amber-500 inline-block" /> 100-500ms
                </span>
                <span className="flex items-center gap-1.5 text-rose-400">
                  <span className="w-2.5 h-2.5 rounded-full bg-rose-500 inline-block" /> &gt;500ms
                </span>
              </div>
            </div>

            {/* SVG Interactive Map */}
            <div className="w-full h-80 bg-slate-900/60 rounded-lg border border-slate-800/80 relative flex items-center justify-center overflow-hidden">
              <svg viewBox="0 0 800 400" className="w-full h-full opacity-60">
                {/* Simplified Continents Outline */}
                <path
                  d="M120,80 Q180,60 220,90 Q240,140 200,180 Q150,160 120,130 Z M200,200 Q260,210 240,300 Q190,320 170,240 Z M420,70 Q520,50 560,110 Q500,160 440,140 Z M450,180 Q520,180 500,290 Q430,270 420,200 Z M600,80 Q720,70 760,140 Q700,200 620,150 Z M640,240 Q730,240 710,320 Q630,310 640,240 Z"
                  fill="#1e293b"
                  stroke="#334155"
                  strokeWidth="1.5"
                />
                {/* Grid Lines */}
                <line x1="0" y1="200" x2="800" y2="200" stroke="#1e293b" strokeDasharray="4" />
                <line x1="400" y1="0" x2="400" y2="400" stroke="#1e293b" strokeDasharray="4" />

                {/* Animated Device Marker Pins */}
                {mapDevices.map((dev) => {
                  const { x, y } = getSvgCoordinates(dev.latitude, dev.longitude)
                  const pinColor =
                    dev.latency_status === 'green'
                      ? '#10b981'
                      : dev.latency_status === 'amber'
                      ? '#f59e0b'
                      : '#ef4444'
                  return (
                    <g
                      key={dev.device_id}
                      className="cursor-pointer transition-transform hover:scale-125"
                      onClick={() => setSelectedMapDevice(dev)}
                    >
                      <circle cx={x} cy={y} r="8" fill={pinColor} opacity="0.3" className="animate-ping" />
                      <circle cx={x} cy={y} r="5" fill={pinColor} stroke="#ffffff" strokeWidth="1.5" />
                      <text x={x + 8} y={y + 4} fill="#e2e8f0" fontSize="9" fontFamily="monospace" fontWeight="bold">
                        {dev.hostname.split('.')[0]}
                      </text>
                    </g>
                  )
                })}
              </svg>

              {/* Selected Device Floating Overlay */}
              {selectedMapDevice && (
                <div className="absolute bottom-3 left-3 bg-slate-950/95 border border-cyan-500/40 p-3 rounded-lg shadow-xl text-xs font-mono space-y-1 max-w-sm">
                  <div className="flex items-center justify-between text-cyan-400 font-bold">
                    <span>{selectedMapDevice.hostname}</span>
                    <button onClick={() => setSelectedMapDevice(null)} className="text-gray-400 hover:text-white">✕</button>
                  </div>
                  <div className="text-gray-300 text-[11px]">{selectedMapDevice.location_desc}</div>
                  <div className="flex items-center justify-between text-[11px] pt-1">
                    <span className="text-gray-400">IP: {selectedMapDevice.public_ip}</span>
                    <span className={`font-bold ${selectedMapDevice.latency_status === 'green' ? 'text-emerald-400' : 'text-amber-400'}`}>
                      {selectedMapDevice.rtt_latency_ms} ms
                    </span>
                  </div>
                  <div className="pt-2 flex gap-2">
                    <button
                      onClick={() => {
                        setSelectedProcessDevice(selectedMapDevice.device_id)
                        fetchDeviceProcesses(selectedMapDevice.device_id)
                        setActiveTab('processes')
                      }}
                      className="px-2 py-1 bg-cyan-600 hover:bg-cyan-500 text-white rounded text-[10px] font-bold"
                    >
                      Inspect Processes →
                    </button>
                    <button
                      onClick={() => {
                        setSelectedFileDevice(selectedMapDevice.device_id)
                        fetchDeviceFiles(selectedMapDevice.device_id, '/var/log')
                        setActiveTab('files')
                      }}
                      className="px-2 py-1 bg-gray-800 hover:bg-gray-700 text-gray-200 rounded text-[10px]"
                    >
                      Browse Files →
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Enrolled Fleet Cards Grid */}
          <div className="space-y-3">
            <h3 className="text-xs font-bold text-gray-400 uppercase tracking-wider">
              Enrolled Endpoint Fleet Presence
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {mapDevices.map((d) => (
                <div
                  key={d.device_id}
                  className="bg-gray-900/70 border border-gray-800 hover:border-cyan-500/40 p-4 rounded-xl space-y-3 transition shadow-lg"
                >
                  <div className="flex items-center justify-between">
                    <div className="font-bold text-sm text-white font-mono truncate">{d.hostname}</div>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
                        d.status === 'active'
                          ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                          : d.status === 'quarantined'
                          ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                          : 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                      }`}
                    >
                      {d.status}
                    </span>
                  </div>

                  <div className="space-y-1 text-xs text-gray-400 font-mono">
                    <div className="flex justify-between">
                      <span>Location:</span>
                      <span className="text-gray-200">{d.location_desc}</span>
                    </div>
                    <div className="flex justify-between">
                      <span>Public IP:</span>
                      <span className="text-gray-200">{d.public_ip}</span>
                    </div>
                    <div className="flex justify-between">
                      <span>RTT Latency:</span>
                      <span className={`font-bold ${d.latency_status === 'green' ? 'text-emerald-400' : 'text-amber-400'}`}>
                        {d.rtt_latency_ms} ms
                      </span>
                    </div>
                  </div>

                  <div className="flex gap-2 pt-2 border-t border-gray-800 text-xs">
                    <button
                      onClick={() => {
                        setSelectedProcessDevice(d.device_id)
                        fetchDeviceProcesses(d.device_id)
                        setActiveTab('processes')
                      }}
                      className="flex-1 px-2 py-1 bg-gray-800 hover:bg-gray-700 text-cyan-400 rounded font-semibold text-center transition"
                    >
                      Processes
                    </button>
                    <button
                      onClick={() => {
                        setSelectedFileDevice(d.device_id)
                        fetchDeviceFiles(d.device_id, '/var/log')
                        setActiveTab('files')
                      }}
                      className="flex-1 px-2 py-1 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded font-semibold text-center transition"
                    >
                      Files
                    </button>
                    <button
                      onClick={() => handleIsolateDevice(d.device_id, d.status !== 'quarantined')}
                      className={`px-2 py-1 rounded font-semibold text-xs ${
                        d.status === 'quarantined'
                          ? 'bg-emerald-600 hover:bg-emerald-500 text-white'
                          : 'bg-rose-600 hover:bg-rose-500 text-white'
                      }`}
                    >
                      {d.status === 'quarantined' ? 'Rejoin' : 'Isolate'}
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* =========================================================================
          TAB 2: OSQUERY-STYLE DISTRIBUTED REMOTE SQL QUERY ENGINE
          ========================================================================= */}
      {activeTab === 'osquery' && (
        <div className="space-y-4">
          <div className="bg-gray-900 border border-gray-800 p-4 rounded-xl space-y-3">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
              <div>
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <span>⚡</span> Distributed Osquery-Style Remote SQL Evaluator
                </h3>
                <p className="text-xs text-gray-400">
                  Query processes, open ports, logged-in users, and system metadata declaratively across enterprise fleets.
                </p>
              </div>

              {/* Target Device Filter */}
              <div className="flex items-center space-x-2">
                <span className="text-xs text-gray-400 font-semibold">Target Scope:</span>
                <select
                  value={queryTargetDeviceId}
                  onChange={(e) => setQueryTargetDeviceId(e.target.value)}
                  className="bg-gray-950 border border-gray-700 rounded-lg px-3 py-1.5 text-xs text-white focus:outline-none focus:border-cyan-500 font-mono"
                >
                  <option value="">All Enrolled Fleet Hosts</option>
                  {mapDevices.map((d) => (
                    <option key={d.device_id} value={d.device_id}>
                      {d.hostname} ({d.public_ip})
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {/* Presets Toolbar */}
            <div className="flex flex-wrap gap-2 pt-1">
              {[
                { label: 'High CPU Processes (>10%)', sql: 'SELECT pid, name, path, cpu_usage, memory_usage, username FROM processes WHERE cpu_usage > 10;' },
                { label: 'Listening TCP Sockets', sql: "SELECT pid, port, protocol, address, state, process_name FROM listening_ports WHERE state = 'LISTEN';" },
                { label: 'Logged-in Sessions', sql: 'SELECT user, tty, host, login_time, pid FROM logged_in_users;' },
                { label: 'Host System Hardware', sql: 'SELECT hostname, os_name, os_version, kernel, uptime_seconds, cpu_count FROM system_info;' },
                { label: 'Suspicious /tmp Executables', sql: "SELECT path, filename, size_bytes, permissions, sha256 FROM file_system WHERE path LIKE '%hidden%';" }
              ].map((preset, idx) => (
                <button
                  key={idx}
                  onClick={() => setSqlQuery(preset.sql)}
                  className="px-2.5 py-1 bg-gray-950 hover:bg-gray-800 text-cyan-300 border border-cyan-500/20 hover:border-cyan-500/40 rounded-lg text-xs font-mono transition"
                >
                  {preset.label}
                </button>
              ))}
            </div>

            {/* SQL Textarea & Dispatch Button */}
            <div className="space-y-2">
              <textarea
                value={sqlQuery}
                onChange={(e) => setSqlQuery(e.target.value)}
                rows="3"
                className="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 font-mono text-xs text-cyan-300 focus:outline-none focus:border-cyan-500 resize-none shadow-inner"
                placeholder="Enter SQL-on-the-Edge query (e.g. SELECT * FROM processes WHERE cpu_usage > 20;)"
              />
              <div className="flex justify-end">
                <button
                  onClick={handleDispatchQuery}
                  disabled={dispatchingQuery}
                  className="px-5 py-2 bg-cyan-600 hover:bg-cyan-500 text-slate-950 text-xs font-bold rounded-lg shadow-lg shadow-cyan-600/20 transition disabled:opacity-50 flex items-center space-x-2"
                >
                  <span>{dispatchingQuery ? '⚡ Dispatching to Fleet...' : '🚀 Dispatch SQL to Fleet'}</span>
                </button>
              </div>
            </div>
          </div>

          {/* Tabular Query Results */}
          <div className="bg-gray-900/70 border border-gray-800 rounded-xl overflow-hidden shadow-xl">
            <div className="p-4 bg-gray-950/80 border-b border-gray-800 flex items-center justify-between">
              <div>
                <h4 className="text-xs font-bold text-white uppercase font-mono">
                  Tabular Results Matrix {selectedRunId && `(Run: ${selectedRunId.slice(0, 8)}...)`}
                </h4>
                <span className="text-[11px] text-gray-400">
                  {currentQueryResults.length} Device Responses Received
                </span>
              </div>
            </div>

            <div className="p-4 space-y-4 max-h-[450px] overflow-y-auto">
              {currentQueryResults.length === 0 ? (
                <div className="text-center text-gray-500 py-8 text-xs font-mono">
                  No query results returned yet. Select or dispatch a query above.
                </div>
              ) : (
                currentQueryResults.map((res) => (
                  <div key={res.result_id} className="bg-slate-950 border border-slate-800 rounded-lg p-3 space-y-2">
                    <div className="flex items-center justify-between text-xs font-mono border-b border-slate-800 pb-2">
                      <span className="text-cyan-400 font-bold flex items-center gap-1.5">
                        <span>🖥️</span> {res.device_hostname || res.device_id}
                      </span>
                      <span className="text-gray-500 text-[10px]">{res.executed_at}</span>
                    </div>

                    {res.returned_data.length === 0 ? (
                      <p className="text-gray-500 text-xs italic">0 rows matched condition.</p>
                    ) : (
                      <div className="overflow-x-auto">
                        <table className="w-full text-left text-xs font-mono">
                          <thead>
                            <tr className="border-b border-slate-800 text-[10px] text-gray-400 uppercase">
                              {Object.keys(res.returned_data[0]).map((col) => (
                                <th key={col} className="py-1.5 px-2">{col}</th>
                              ))}
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-slate-900 text-gray-200">
                            {res.returned_data.map((row, rIdx) => (
                              <tr key={rIdx} className="hover:bg-slate-900/60">
                                {Object.values(row).map((val, cIdx) => (
                                  <td key={cIdx} className="py-1.5 px-2 whitespace-nowrap">
                                    {typeof val === 'boolean' ? (val ? 'TRUE' : 'FALSE') : String(val)}
                                  </td>
                                ))}
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}

      {/* =========================================================================
          TAB 3: REMOTE PROCESS TREE & KILL SWITCH
          ========================================================================= */}
      {activeTab === 'processes' && (
        <div className="space-y-4">
          <div className="bg-gray-900 border border-gray-800 p-4 rounded-xl flex flex-col md:flex-row md:items-center justify-between gap-3">
            <div>
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <span>⚙️</span> Remote Live Process Tree &amp; Active Kill Switch
              </h3>
              <p className="text-xs text-gray-400">
                Inspect live process states on endpoints and terminate suspicious processes in one click (SIGKILL).
              </p>
            </div>

            <div className="flex items-center space-x-2">
              <span className="text-xs text-gray-400 font-semibold">Select Host:</span>
              <select
                value={selectedProcessDevice}
                onChange={(e) => {
                  setSelectedProcessDevice(e.target.value)
                  fetchDeviceProcesses(e.target.value)
                }}
                className="bg-gray-950 border border-gray-700 rounded-lg px-3 py-1.5 text-xs text-white focus:outline-none focus:border-cyan-500 font-mono"
              >
                {mapDevices.map((d) => (
                  <option key={d.device_id} value={d.device_id}>
                    {d.hostname} ({d.public_ip})
                  </option>
                ))}
              </select>
              <button
                onClick={() => fetchDeviceProcesses(selectedProcessDevice)}
                disabled={loadingProcesses}
                className="px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-lg text-xs font-semibold"
              >
                {loadingProcesses ? 'Scanning...' : 'Refresh'}
              </button>
            </div>
          </div>

          {/* Process Table */}
          <div className="bg-gray-900/60 border border-gray-800 rounded-xl overflow-hidden shadow-xl">
            <table className="w-full text-left text-xs">
              <thead className="bg-gray-950 text-gray-400 uppercase font-mono border-b border-gray-800 text-[10px]">
                <tr>
                  <th className="py-3 px-4">PID</th>
                  <th className="py-3 px-4">Process Name</th>
                  <th className="py-3 px-4">Path / Binary</th>
                  <th className="py-3 px-4">CPU %</th>
                  <th className="py-3 px-4">Memory %</th>
                  <th className="py-3 px-4">User</th>
                  <th className="py-3 px-4 text-right">Remediation Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800 font-mono">
                {processesList.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="py-8 text-center text-gray-500">
                      {loadingProcesses ? 'Streaming active processes from endpoint...' : 'No processes found.'}
                    </td>
                  </tr>
                ) : (
                  processesList.map((p) => (
                    <tr key={p.pid} className="hover:bg-gray-800/40">
                      <td className="py-3 px-4 text-cyan-400 font-bold">{p.pid}</td>
                      <td className="py-3 px-4 text-white font-semibold flex items-center gap-1.5">
                        <span>{p.cpu_usage > 50 ? '🔥' : '⚙️'}</span>
                        <span>{p.name}</span>
                      </td>
                      <td className="py-3 px-4 text-gray-400 text-[11px] max-w-xs truncate">{p.path}</td>
                      <td className="py-3 px-4">
                        <span className={`font-bold ${p.cpu_usage > 50 ? 'text-rose-400' : 'text-gray-300'}`}>
                          {p.cpu_usage}%
                        </span>
                      </td>
                      <td className="py-3 px-4 text-gray-300">{p.memory_usage}%</td>
                      <td className="py-3 px-4 text-gray-400">{p.username}</td>
                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={() => handleKillProcess(p.pid, p.name)}
                          disabled={terminatingPid === p.pid}
                          className="px-2.5 py-1 bg-rose-950 hover:bg-rose-900 text-rose-300 border border-rose-800 rounded font-bold text-[11px] transition shadow disabled:opacity-50"
                        >
                          {terminatingPid === p.pid ? 'Killing...' : '⚡ Terminate (SIGKILL)'}
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* =========================================================================
          TAB 4: REMOTE VISUAL FILE EXPLORER
          ========================================================================= */}
      {activeTab === 'files' && (
        <div className="space-y-4">
          <div className="bg-gray-900 border border-gray-800 p-4 rounded-xl flex flex-col md:flex-row md:items-center justify-between gap-3">
            <div>
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <span>📁</span> Remote Visual File Explorer
              </h3>
              <p className="text-xs text-gray-400">
                Browse remote file hierarchies, inspect permissions and SHA-256 hashes, and download forensic artifacts.
              </p>
            </div>

            <div className="flex items-center space-x-2">
              <span className="text-xs text-gray-400 font-semibold">Select Host:</span>
              <select
                value={selectedFileDevice}
                onChange={(e) => {
                  setSelectedFileDevice(e.target.value)
                  fetchDeviceFiles(e.target.value, filePath)
                }}
                className="bg-gray-950 border border-gray-700 rounded-lg px-3 py-1.5 text-xs text-white focus:outline-none focus:border-cyan-500 font-mono"
              >
                {mapDevices.map((d) => (
                  <option key={d.device_id} value={d.device_id}>
                    {d.hostname} ({d.public_ip})
                  </option>
                ))}
              </select>
            </div>
          </div>

          {/* Path Navigation Bar */}
          <div className="bg-gray-900/80 border border-gray-800 p-3 rounded-xl flex items-center gap-3">
            <span className="text-xs text-cyan-400 font-mono font-bold">Path:</span>
            <input
              type="text"
              value={filePath}
              onChange={(e) => setFilePath(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && fetchDeviceFiles(selectedFileDevice, filePath)}
              className="flex-1 bg-slate-950 border border-slate-800 rounded px-3 py-1.5 text-xs text-white font-mono focus:outline-none focus:border-cyan-500"
              placeholder="/var/log"
            />
            <button
              onClick={() => fetchDeviceFiles(selectedFileDevice, filePath)}
              disabled={loadingFiles}
              className="px-4 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-slate-950 text-xs font-bold rounded shadow transition disabled:opacity-50"
            >
              {loadingFiles ? 'Loading...' : 'Go to Path'}
            </button>
          </div>

          {/* File Listing Table */}
          <div className="bg-gray-900/60 border border-gray-800 rounded-xl overflow-hidden shadow-xl">
            <table className="w-full text-left text-xs">
              <thead className="bg-gray-950 text-gray-400 uppercase font-mono border-b border-gray-800 text-[10px]">
                <tr>
                  <th className="py-3 px-4">Filename</th>
                  <th className="py-3 px-4">Type</th>
                  <th className="py-3 px-4">Size</th>
                  <th className="py-3 px-4">Permissions</th>
                  <th className="py-3 px-4">Owner</th>
                  <th className="py-3 px-4">Modified</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800 font-mono">
                {fileList.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="py-8 text-center text-gray-500">
                      {loadingFiles ? 'Exploring directory...' : 'No files found in directory.'}
                    </td>
                  </tr>
                ) : (
                  fileList.map((f, idx) => (
                    <tr key={idx} className="hover:bg-gray-800/40">
                      <td className="py-3 px-4 text-white font-semibold flex items-center gap-2">
                        <span>{f.type === 'directory' ? '📁' : '📄'}</span>
                        <span
                          className={f.type === 'directory' ? 'text-cyan-400 cursor-pointer hover:underline' : ''}
                          onClick={() => {
                            if (f.type === 'directory') {
                              setFilePath(f.path)
                              fetchDeviceFiles(selectedFileDevice, f.path)
                            }
                          }}
                        >
                          {f.name}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-gray-400 uppercase text-[10px]">{f.type}</td>
                      <td className="py-3 px-4 text-gray-300">{f.size}</td>
                      <td className="py-3 px-4 text-gray-400">{f.permissions}</td>
                      <td className="py-3 px-4 text-gray-400">{f.owner}</td>
                      <td className="py-3 px-4 text-gray-500 text-[11px]">{f.modified}</td>
                      <td className="py-3 px-4 text-right">
                        {f.type === 'file' && (
                          <button
                            onClick={() => handleDownloadFile(f.path)}
                            disabled={transferringFile}
                            className="px-2.5 py-1 bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-800 rounded font-semibold text-[11px] transition shadow"
                          >
                            ⬇ Download Artifact
                          </button>
                        )}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* =========================================================================
          TAB 5: FLEET ACTION AUDIT & TRANSFER LEDGER
          ========================================================================= */}
      {activeTab === 'audit' && (
        <div className="space-y-6">
          {/* Action Logs */}
          <div className="space-y-3">
            <h3 className="text-xs font-bold text-gray-400 uppercase tracking-wider">
              Fleet Remediation Actions Audit Ledger
            </h3>
            <div className="bg-gray-900/60 border border-gray-800 rounded-xl overflow-hidden shadow-xl">
              <table className="w-full text-left text-xs">
                <thead className="bg-gray-950 text-gray-400 uppercase font-mono border-b border-gray-800 text-[10px]">
                  <tr>
                    <th className="py-3 px-4">Action ID</th>
                    <th className="py-3 px-4">Target Device</th>
                    <th className="py-3 px-4">Action Type</th>
                    <th className="py-3 px-4">Parameters</th>
                    <th className="py-3 px-4">Status</th>
                    <th className="py-3 px-4">Logged At</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800 font-mono">
                  {actionLogs.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="py-8 text-center text-gray-500">
                        No fleet actions executed yet.
                      </td>
                    </tr>
                  ) : (
                    actionLogs.map((a) => (
                      <tr key={a.action_id} className="hover:bg-gray-800/40">
                        <td className="py-3 px-4 text-cyan-400">{a.action_id.slice(0, 8)}...</td>
                        <td className="py-3 px-4 text-gray-200">{a.device_id.slice(0, 8)}...</td>
                        <td className="py-3 px-4 font-bold text-white">{a.action_type}</td>
                        <td className="py-3 px-4 text-gray-400 text-[11px]">
                          {JSON.stringify(a.target_parameters)}
                        </td>
                        <td className="py-3 px-4">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                              a.execution_status === 'SUCCESS'
                                ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                                : 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                            }`}
                          >
                            {a.execution_status}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-gray-500 text-[11px]">{a.logged_at.slice(0, 19).replace('T', ' ')}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Remote File Transfers */}
          <div className="space-y-3">
            <h3 className="text-xs font-bold text-gray-400 uppercase tracking-wider">
              Cryptographically Audited File Transfers
            </h3>
            <div className="bg-gray-900/60 border border-gray-800 rounded-xl overflow-hidden shadow-xl">
              <table className="w-full text-left text-xs">
                <thead className="bg-gray-950 text-gray-400 uppercase font-mono border-b border-gray-800 text-[10px]">
                  <tr>
                    <th className="py-3 px-4">Transfer ID</th>
                    <th className="py-3 px-4">Direction</th>
                    <th className="py-3 px-4">Remote File Path</th>
                    <th className="py-3 px-4">SHA-256 Hash</th>
                    <th className="py-3 px-4">Transferred At</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800 font-mono">
                  {fileTransfers.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="py-8 text-center text-gray-500">
                        No file transfers on record.
                      </td>
                    </tr>
                  ) : (
                    fileTransfers.map((t) => (
                      <tr key={t.transfer_id} className="hover:bg-gray-800/40">
                        <td className="py-3 px-4 text-cyan-400">{t.transfer_id.slice(0, 8)}...</td>
                        <td className="py-3 px-4">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                              t.transfer_direction === 'DOWNLOAD'
                                ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                                : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                            }`}
                          >
                            {t.transfer_direction}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-white font-semibold">{t.local_file_path}</td>
                        <td className="py-3 px-4 text-gray-400 text-[11px] truncate max-w-xs">{t.sha256_hash}</td>
                        <td className="py-3 px-4 text-gray-500 text-[11px]">{t.transferred_at.slice(0, 19).replace('T', ' ')}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
