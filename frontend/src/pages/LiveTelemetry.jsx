import React, { useState, useEffect } from 'react'
import axios from 'axios'
import LiveConsole from '../components/LiveConsole'

export default function LiveTelemetry() {
  const token = localStorage.getItem('token')

  const [metrics, setMetrics] = useState({
    current_eps: 8450,
    average_eps_60s: 8200.0,
    pipeline_latency_ms: 12.4,
    healthy: true,
    sla_target_ms: 250.0,
    window_duration_seconds: 60,
  })

  const [fleet, setFleet] = useState([])
  const [loadingFleet, setLoadingFleet] = useState(false)
  const [simulating, setSimulating] = useState(false)
  const [simCount, setSimCount] = useState(25)
  const [simClass, setSimClass] = useState('Process Activity')
  const [simSeverity, setSimSeverity] = useState(2)
  const [feedback, setFeedback] = useState(null)
  const [lockAlertId, setLockAlertId] = useState('alert-inc-4091')

  const fetchMetrics = async () => {
    try {
      const res = await axios.get('/api/metrics/realtime', {
        headers: { Authorization: `Bearer ${token}` },
      })
      setMetrics(res.data)
    } catch (err) {
      console.error('Error fetching real-time metrics:', err)
    }
  }

  const fetchFleet = async () => {
    setLoadingFleet(true)
    try {
      const res = await axios.get('/api/metrics/fleet-status', {
        headers: { Authorization: `Bearer ${token}` },
      })
      setFleet(res.data)
    } catch (err) {
      console.error('Error fetching fleet status:', err)
    } finally {
      setLoadingFleet(false)
    }
  }

  useEffect(() => {
    fetchMetrics()
    fetchFleet()
    const interval = setInterval(() => {
      fetchMetrics()
      fetchFleet()
    }, 4000)
    return () => clearInterval(interval)
  }, [token])

  const handleSimulateBurst = async (countOverride) => {
    setSimulating(true)
    setFeedback(null)
    const count = countOverride || simCount
    try {
      const res = await axios.post(
        '/api/ws/simulate-log',
        {
          count,
          class_name: simClass,
          severity_id: Number(simSeverity),
          message: `Dynamic telemetry stream burst [type=${simClass}]`,
          hostname: 'prod-ingress-edge-01',
        },
        { headers: { Authorization: `Bearer ${token}` } }
      )
      setFeedback({
        type: 'success',
        msg: `Dispatched ${res.data.count_sent} OCSF logs over Redis Pub/Sub! (Latency: ${res.data.pipeline_latency_ms}ms)`,
      })
      fetchMetrics()
    } catch (err) {
      setFeedback({
        type: 'error',
        msg: `Burst injection failed: ${err.response?.data?.detail || err.message}`,
      })
    } finally {
      setSimulating(false)
    }
  }

  const handleSendHeartbeat = async () => {
    try {
      const randomId = `dev-node-${Math.floor(Math.random() * 900 + 100)}`
      await axios.post(
        '/api/metrics/heartbeat',
        {
          device_id: randomId,
          hostname: `workstation-${randomId}.corp.internal`,
          os_version: 'Linux 6.8 (Ubuntu 24.04 LTS)',
          agent_version: 'v12.0.4-stream',
        },
        { headers: { Authorization: `Bearer ${token}` } }
      )
      setFeedback({
        type: 'success',
        msg: `Heartbeat recorded for ${randomId} in Redis with 120s TTL.`,
      })
      fetchFleet()
    } catch (err) {
      setFeedback({
        type: 'error',
        msg: `Heartbeat failed: ${err.response?.data?.detail || err.message}`,
      })
    }
  }

  const handleAcquireLock = async () => {
    try {
      const res = await axios.post(
        '/api/ws/co-triage-lock',
        { alert_id: lockAlertId, action: 'acquire_lock' },
        { headers: { Authorization: `Bearer ${token}` } }
      )
      setFeedback({
        type: 'success',
        msg: `Co-Triage Lock acquired on ${res.data.alert_id} by ${res.data.locked_by}. Broadcasted to all analysts.`,
      })
    } catch (err) {
      setFeedback({
        type: 'error',
        msg: `Lock dispatch failed: ${err.response?.data?.detail || err.message}`,
      })
    }
  }

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12 font-sans">
      {/* Header Banner */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-base-800 pb-5">
        <div>
          <div className="flex items-center gap-3">
            <span className="text-2xl font-mono text-cyan-400 font-bold">⚡</span>
            <h1 className="text-2xl font-bold tracking-tight text-slate-100 font-mono">
              Real-Time Security Telemetry &amp; Tail -f Console
            </h1>
            <span className="text-xs font-mono bg-cyan-950 text-cyan-300 px-2.5 py-0.5 rounded-full border border-cyan-700">
              v12.0 Active Mesh
            </span>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Sub-millisecond WebSocket multiplexing, sliding Redis window EPS analytics, and virtualized high-volume streaming.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="px-3 py-1.5 bg-base-900 border border-base-700 rounded-lg text-xs font-mono flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
            <span className="text-slate-300">WebSocket Mesh:</span>
            <span className="text-emerald-400 font-bold">ONLINE</span>
          </div>
          <button
            onClick={() => {
              fetchMetrics()
              fetchFleet()
            }}
            className="bg-base-900 hover:bg-base-800 border border-base-700 text-slate-300 text-xs px-3 py-1.5 rounded-lg transition"
          >
            ↻ Refresh
          </button>
        </div>
      </div>

      {feedback && (
        <div
          className={`p-3 rounded-lg text-xs font-mono flex items-center justify-between ${
            feedback.type === 'success'
              ? 'bg-emerald-950/80 text-emerald-300 border border-emerald-800'
              : 'bg-rose-950/80 text-rose-300 border border-rose-800'
          }`}
        >
          <span>{feedback.msg}</span>
          <button onClick={() => setFeedback(null)} className="text-slate-400 hover:text-white">
            ✕
          </button>
        </div>
      )}

      {/* Top 4 Performance Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Current EPS Card */}
        <div className="panel p-4 bg-gradient-to-br from-base-900 to-cyan-950/30 border border-cyan-500/30 rounded-xl space-y-1 shadow-md font-mono">
          <div className="flex justify-between items-center text-xs text-slate-400">
            <span>Current Ingestion Rate</span>
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping"></span>
          </div>
          <div className="text-2xl font-bold text-cyan-300 flex items-baseline gap-2">
            <span>{metrics.current_eps.toLocaleString()}</span>
            <span className="text-xs font-normal text-cyan-500">EPS (1s)</span>
          </div>
          <div className="text-[11px] text-slate-400">Sliding time window in Redis ZSET</div>
        </div>

        {/* 60s Average EPS Card */}
        <div className="panel p-4 bg-base-900 border border-base-700 rounded-xl space-y-1 shadow-md font-mono">
          <div className="text-xs text-slate-400">60-Second Mean Throughput</div>
          <div className="text-2xl font-bold text-slate-100 flex items-baseline gap-2">
            <span>{metrics.average_eps_60s.toLocaleString()}</span>
            <span className="text-xs font-normal text-slate-500">EPS (avg)</span>
          </div>
          <div className="text-[11px] text-slate-400">Total sliding 60s buffer density</div>
        </div>

        {/* Pipeline Latency Card */}
        <div className="panel p-4 bg-base-900 border border-base-700 rounded-xl space-y-1 shadow-md font-mono">
          <div className="flex justify-between items-center text-xs text-slate-400">
            <span>Pipeline Ingest Latency</span>
            <span className="text-[10px] bg-emerald-950 text-emerald-300 px-1.5 py-0.5 rounded border border-emerald-800">
              SLA MET
            </span>
          </div>
          <div className="text-2xl font-bold text-emerald-400 flex items-baseline gap-2">
            <span>{metrics.pipeline_latency_ms}</span>
            <span className="text-xs font-normal text-slate-500">ms</span>
          </div>
          <div className="text-[11px] text-slate-400">Target SLA: &lt; {metrics.sla_target_ms} ms</div>
        </div>

        {/* Active Fleet Agents */}
        <div className="panel p-4 bg-base-900 border border-base-700 rounded-xl space-y-1 shadow-md font-mono">
          <div className="text-xs text-slate-400">Active Fleet Agents</div>
          <div className="text-2xl font-bold text-indigo-300 flex items-baseline gap-2">
            <span>{fleet.filter((d) => d.status === 'Online').length}</span>
            <span className="text-xs font-normal text-slate-500">/ {fleet.length} Devices</span>
          </div>
          <div className="text-[11px] text-slate-400">Redis TTL key auto-expiration</div>
        </div>
      </div>

      {/* Traffic Burst Injection & Co-Triage Simulator Bar */}
      <div className="panel p-4 bg-base-900 border border-base-700 rounded-xl space-y-3 font-mono">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-base-800 pb-3">
          <div className="flex items-center gap-2">
            <span className="text-cyan-400 font-bold">▶</span>
            <span className="text-sm font-bold text-slate-200">High-Throughput Telemetry Traffic Simulator</span>
          </div>
          <div className="flex items-center gap-2">
            <button
              disabled={simulating}
              onClick={() => handleSimulateBurst(10)}
              className="bg-base-800 hover:bg-base-700 text-slate-300 px-3 py-1.5 rounded text-xs border border-base-600 transition"
            >
              +10 Logs
            </button>
            <button
              disabled={simulating}
              onClick={() => handleSimulateBurst(50)}
              className="bg-cyan-950 hover:bg-cyan-900 text-cyan-300 px-3 py-1.5 rounded text-xs border border-cyan-800 transition font-bold"
            >
              +50 Burst
            </button>
            <button
              disabled={simulating}
              onClick={() => handleSimulateBurst(200)}
              className="bg-indigo-600 hover:bg-indigo-500 text-white px-3.5 py-1.5 rounded text-xs font-bold transition shadow"
            >
              {simulating ? 'Injecting...' : '⚡ +200 High-Density Flood'}
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-3 text-xs">
          <div>
            <label className="text-slate-400 block mb-1">Log Class (OCSF)</label>
            <select
              value={simClass}
              onChange={(e) => setSimClass(e.target.value)}
              className="w-full bg-base-950 border border-base-700 text-slate-200 p-2 rounded focus:outline-none"
            >
              <option value="Process Activity">Process Activity (1007)</option>
              <option value="Network Activity">Network Activity (4001)</option>
              <option value="Authentication">Authentication (3002)</option>
              <option value="File Activity">File Activity (1001)</option>
              <option value="Security Finding">Security Finding (2001)</option>
            </select>
          </div>

          <div>
            <label className="text-slate-400 block mb-1">Severity Level</label>
            <select
              value={simSeverity}
              onChange={(e) => setSimSeverity(e.target.value)}
              className="w-full bg-base-950 border border-base-700 text-slate-200 p-2 rounded focus:outline-none"
            >
              <option value="0">0 - Info</option>
              <option value="1">1 - Low</option>
              <option value="2">2 - Medium</option>
              <option value="3">3 - High</option>
              <option value="4">4 - Critical</option>
            </select>
          </div>

          <div>
            <label className="text-slate-400 block mb-1">Burst Packet Count</label>
            <input
              type="number"
              value={simCount}
              onChange={(e) => setSimCount(e.target.value)}
              min="1"
              max="500"
              className="w-full bg-base-950 border border-base-700 text-slate-200 p-2 rounded focus:outline-none"
            />
          </div>

          <div className="flex items-end">
            <button
              disabled={simulating}
              onClick={() => handleSimulateBurst()}
              className="w-full bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold p-2 rounded transition text-xs flex items-center justify-center gap-1.5"
            >
              <span>{simulating ? 'Broadcasting...' : 'Broadcast to WebSocket'}</span>
            </button>
          </div>
        </div>
      </div>

      {/* Main Live Virtualized Terminal */}
      <LiveConsole token={token} />

      {/* Dynamic Agent Fleet Heartbeats & Co-Triage Presence */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 font-mono">
        {/* Fleet Heartbeat Table */}
        <div className="lg:col-span-2 panel p-4 bg-base-900 border border-base-700 rounded-xl space-y-3">
          <div className="flex justify-between items-center border-b border-base-800 pb-3">
            <div className="flex items-center gap-2">
              <span className="text-indigo-400 font-bold">📡</span>
              <h3 className="text-sm font-bold text-slate-100">Live Agent Fleet Heartbeats (Redis TTL)</h3>
            </div>
            <button
              onClick={handleSendHeartbeat}
              className="bg-indigo-950 hover:bg-indigo-900 text-indigo-300 border border-indigo-700 text-xs px-2.5 py-1 rounded transition"
            >
              + Ping Random Agent
            </button>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-base-800 text-slate-400 uppercase text-[10px]">
                  <th className="py-2 px-3">Hostname</th>
                  <th className="py-2 px-3">Device UID</th>
                  <th className="py-2 px-3">Agent Version</th>
                  <th className="py-2 px-3">Status</th>
                  <th className="py-2 px-3 text-right">Last Heartbeat</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-base-800/60">
                {fleet.map((dev) => (
                  <tr key={dev.device_id} className="hover:bg-base-950/40">
                    <td className="py-2 px-3 font-semibold text-slate-200">{dev.hostname}</td>
                    <td className="py-2 px-3 text-slate-400">{dev.device_id}</td>
                    <td className="py-2 px-3 text-cyan-400 text-[11px]">{dev.agent_version}</td>
                    <td className="py-2 px-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          dev.status === 'Online'
                            ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                            : 'bg-rose-950 text-rose-300 border border-rose-800'
                        }`}
                      >
                        {dev.status}
                      </span>
                    </td>
                    <td className="py-2 px-3 text-right text-slate-400">
                      {dev.latency_sec !== null ? `${dev.latency_sec}s ago` : 'Never'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Co-Triage Presence Locker */}
        <div className="panel p-4 bg-base-900 border border-base-700 rounded-xl space-y-3">
          <div className="border-b border-base-800 pb-3 flex items-center gap-2">
            <span className="text-amber-400 font-bold">🔒</span>
            <h3 className="text-sm font-bold text-slate-100">Co-Triage Analyst Locking</h3>
          </div>
          <p className="text-xs text-slate-400 font-sans">
            Acquire distributed locks on active incident alerts to prevent duplicate triage efforts across distributed SOC analysts.
          </p>

          <div className="space-y-3 pt-2 text-xs">
            <div>
              <label className="text-slate-400 block mb-1">Target Incident / Alert ID</label>
              <input
                type="text"
                value={lockAlertId}
                onChange={(e) => setLockAlertId(e.target.value)}
                className="w-full bg-base-950 border border-base-700 text-slate-200 p-2 rounded focus:outline-none font-mono"
              />
            </div>

            <button
              onClick={handleAcquireLock}
              className="w-full bg-amber-600 hover:bg-amber-500 text-slate-950 font-bold py-2 rounded text-xs transition"
            >
              Acquire Co-Triage Lock
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
