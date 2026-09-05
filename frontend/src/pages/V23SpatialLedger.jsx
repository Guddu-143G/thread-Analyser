import React, { useState, useEffect, useRef } from 'react'
import client from '../api/client'

export default function V23SpatialLedger() {
  const [activeTab, setActiveTab] = useState('gnn') // gnn, rasp, cpa, ledger
  const [engineStatus, setEngineStatus] = useState(null)
  const [loading, setLoading] = useState(true)
  const [actionLoading, setActionLoading] = useState(false)
  const [error, setError] = useState('')
  const [successMsg, setSuccessMsg] = useState('')

  // -------------------------------------------------------------
  // TAB 1: GNN Spatial-Temporal UEBA State
  // -------------------------------------------------------------
  const [gnnTopology, setGnnTopology] = useState(null)
  const [anomalyResult, setAnomalyResult] = useState(null)
  const [selectedEventType, setSelectedEventType] = useState('auth')
  const [sourceEntity, setSourceEntity] = useState('admin_alice')
  const [targetEntity, setTargetEntity] = useState('srv-finance-db01')

  // -------------------------------------------------------------
  // TAB 2: eBPF CO-RE LSM RASP Controller State
  // -------------------------------------------------------------
  const [raspStatus, setRaspStatus] = useState(null)
  const [targetUid, setTargetUid] = useState(1000)
  const [enforceKill, setEnforceKill] = useState(true)
  const [simBinary, setSimBinary] = useState('/dev/shm/suspicious_elf')
  const [simArgs, setSimArgs] = useState('-e /bin/sh')
  const [simUid, setSimUid] = useState(1000)
  const [raspSimResult, setRaspSimResult] = useState(null)

  // -------------------------------------------------------------
  // TAB 3: SEP Side-Channel CPA Oscilloscope State
  // -------------------------------------------------------------
  const [cpaKeyLength, setCpaKeyLength] = useState(8)
  const [cpaTraceCount, setCpaTraceCount] = useState(60)
  const [cpaNoiseLevel, setCpaNoiseLevel] = useState(0.2)
  const [cpaTargetKeyHex, setCpaTargetKeyHex] = useState('5345435245543233') // "SECRET23"
  const [traceData, setTraceData] = useState(null)
  const [cpaAnalysisResult, setCpaAnalysisResult] = useState(null)

  // -------------------------------------------------------------
  // TAB 4: Merkle Temporal SQL Ledger State
  // -------------------------------------------------------------
  const [ledgerRecords, setLedgerRecords] = useState([])
  const [ledgerVerification, setLedgerVerification] = useState(null)
  const [newRecordDevice, setNewRecordDevice] = useState({
    device_id: 'dev-sec-enclave-01',
    hostname: 'srv-vault-node-alpha',
    ip_address: '10.200.4.15',
    system_status: 'isolated',
    operation_type: 'UPDATE'
  })
  const [tamperTargetId, setTamperTargetId] = useState('')

  // Fetch initial engine status
  const fetchGlobalStatus = async (isQuiet = false) => {
    try {
      if (!isQuiet) setLoading(true)
      const res = await client.get('/v23/status')
      setEngineStatus(res.data)
    } catch (err) {
      console.error('Failed to load V23 status:', err)
      if (!isQuiet) setError('Failed to connect to V23 Spatial-Ledger Engine.')
    } finally {
      if (!isQuiet) setLoading(false)
    }
  }

  // Fetch GNN Topology
  const fetchGnnTopology = async () => {
    try {
      const res = await client.get('/v23/gnn/topology')
      setGnnTopology(res.data)
    } catch (err) {
      console.error('Failed to load GNN topology:', err)
    }
  }

  // Fetch RASP Status
  const fetchRaspStatus = async () => {
    try {
      const res = await client.get('/v23/rasp/status')
      setRaspStatus(res.data)
    } catch (err) {
      console.error('Failed to load RASP status:', err)
    }
  }

  // Fetch CPA Traces
  const fetchCpaTraces = async () => {
    try {
      const res = await client.post('/v23/side-channel/traces/generate', {
        num_traces: cpaTraceCount,
        key_length: cpaKeyLength,
        target_key_hex: cpaTargetKeyHex,
        noise_level: cpaNoiseLevel
      })
      setTraceData(res.data)
    } catch (err) {
      console.error('Failed to fetch CPA traces:', err)
    }
  }

  // Fetch Ledger Records
  const fetchLedger = async () => {
    try {
      const res = await client.get('/v23/ledger/records?limit=30')
      setLedgerRecords(res.data || [])
      if (res.data && res.data.length > 0 && !tamperTargetId) {
        setTamperTargetId(res.data[0].ledger_id)
      }
    } catch (err) {
      console.error('Failed to load ledger records:', err)
    }
  }

  useEffect(() => {
    fetchGlobalStatus()
    fetchGnnTopology()
    fetchRaspStatus()
    fetchCpaTraces()
    fetchLedger()
    const interval = setInterval(() => {
      fetchGlobalStatus(true)
      fetchGnnTopology()
      fetchRaspStatus()
      fetchLedger()
    }, 5000)
    return () => clearInterval(interval)
  }, [])

  // -------------------------------------------------------------
  // GNN Actions
  // -------------------------------------------------------------
  const handleIngestOcsf = async () => {
    try {
      setActionLoading(true)
      setError('')
      const res = await client.post('/v23/gnn/events/ingest', {
        event_type: selectedEventType,
        source_entity: sourceEntity,
        target_entity: targetEntity
      })
      setSuccessMsg(`Entity interaction ingested. Graph contains ${res.data.total_nodes_in_graph} nodes and ${res.data.total_edges_in_graph} edges.`)
      fetchGnnTopology()
      fetchGlobalStatus()
      setTimeout(() => setSuccessMsg(''), 4000)
    } catch (err) {
      setError('Failed to ingest entity event into GNN core.')
    } finally {
      setActionLoading(false)
    }
  }

  const handleRunGnnInference = async () => {
    try {
      setActionLoading(true)
      setError('')
      const res = await client.post('/v23/gnn/anomaly/score')
      setAnomalyResult(res.data)
      setSuccessMsg(`GNN Inference completed: Mean Anomaly ${(res.data.mean_anomaly_score * 100).toFixed(1)}% | Max ${(res.data.max_anomaly_score * 100).toFixed(1)}%`)
      setTimeout(() => setSuccessMsg(''), 5000)
    } catch (err) {
      setError('GNN anomaly inference failed.')
    } finally {
      setActionLoading(false)
    }
  }

  // -------------------------------------------------------------
  // RASP Actions
  // -------------------------------------------------------------
  const handleUpdateRaspPolicy = async (e) => {
    e.preventDefault()
    try {
      setActionLoading(true)
      setError('')
      const res = await client.post('/v23/rasp/policy', {
        uid: parseInt(targetUid, 10),
        enforce_kill: enforceKill
      })
      setSuccessMsg(`eBPF Map Synchronized: UID ${targetUid} enforcement set to ${res.data.policy_mode}`)
      fetchRaspStatus()
      setTimeout(() => setSuccessMsg(''), 4000)
    } catch (err) {
      setError('Failed to update eBPF LSM policy map.')
    } finally {
      setActionLoading(false)
    }
  }

  const handleSimulateRaspExec = async () => {
    try {
      setActionLoading(true)
      setError('')
      const res = await client.post('/v23/rasp/simulate-execution', {
        uid: parseInt(simUid, 10),
        binary_path: simBinary,
        command_args: simArgs
      })
      setRaspSimResult(res.data)
      setSuccessMsg(`LSM Kernel Action: ${res.data.action} (Exit Code: ${res.data.exit_code})`)
      setTimeout(() => setSuccessMsg(''), 5000)
    } catch (err) {
      setError('eBPF execution simulation failed.')
    } finally {
      setActionLoading(false)
    }
  }

  // -------------------------------------------------------------
  // CPA Actions
  // -------------------------------------------------------------
  const handleRunCpa = async () => {
    try {
      setActionLoading(true)
      setError('')
      const res = await client.post('/v23/side-channel/cpa/analyze', {
        num_traces: cpaTraceCount,
        key_length: cpaKeyLength,
        target_key_hex: cpaTargetKeyHex
      })
      setCpaAnalysisResult(res.data)
      setSuccessMsg(`CPA Attack Success: Reconstructed "${res.data.recovered_key_text}" (Hex: ${res.data.recovered_key_hex}) with Peak Correlation ${res.data.max_correlation_peak}`)
      setTimeout(() => setSuccessMsg(''), 5000)
    } catch (err) {
      setError('Correlation Power Analysis failed.')
    } finally {
      setActionLoading(false)
    }
  }

  // -------------------------------------------------------------
  // Merkle Ledger Actions
  // -------------------------------------------------------------
  const handleAppendLedger = async (e) => {
    e.preventDefault()
    try {
      setActionLoading(true)
      setError('')
      const res = await client.post('/v23/ledger/append', newRecordDevice)
      setSuccessMsg(`Appended Block ${res.data.ledger_id.slice(0, 8)} with hash ${res.data.record_hash.slice(0, 12)}...`)
      fetchLedger()
      fetchGlobalStatus()
      setTimeout(() => setSuccessMsg(''), 4000)
    } catch (err) {
      setError('Failed to append record to Merkle ledger.')
    } finally {
      setActionLoading(false)
    }
  }

  const handleVerifyLedger = async () => {
    try {
      setActionLoading(true)
      setError('')
      const res = await client.get('/v23/ledger/verify')
      setLedgerVerification(res.data)
      if (res.data.is_valid) {
        setSuccessMsg(`Ledger Integrity VERIFIED! ${res.data.verified_blocks} blocks cryptographically intact.`)
      } else {
        setError(`INTEGRITY BREACH DETECTED! ${res.data.tampered_blocks_count} tampered block(s) detected.`)
      }
      setTimeout(() => setSuccessMsg(''), 6000)
    } catch (err) {
      setError('Ledger cryptographic verification failed.')
    } finally {
      setActionLoading(false)
    }
  }

  const handleTamperLedger = async () => {
    try {
      setActionLoading(true)
      setError('')
      const res = await client.post('/v23/ledger/tamper-simulation', null, {
        params: tamperTargetId ? { ledger_id: tamperTargetId } : {}
      })
      setSuccessMsg(`Rogue DBA SQL Mutation Injected: Altered block ${res.data.tampered_ledger_id.slice(0, 8)}. Click "Verify Chain" to inspect detection!`)
      fetchLedger()
      setTimeout(() => setSuccessMsg(''), 6000)
    } catch (err) {
      setError('Failed to simulate DBA ledger tamper.')
    } finally {
      setActionLoading(false)
    }
  }

  return (
    <div className="space-y-6 text-slate-200">
      {/* Top Banner & Title */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-gradient-to-r from-base-900 via-indigo-950/40 to-base-900 p-6 rounded-xl border border-indigo-500/20 shadow-2xl backdrop-blur-md">
        <div>
          <div className="flex items-center gap-3">
            <span className="p-2.5 bg-indigo-500/10 border border-indigo-500/30 rounded-lg text-indigo-400 font-mono text-xl shadow-[0_0_15px_rgba(99,102,241,0.25)]">
              ⚛
            </span>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-2xl font-bold font-mono tracking-tight text-white">
                  SPATIAL-TEMPORAL UEBA &amp; MERKLE LEDGER
                </h1>
                <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                  v23.0.0
                </span>
              </div>
              <p className="text-sm text-slate-400 mt-0.5">
                PyG Heterogeneous Graph Core • eBPF CO-RE LSM RASP • SEP Side-Channel CPA • Merkle-Chained SQL Ledger
              </p>
            </div>
          </div>
        </div>

        {/* Global Status Indicators */}
        <div className="flex items-center gap-3">
          <div className="px-3 py-2 bg-base-950/80 rounded-lg border border-base-700/80 font-mono text-xs flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-indigo-400 animate-pulse"></span>
            <span className="text-slate-400">GNN Graph:</span>
            <span className="text-indigo-400 font-semibold">{engineStatus?.gnn_active_nodes || 0} Nodes</span>
          </div>
          <div className="px-3 py-2 bg-base-950/80 rounded-lg border border-base-700/80 font-mono text-xs flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse"></span>
            <span className="text-slate-400">eBPF Driver:</span>
            <span className="text-cyan-400 font-semibold">CO-RE Active</span>
          </div>
          <div className="px-3 py-2 bg-base-950/80 rounded-lg border border-base-700/80 font-mono text-xs flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
            <span className="text-slate-400">Ledger Status:</span>
            <span className="text-emerald-400 font-semibold">{engineStatus?.ledger_integrity_state || 'VERIFIED'}</span>
          </div>
        </div>
      </div>

      {/* Error & Success Alerts */}
      {error && (
        <div className="p-4 bg-rose-950/60 border border-rose-800/80 rounded-lg text-rose-300 font-mono text-xs flex items-center justify-between shadow-lg">
          <div className="flex items-center gap-2">
            <span className="text-base">⚠</span>
            <span>{error}</span>
          </div>
          <button onClick={() => setError('')} className="text-rose-400 hover:text-rose-200">✕</button>
        </div>
      )}
      {successMsg && (
        <div className="p-4 bg-emerald-950/60 border border-emerald-800/80 rounded-lg text-emerald-300 font-mono text-xs flex items-center justify-between shadow-lg">
          <div className="flex items-center gap-2">
            <span className="text-base">✓</span>
            <span>{successMsg}</span>
          </div>
          <button onClick={() => setSuccessMsg('')} className="text-emerald-400 hover:text-emerald-200">✕</button>
        </div>
      )}

      {/* Main Tab Navigation */}
      <div className="flex border-b border-base-700/80 space-x-2">
        <button
          onClick={() => setActiveTab('gnn')}
          className={`px-5 py-3 font-mono text-xs font-semibold rounded-t-lg transition-all flex items-center gap-2 ${
            activeTab === 'gnn'
              ? 'bg-base-900 border-t-2 border-l border-r border-t-indigo-500 border-l-base-700 border-r-base-700 text-indigo-300 shadow-lg'
              : 'text-slate-400 hover:text-slate-200 hover:bg-base-900/40'
          }`}
        >
          <span>🕸</span>
          <span>1. GNN Spatial-Temporal UEBA</span>
        </button>

        <button
          onClick={() => setActiveTab('rasp')}
          className={`px-5 py-3 font-mono text-xs font-semibold rounded-t-lg transition-all flex items-center gap-2 ${
            activeTab === 'rasp'
              ? 'bg-base-900 border-t-2 border-l border-r border-t-cyan-500 border-l-base-700 border-r-base-700 text-cyan-300 shadow-lg'
              : 'text-slate-400 hover:text-slate-200 hover:bg-base-900/40'
          }`}
        >
          <span>🛡</span>
          <span>2. eBPF CO-RE LSM RASP</span>
        </button>

        <button
          onClick={() => setActiveTab('cpa')}
          className={`px-5 py-3 font-mono text-xs font-semibold rounded-t-lg transition-all flex items-center gap-2 ${
            activeTab === 'cpa'
              ? 'bg-base-900 border-t-2 border-l border-r border-t-purple-500 border-l-base-700 border-r-base-700 text-purple-300 shadow-lg'
              : 'text-slate-400 hover:text-slate-200 hover:bg-base-900/40'
          }`}
        >
          <span>⚡</span>
          <span>3. SEP Side-Channel CPA</span>
        </button>

        <button
          onClick={() => setActiveTab('ledger')}
          className={`px-5 py-3 font-mono text-xs font-semibold rounded-t-lg transition-all flex items-center gap-2 ${
            activeTab === 'ledger'
              ? 'bg-base-900 border-t-2 border-l border-r border-t-emerald-500 border-l-base-700 border-r-base-700 text-emerald-300 shadow-lg'
              : 'text-slate-400 hover:text-slate-200 hover:bg-base-900/40'
          }`}
        >
          <span>⛓</span>
          <span>4. Merkle Temporal SQL Ledger</span>
        </button>
      </div>

      {/* ============================================================= */}
      {/* TAB 1: GNN Spatial-Temporal UEBA Core                         */}
      {/* ============================================================= */}
      {activeTab === 'gnn' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Left Column: Entity Interaction Ingest */}
          <div className="lg:col-span-5 space-y-6">
            <div className="bg-base-900/90 border border-base-700/80 rounded-xl p-5 shadow-xl space-y-4">
              <div className="flex items-center justify-between border-b border-base-700 pb-3">
                <h3 className="font-mono text-sm font-bold text-slate-100 flex items-center gap-2">
                  <span className="text-indigo-400">◈</span> Ingest Entity Interaction
                </h3>
                <span className="text-[10px] font-mono text-indigo-400 bg-indigo-950/60 px-2 py-0.5 rounded border border-indigo-800/60">
                  OCSF Unified
                </span>
              </div>

              <div>
                <label className="block text-xs font-mono text-slate-400 mb-1">Interaction Topology Class:</label>
                <select
                  value={selectedEventType}
                  onChange={(e) => setSelectedEventType(e.target.value)}
                  className="w-full bg-base-950 border border-base-700 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 focus:border-indigo-500 focus:outline-none"
                >
                  <option value="auth">Authentication: User ➔ Device (Class 3002)</option>
                  <option value="process">Process Spawn: Device ➔ Process (Class 1007)</option>
                  <option value="file">File Access: Process ➔ File (Class 1001)</option>
                  <option value="network">Network Egress: Device ➔ IP (Class 4001)</option>
                </select>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-mono text-slate-400 mb-1">Source Entity:</label>
                  <input
                    type="text"
                    value={sourceEntity}
                    onChange={(e) => setSourceEntity(e.target.value)}
                    className="w-full bg-base-950 border border-base-700 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 focus:border-indigo-500 focus:outline-none"
                  />
                </div>
                <div>
                  <label className="block text-xs font-mono text-slate-400 mb-1">Target Entity:</label>
                  <input
                    type="text"
                    value={targetEntity}
                    onChange={(e) => setTargetEntity(e.target.value)}
                    className="w-full bg-base-950 border border-base-700 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 focus:border-indigo-500 focus:outline-none"
                  />
                </div>
              </div>

              <div className="flex gap-2 pt-1">
                <button
                  disabled={actionLoading}
                  onClick={handleIngestOcsf}
                  className="flex-1 py-2.5 bg-indigo-600 hover:bg-indigo-500 text-white font-mono text-xs font-semibold rounded-lg transition-all shadow-md active:scale-95 flex items-center justify-center gap-2"
                >
                  <span>⚡</span> Ingest into Graph
                </button>
                <button
                  disabled={actionLoading}
                  onClick={handleRunGnnInference}
                  className="flex-1 py-2.5 bg-emerald-600 hover:bg-emerald-500 text-white font-mono text-xs font-semibold rounded-lg transition-all shadow-md active:scale-95 flex items-center justify-center gap-2"
                >
                  <span>🧠</span> Run GNN Inference
                </button>
              </div>
            </div>

            {/* Inference Result Card */}
            {anomalyResult && (
              <div className={`p-5 rounded-xl border shadow-xl ${
                anomalyResult.is_anomalous
                  ? 'bg-rose-950/40 border-rose-600/50 text-rose-200'
                  : 'bg-emerald-950/30 border-emerald-600/40 text-emerald-200'
              }`}>
                <div className="flex items-center justify-between mb-3">
                  <span className="font-mono text-xs font-bold uppercase tracking-wider flex items-center gap-2">
                    <span className={`w-2.5 h-2.5 rounded-full ${anomalyResult.is_anomalous ? 'bg-rose-500 animate-ping' : 'bg-emerald-400'}`}></span>
                    {anomalyResult.is_anomalous ? 'ANOMALOUS TOPOLOGY BURST' : 'STABLE BASELINE TOPOLOGY'}
                  </span>
                  <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-base-950/80 border border-base-700">
                    Edges: {anomalyResult.evaluated_edges_count}
                  </span>
                </div>

                <div className="space-y-3">
                  <div>
                    <div className="flex justify-between text-xs font-mono mb-1">
                      <span>Max Anomaly Peak:</span>
                      <span className="font-bold text-sm">{(anomalyResult.max_anomaly_score * 100).toFixed(1)}%</span>
                    </div>
                    <div className="w-full bg-base-950 h-2.5 rounded-full overflow-hidden border border-base-800">
                      <div
                        className={`h-full transition-all duration-700 ${
                          anomalyResult.max_anomaly_score > 0.65 ? 'bg-rose-500' : anomalyResult.max_anomaly_score > 0.4 ? 'bg-amber-500' : 'bg-emerald-500'
                        }`}
                        style={{ width: `${Math.min(100, anomalyResult.max_anomaly_score * 100)}%` }}
                      ></div>
                    </div>
                  </div>

                  <div className="text-[11px] font-mono bg-base-950/80 p-2.5 rounded border border-base-800/80 space-y-1">
                    <div><span className="text-slate-400">Mean Anomaly Score:</span> <span className="text-slate-200 font-bold">{(anomalyResult.mean_anomaly_score * 100).toFixed(2)}%</span></div>
                    <div><span className="text-slate-400">Evaluated Edges:</span> <span className="text-slate-200">{anomalyResult.evaluated_edges_count} directional pairs</span></div>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Right Column: PyG Tensor Graph Topology Visualizer */}
          <div className="lg:col-span-7 space-y-6">
            <div className="bg-base-900/90 border border-base-700/80 rounded-xl p-5 shadow-xl space-y-4">
              <div className="flex items-center justify-between border-b border-base-700 pb-3">
                <div>
                  <h3 className="font-mono text-sm font-bold text-slate-100 flex items-center gap-2">
                    <span className="text-indigo-400">🕸</span> PyTorch Geometric (PyG) Tensor Matrix
                  </h3>
                  <p className="text-[11px] font-mono text-slate-400">
                    Heterogeneous Multi-Entity Feature Embeddings &amp; Directed Edges
                  </p>
                </div>
                <div className="flex gap-2">
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-indigo-950 text-indigo-300 border border-indigo-800">
                    Nodes: {gnnTopology?.total_nodes || 0}
                  </span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-800">
                    Edges: {gnnTopology?.total_edges || 0}
                  </span>
                </div>
              </div>

              {/* Tensor Metadata Shapes */}
              <div className="grid grid-cols-3 gap-3">
                <div className="bg-base-950 p-3 rounded-lg border border-base-800 font-mono text-xs">
                  <div className="text-slate-400 text-[10px]">Node Features (X)</div>
                  <div className="text-indigo-300 font-bold mt-0.5">{gnnTopology?.pyg_tensor_shapes?.node_features_x || '[0, 8]'}</div>
                </div>
                <div className="bg-base-950 p-3 rounded-lg border border-base-800 font-mono text-xs">
                  <div className="text-slate-400 text-[10px]">Edge Index (2, |E|)</div>
                  <div className="text-purple-300 font-bold mt-0.5">{gnnTopology?.pyg_tensor_shapes?.edge_index || '[2, 0]'}</div>
                </div>
                <div className="bg-base-950 p-3 rounded-lg border border-base-800 font-mono text-xs">
                  <div className="text-slate-400 text-[10px]">Edge Attributes (|E|,)</div>
                  <div className="text-cyan-300 font-bold mt-0.5">{gnnTopology?.pyg_tensor_shapes?.edge_attr || '[0]'}</div>
                </div>
              </div>

              {/* Node Graph Entities Grid */}
              <div className="bg-base-950 border border-base-800 rounded-xl p-4 min-h-[260px] relative overflow-hidden flex flex-col justify-between">
                <div className="absolute inset-0 opacity-10 pointer-events-none bg-[radial-gradient(#6366f1_1px,transparent_1px)] [background-size:16px_16px]"></div>

                <div className="text-[11px] font-mono text-slate-400 flex justify-between items-center mb-2">
                  <span>ACTIVE SPATIAL GRAPH ENTITIES</span>
                  <span className="text-indigo-400">Mean Anomaly: {((gnnTopology?.mean_anomaly_score || 0) * 100).toFixed(1)}%</span>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 relative z-10 max-h-72 overflow-y-auto pr-1">
                  {(gnnTopology?.nodes || []).map((node, idx) => (
                    <div
                      key={idx}
                      className="p-2.5 rounded-lg bg-base-900/80 border border-base-700/80 hover:border-indigo-500/50 transition-all font-mono text-xs shadow"
                    >
                      <div className="flex items-center justify-between mb-1">
                        <span className={`text-[10px] font-bold px-1.5 py-0.2 rounded ${
                          node.node_type === 'user' ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                          node.node_type === 'device' ? 'bg-cyan-950 text-cyan-300 border border-cyan-800' :
                          node.node_type === 'ip' ? 'bg-indigo-950 text-indigo-300 border border-indigo-800' :
                          'bg-emerald-950 text-emerald-300 border border-emerald-800'
                        }`}>
                          {node.node_type.toUpperCase()}
                        </span>
                        <span className="text-[10px] text-slate-500">deg: {node.degree}</span>
                      </div>
                      <div className="text-slate-200 font-bold truncate text-[11px]" title={node.node_key}>
                        {node.node_key.split(':').slice(2).join(':') || node.node_key}
                      </div>
                      <div className="text-[10px] text-slate-400 truncate mt-1">
                        score: <span className={node.is_anomalous ? 'text-rose-400 font-bold' : 'text-emerald-400'}>{(node.anomaly_score * 100).toFixed(1)}%</span>
                      </div>
                    </div>
                  ))}
                </div>

                <div className="mt-4 pt-3 border-t border-base-800 text-[10px] font-mono text-slate-500 flex justify-between">
                  <span>GNN Layer: Heterogeneous GraphSAGE / GATv2</span>
                  <span>Spatial-Temporal Resolution: Real-Time</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ============================================================= */}
      {/* TAB 2: eBPF CO-RE LSM RASP Controller                         */}
      {/* ============================================================= */}
      {activeTab === 'rasp' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Left Column: BPF Map Policy Manager */}
          <div className="lg:col-span-5 space-y-6">
            <div className="bg-base-900/90 border border-base-700/80 rounded-xl p-5 shadow-xl space-y-4">
              <div className="flex items-center justify-between border-b border-base-700 pb-3">
                <div>
                  <h3 className="font-mono text-sm font-bold text-slate-100 flex items-center gap-2">
                    <span className="text-cyan-400">🛡</span> eBPF CO-RE LSM Policy Map
                  </h3>
                  <p className="text-[11px] font-mono text-slate-400">
                    Live In-Kernel LSM Hook Controller
                  </p>
                </div>
                <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950 px-2 py-0.5 rounded border border-cyan-800">
                  {raspStatus?.status || 'ONLINE_ACTIVE'}
                </span>
              </div>

              <form onSubmit={handleUpdateRaspPolicy} className="space-y-4">
                <div>
                  <label className="block text-xs font-mono text-slate-400 mb-1">Target Service UID:</label>
                  <input
                    type="number"
                    value={targetUid}
                    onChange={(e) => setTargetUid(e.target.value)}
                    className="w-full bg-base-950 border border-base-700 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 focus:border-cyan-500 focus:outline-none"
                  />
                  <span className="text-[10px] text-slate-500 font-mono mt-0.5 block">
                    e.g., 1000 (app user), 33 (www-data), 0 (root)
                  </span>
                </div>

                <div className="space-y-2 bg-base-950 p-3 rounded-lg border border-base-800 font-mono text-xs">
                  <div className="text-slate-400 text-[10px] uppercase font-bold mb-1">Enforcement Mode:</div>
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="radio"
                      name="policy_mode"
                      checked={enforceKill}
                      onChange={() => setEnforceKill(true)}
                      className="text-cyan-500 focus:ring-0"
                    />
                    <span className="text-slate-300 text-xs">ENFORCE_BLOCK (Return -EPERM on suspicious execution)</span>
                  </label>
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="radio"
                      name="policy_mode"
                      checked={!enforceKill}
                      onChange={() => setEnforceKill(false)}
                      className="text-cyan-500 focus:ring-0"
                    />
                    <span className="text-slate-300 text-xs">AUDIT_LOG (Log telemetry without blocking)</span>
                  </label>
                </div>

                <button
                  type="submit"
                  disabled={actionLoading}
                  className="w-full py-2.5 bg-cyan-600 hover:bg-cyan-500 text-white font-mono text-xs font-semibold rounded-lg transition-all shadow-md active:scale-95 flex items-center justify-center gap-2"
                >
                  <span>⚡</span> Commit to Kernel BPF Map
                </button>
              </form>
            </div>

            {/* Active LSM Probes Status Card */}
            <div className="bg-base-900/90 border border-base-700/80 rounded-xl p-5 shadow-xl space-y-3 font-mono text-xs">
              <div className="text-slate-200 font-bold border-b border-base-700 pb-2">
                Kernel CO-RE LSM Telemetry
              </div>
              <div className="grid grid-cols-2 gap-2 text-[11px]">
                <div className="bg-base-950 p-2 rounded border border-base-800">
                  <span className="text-slate-500 block">Relocation Type:</span>
                  <span className="text-cyan-400 font-bold truncate">{raspStatus?.relocation_type || 'libbpf CO-RE'}</span>
                </div>
                <div className="bg-base-950 p-2 rounded border border-base-800">
                  <span className="text-slate-500 block">LSM Hook:</span>
                  <span className="text-emerald-400 font-bold">{raspStatus?.kernel_hook || 'lsm/bprm_check_security'}</span>
                </div>
                <div className="bg-base-950 p-2 rounded border border-base-800">
                  <span className="text-slate-500 block">Active Policies:</span>
                  <span className="text-slate-200 font-bold">{raspStatus?.active_policies_count || 3} UIDs</span>
                </div>
                <div className="bg-base-950 p-2 rounded border border-base-800">
                  <span className="text-slate-500 block">BTF Source:</span>
                  <span className="text-slate-200 font-bold truncate">{raspStatus?.btf_path || '/sys/kernel/btf/vmlinux'}</span>
                </div>
              </div>
            </div>
          </div>

          {/* Right Column: Syscall Execution Simulation */}
          <div className="lg:col-span-7 space-y-6">
            <div className="bg-base-900/90 border border-base-700/80 rounded-xl p-5 shadow-xl space-y-4">
              <div className="flex items-center justify-between border-b border-base-700 pb-3">
                <div>
                  <h3 className="font-mono text-sm font-bold text-slate-100 flex items-center gap-2">
                    <span className="text-cyan-400">⚡</span> Kernel LSM Execution Interceptor
                  </h3>
                  <p className="text-[11px] font-mono text-slate-400">
                    Simulate Binary Spawning Against Active LSM Bounds
                  </p>
                </div>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-base-950 text-slate-400 border border-base-800">
                  Kernel Space
                </span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 font-mono text-xs">
                <div>
                  <label className="block text-slate-400 mb-1 text-[11px]">Binary Path:</label>
                  <select
                    value={simBinary}
                    onChange={(e) => setSimBinary(e.target.value)}
                    className="w-full bg-base-950 border border-base-700 rounded-lg px-2.5 py-2 text-slate-200 focus:border-cyan-500 focus:outline-none"
                  >
                    <option value="/dev/shm/suspicious_elf">/dev/shm/suspicious_elf (Shared Mem)</option>
                    <option value="/tmp/.hidden_dropper">/tmp/.hidden_dropper (Temp Dropper)</option>
                    <option value="/usr/bin/python3">/usr/bin/python3 (Approved Binary)</option>
                    <option value="/usr/bin/ls">/usr/bin/ls (Approved Tool)</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-400 mb-1 text-[11px]">Execution UID:</label>
                  <input
                    type="number"
                    value={simUid}
                    onChange={(e) => setSimUid(e.target.value)}
                    className="w-full bg-base-950 border border-base-700 rounded-lg px-2.5 py-2 text-slate-200 focus:border-cyan-500 focus:outline-none"
                  />
                </div>

                <div>
                  <label className="block text-slate-400 mb-1 text-[11px]">Command Arguments:</label>
                  <input
                    type="text"
                    value={simArgs}
                    onChange={(e) => setSimArgs(e.target.value)}
                    className="w-full bg-base-950 border border-base-700 rounded-lg px-2.5 py-2 text-slate-200 focus:border-cyan-500 focus:outline-none"
                  />
                </div>
              </div>

              <button
                disabled={actionLoading}
                onClick={handleSimulateRaspExec}
                className="w-full py-2.5 bg-cyan-600 hover:bg-cyan-500 text-white font-mono text-xs font-semibold rounded-lg transition-all shadow-md active:scale-95 flex items-center justify-center gap-2"
              >
                <span>▶</span> Execute Kernel LSM Hook Check
              </button>

              {/* Simulation Result Terminal Output */}
              {raspSimResult && (
                <div className="bg-base-950 border border-base-800 rounded-xl p-4 font-mono text-xs space-y-3">
                  <div className="flex items-center justify-between border-b border-base-800 pb-2">
                    <span className="text-slate-400 text-[11px]">LSM KERNEL DISPATCH LOG</span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                      raspSimResult.action === 'BLOCKED_EPERM'
                        ? 'bg-rose-950 text-rose-300 border border-rose-800'
                        : 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                    }`}>
                      {raspSimResult.action}
                    </span>
                  </div>

                  <div className="space-y-1.5 text-[11px]">
                    <div className="flex justify-between">
                      <span className="text-slate-500">Binary Path:</span>
                      <span className="text-slate-200 font-bold">{raspSimResult.binary_path}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">Caller UID:</span>
                      <span className="text-slate-200 font-bold">{raspSimResult.uid}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">Exit Code:</span>
                      <span className={raspSimResult.exit_code === 0 ? 'text-emerald-400 font-bold' : 'text-rose-400 font-bold'}>
                        {raspSimResult.exit_code} ({raspSimResult.errno || 'SUCCESS'})
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">LSM Rationale:</span>
                      <span className="text-slate-300">{raspSimResult.reason}</span>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ============================================================= */}
      {/* TAB 3: SEP Side-Channel CPA Oscilloscope                      */}
      {/* ============================================================= */}
      {activeTab === 'cpa' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Left Column: Trace Generation & Configuration */}
          <div className="lg:col-span-5 space-y-6">
            <div className="bg-base-900/90 border border-base-700/80 rounded-xl p-5 shadow-xl space-y-4">
              <div className="flex items-center justify-between border-b border-base-700 pb-3">
                <div>
                  <h3 className="font-mono text-sm font-bold text-slate-100 flex items-center gap-2">
                    <span className="text-purple-400">⚡</span> Side-Channel Power Analysis
                  </h3>
                  <p className="text-[11px] font-mono text-slate-400">
                    Hamming Weight Hypothesis &amp; Pearson Correlation
                  </p>
                </div>
                <span className="text-[10px] font-mono text-purple-400 bg-purple-950 px-2 py-0.5 rounded border border-purple-800">
                  Subsystem: SEP
                </span>
              </div>

              <div className="grid grid-cols-2 gap-3 font-mono text-xs">
                <div>
                  <label className="block text-slate-400 mb-1 text-[11px]">Traces Sampled (N):</label>
                  <input
                    type="number"
                    value={cpaTraceCount}
                    onChange={(e) => setCpaTraceCount(parseInt(e.target.value, 10))}
                    className="w-full bg-base-950 border border-base-700 rounded-lg px-2.5 py-2 text-slate-200 focus:border-purple-500 focus:outline-none"
                  />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1 text-[11px]">Key Length (Bytes):</label>
                  <input
                    type="number"
                    value={cpaKeyLength}
                    onChange={(e) => setCpaKeyLength(parseInt(e.target.value, 10))}
                    className="w-full bg-base-950 border border-base-700 rounded-lg px-2.5 py-2 text-slate-200 focus:border-purple-500 focus:outline-none"
                  />
                </div>
                <div className="col-span-2">
                  <label className="block text-slate-400 mb-1 text-[11px]">Target Key Hex Secret:</label>
                  <input
                    type="text"
                    value={cpaTargetKeyHex}
                    onChange={(e) => setCpaTargetKeyHex(e.target.value)}
                    className="w-full bg-base-950 border border-base-700 rounded-lg px-2.5 py-2 text-slate-200 font-bold focus:border-purple-500 focus:outline-none"
                  />
                </div>
              </div>

              <div className="flex gap-2">
                <button
                  disabled={actionLoading}
                  onClick={fetchCpaTraces}
                  className="flex-1 py-2.5 bg-base-800 hover:bg-base-700 text-slate-200 font-mono text-xs font-semibold rounded-lg transition-all"
                >
                  ↻ Sample Traces
                </button>
                <button
                  disabled={actionLoading}
                  onClick={handleRunCpa}
                  className="flex-1 py-2.5 bg-purple-600 hover:bg-purple-500 text-white font-mono text-xs font-semibold rounded-lg transition-all shadow-md active:scale-95 flex items-center justify-center gap-2"
                >
                  <span>⚡</span> Run CPA Attack
                </button>
              </div>
            </div>

            {/* CPA Recovery Card */}
            {cpaAnalysisResult && (
              <div className="bg-base-900/90 border border-purple-500/40 rounded-xl p-5 shadow-xl space-y-3 font-mono text-xs">
                <div className="flex items-center justify-between border-b border-base-700 pb-2">
                  <span className="text-purple-300 font-bold uppercase">RECONSTRUCTED KEY HYPOTHESIS</span>
                  <span className="text-[10px] bg-purple-950 text-purple-300 px-2 py-0.5 rounded border border-purple-800">
                    {cpaAnalysisResult.status}
                  </span>
                </div>

                <div className="space-y-2 text-[11px]">
                  <div>
                    <span className="text-slate-400 block mb-1">Reconstructed Key Text:</span>
                    <span className="text-purple-300 font-bold text-lg bg-base-950 px-3 py-1.5 rounded border border-purple-800/80 inline-block">
                      {cpaAnalysisResult.recovered_key_text}
                    </span>
                  </div>

                  <div>
                    <span className="text-slate-400 block mb-1">Reconstructed Key Hex:</span>
                    <span className="text-emerald-400 font-bold text-sm bg-base-950 px-2.5 py-1 rounded border border-base-800 inline-block font-mono">
                      0x{cpaAnalysisResult.recovered_key_hex}
                    </span>
                  </div>

                  <div>
                    <span className="text-slate-400 block mb-1">Peak Pearson Correlation:</span>
                    <span className="text-cyan-400 font-bold">{cpaAnalysisResult.max_correlation_peak}</span>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Right Column: Oscilloscope Power Waveform Canvas */}
          <div className="lg:col-span-7 space-y-6">
            <div className="bg-base-900/90 border border-base-700/80 rounded-xl p-5 shadow-xl space-y-4">
              <div className="flex items-center justify-between border-b border-base-700 pb-3">
                <div>
                  <h3 className="font-mono text-sm font-bold text-slate-100 flex items-center gap-2">
                    <span className="text-purple-400">📈</span> Power Consumption Waveform (DPA / CPA)
                  </h3>
                  <p className="text-[11px] font-mono text-slate-400">
                    Instantaneous Current Draw During Cryptographic XOR Execution
                  </p>
                </div>
                <span className="text-[10px] font-mono text-slate-400 bg-base-950 px-2 py-0.5 rounded border border-base-800">
                  Rate: {traceData?.simulated_sampling_rate_msps || 250} MS/s
                </span>
              </div>

              {/* Simulated Waveform Visualizer */}
              <div className="bg-base-950 border border-base-800 rounded-xl p-4 min-h-[260px] relative overflow-hidden flex flex-col justify-between">
                <div className="absolute inset-0 opacity-15 pointer-events-none bg-[radial-gradient(#a855f7_1px,transparent_1px)] [background-size:20px_20px]"></div>

                {/* Oscilloscope Grid Display */}
                <div className="h-44 w-full flex items-center justify-center relative">
                  <svg className="w-full h-full" viewBox="0 0 500 150" preserveAspectRatio="none">
                    <path
                      d="M 0 75 Q 30 20 60 75 T 120 75 T 180 30 T 240 120 T 300 75 T 360 40 T 420 110 T 500 75"
                      fill="none"
                      stroke="#a855f7"
                      strokeWidth="2"
                      className="opacity-80"
                    />
                    <path
                      d="M 0 75 Q 25 60 50 75 T 100 75 T 150 50 T 200 100 T 250 75 T 300 60 T 350 90 T 400 75 T 450 65 T 500 75"
                      fill="none"
                      stroke="#06b6d4"
                      strokeWidth="1.5"
                      className="opacity-60"
                    />
                    <path
                      d="M 0 75 Q 40 85 80 75 T 160 75 T 240 75 T 320 75 T 400 75 T 480 75 T 500 75"
                      fill="none"
                      stroke="#10b981"
                      strokeWidth="1"
                      className="opacity-40"
                    />
                  </svg>
                </div>

                <div className="flex justify-between items-center text-[10px] font-mono text-slate-500 border-t border-base-800/80 pt-2">
                  <span>Traces: {traceData?.traces_generated_count || cpaTraceCount}</span>
                  <span>Mean Power: {traceData?.power_consumption_mean_mw || 12.4} mW</span>
                  <span>Noise: σ={traceData?.noise_deviation || cpaNoiseLevel}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ============================================================= */}
      {/* TAB 4: Merkle Temporal SQL Ledger                             */}
      {/* ============================================================= */}
      {activeTab === 'ledger' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Left Column: Append & Tamper Actions */}
          <div className="lg:col-span-5 space-y-6">
            {/* Append Block Form */}
            <div className="bg-base-900/90 border border-base-700/80 rounded-xl p-5 shadow-xl space-y-4">
              <div className="flex items-center justify-between border-b border-base-700 pb-3">
                <div>
                  <h3 className="font-mono text-sm font-bold text-slate-100 flex items-center gap-2">
                    <span className="text-emerald-400">⛓</span> Append Cryptographic Ledger Block
                  </h3>
                  <p className="text-[11px] font-mono text-slate-400">
                    SHA-256 Chained Neon SQL Audit Record
                  </p>
                </div>
              </div>

              <form onSubmit={handleAppendLedger} className="space-y-3 font-mono text-xs">
                <div>
                  <label className="block text-slate-400 mb-1 text-[11px]">Device Identifier:</label>
                  <input
                    type="text"
                    value={newRecordDevice.device_id}
                    onChange={(e) => setNewRecordDevice({ ...newRecordDevice, device_id: e.target.value })}
                    className="w-full bg-base-950 border border-base-700 rounded-lg px-2.5 py-2 text-slate-200 focus:border-emerald-500 focus:outline-none"
                  />
                </div>

                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <label className="block text-slate-400 mb-1 text-[11px]">Hostname:</label>
                    <input
                      type="text"
                      value={newRecordDevice.hostname}
                      onChange={(e) => setNewRecordDevice({ ...newRecordDevice, hostname: e.target.value })}
                      className="w-full bg-base-950 border border-base-700 rounded-lg px-2.5 py-2 text-slate-200 focus:border-emerald-500 focus:outline-none"
                    />
                  </div>
                  <div>
                    <label className="block text-slate-400 mb-1 text-[11px]">IP Address:</label>
                    <input
                      type="text"
                      value={newRecordDevice.ip_address}
                      onChange={(e) => setNewRecordDevice({ ...newRecordDevice, ip_address: e.target.value })}
                      className="w-full bg-base-950 border border-base-700 rounded-lg px-2.5 py-2 text-slate-200 focus:border-emerald-500 focus:outline-none"
                    />
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <label className="block text-slate-400 mb-1 text-[11px]">System Status:</label>
                    <select
                      value={newRecordDevice.system_status}
                      onChange={(e) => setNewRecordDevice({ ...newRecordDevice, system_status: e.target.value })}
                      className="w-full bg-base-950 border border-base-700 rounded-lg px-2.5 py-2 text-slate-200 focus:border-emerald-500 focus:outline-none"
                    >
                      <option value="active">active</option>
                      <option value="isolated">isolated</option>
                      <option value="compromised">compromised</option>
                      <option value="decommissioned">decommissioned</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-slate-400 mb-1 text-[11px]">Operation:</label>
                    <select
                      value={newRecordDevice.operation_type}
                      onChange={(e) => setNewRecordDevice({ ...newRecordDevice, operation_type: e.target.value })}
                      className="w-full bg-base-950 border border-base-700 rounded-lg px-2.5 py-2 text-slate-200 focus:border-emerald-500 focus:outline-none"
                    >
                      <option value="INSERT">INSERT</option>
                      <option value="UPDATE">UPDATE</option>
                      <option value="DELETE">DELETE</option>
                    </select>
                  </div>
                </div>

                <div className="flex gap-2 pt-2">
                  <button
                    type="submit"
                    disabled={actionLoading}
                    className="flex-1 py-2.5 bg-emerald-600 hover:bg-emerald-500 text-white font-mono text-xs font-semibold rounded-lg transition-all shadow-md active:scale-95 flex items-center justify-center gap-2"
                  >
                    <span>+</span> Append Block
                  </button>
                  <button
                    type="button"
                    disabled={actionLoading}
                    onClick={handleVerifyLedger}
                    className="flex-1 py-2.5 bg-indigo-600 hover:bg-indigo-500 text-white font-mono text-xs font-semibold rounded-lg transition-all shadow-md active:scale-95 flex items-center justify-center gap-2"
                  >
                    <span>✓</span> Verify Chain
                  </button>
                </div>
              </form>
            </div>

            {/* DBA Tamper Demonstration Card */}
            <div className="bg-base-900/90 border border-rose-800/60 rounded-xl p-5 shadow-xl space-y-4 font-mono text-xs">
              <div className="flex items-center justify-between border-b border-base-700 pb-2">
                <span className="text-rose-400 font-bold uppercase flex items-center gap-2">
                  <span>⚠</span> Rogue DBA Tamper Simulator
                </span>
                <span className="text-[10px] bg-rose-950 text-rose-300 px-2 py-0.5 rounded border border-rose-800">
                  Direct SQL Mutation
                </span>
              </div>

              <div className="space-y-3">
                <div>
                  <label className="block text-slate-400 mb-1 text-[11px]">Target Ledger Block:</label>
                  <select
                    value={tamperTargetId}
                    onChange={(e) => setTamperTargetId(e.target.value)}
                    className="w-full bg-base-950 border border-base-700 rounded-lg px-2.5 py-2 text-slate-200 focus:border-rose-500 focus:outline-none"
                  >
                    {ledgerRecords.map((r) => (
                      <option key={r.ledger_id} value={r.ledger_id}>
                        {r.hostname} ({r.ledger_id.slice(0, 8)}... - {r.operation_type})
                      </option>
                    ))}
                  </select>
                </div>

                <button
                  type="button"
                  disabled={actionLoading}
                  onClick={handleTamperLedger}
                  className="w-full py-2.5 bg-rose-700 hover:bg-rose-600 text-white font-mono text-xs font-semibold rounded-lg transition-all active:scale-95 flex items-center justify-center gap-2"
                >
                  <span>⚡</span> Inject Silent SQL Update (Tamper Row)
                </button>
              </div>
            </div>
          </div>

          {/* Right Column: Merkle Ledger Explorer */}
          <div className="lg:col-span-7 space-y-6">
            <div className="bg-base-900/90 border border-base-700/80 rounded-xl p-5 shadow-xl space-y-4">
              <div className="flex items-center justify-between border-b border-base-700 pb-3">
                <div>
                  <h3 className="font-mono text-sm font-bold text-slate-100 flex items-center gap-2">
                    <span className="text-emerald-400">⛓</span> Cryptographically Chained SQL Blocks
                  </h3>
                  <p className="text-[11px] font-mono text-slate-400">
                    Parent Hash Pointer SHA-256 Linkages
                  </p>
                </div>
                <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950 px-2 py-0.5 rounded border border-emerald-800">
                  Total Blocks: {ledgerRecords.length}
                </span>
              </div>

              {/* Verification Result Banner */}
              {ledgerVerification && (
                <div className={`p-3 rounded-lg border font-mono text-xs flex items-center justify-between ${
                  ledgerVerification.is_valid
                    ? 'bg-emerald-950/40 border-emerald-700/60 text-emerald-300'
                    : 'bg-rose-950/60 border-rose-700 text-rose-200'
                }`}>
                  <div className="flex items-center gap-2">
                    <span>{ledgerVerification.is_valid ? '✓' : '✖'}</span>
                    <span>
                      {ledgerVerification.is_valid
                        ? `CHAIN INTACT: ${ledgerVerification.verified_blocks} blocks verified.`
                        : `CHAIN RUPTURE DETECTED: ${ledgerVerification.tampered_blocks_count} tampered block(s)!`}
                    </span>
                  </div>
                  <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-base-950">
                    {ledgerVerification.chain_status}
                  </span>
                </div>
              )}

              {/* Ledger Blocks List */}
              <div className="space-y-2.5 max-h-[460px] overflow-y-auto pr-1">
                {ledgerRecords.map((block, idx) => (
                  <div
                    key={block.ledger_id}
                    className="p-3 bg-base-950 border border-base-800 rounded-lg font-mono text-xs hover:border-emerald-500/50 transition-all space-y-1.5"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-slate-200 flex items-center gap-2">
                        <span className="text-slate-500 text-[10px]">#{idx + 1}</span>
                        <span>{block.hostname}</span>
                        <span className="text-[10px] text-slate-400 font-normal">({block.ip_address})</span>
                      </span>
                      <span className={`text-[10px] px-1.5 py-0.5 rounded font-bold ${
                        block.operation_type === 'INSERT' ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' :
                        block.operation_type === 'UPDATE' ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                        'bg-rose-950 text-rose-300 border border-rose-800'
                      }`}>
                        {block.operation_type}
                      </span>
                    </div>

                    <div className="text-[10px] text-slate-400 space-y-0.5">
                      <div className="truncate">
                        <span className="text-slate-500">Parent: </span>
                        <span className="text-slate-400">{block.parent_hash || '00000000000000000000000000000000 (GENESIS)'}</span>
                      </div>
                      <div className="truncate">
                        <span className="text-emerald-400 font-bold">Hash: </span>
                        <span className="text-emerald-300">{block.record_hash}</span>
                      </div>
                    </div>
                  </div>
                ))}

                {ledgerRecords.length === 0 && (
                  <div className="text-center py-10 text-slate-500 font-mono text-xs">
                    No blocks in audit ledger. Append a new block to initialize the cryptographic chain.
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
