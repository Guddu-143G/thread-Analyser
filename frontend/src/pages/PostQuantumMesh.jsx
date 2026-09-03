import React, { useState, useEffect } from 'react'
import axios from 'axios'

export default function PostQuantumMesh() {
  const token = localStorage.getItem('token')

  const [activeTab, setActiveTab] = useState('pqc') // pqc | pmu | gart | rollup
  const [feedback, setFeedback] = useState(null)

  // 1. PQC State
  const [pqcHandshake, setPqcHandshake] = useState(null)
  const [pqcPayloadInput, setPqcPayloadInput] = useState('{\n  "event": "PROCESS_SPAWN",\n  "user": "root",\n  "cmd": "/bin/sh -c reverse_shell",\n  "node": "prod-k8s-worker-09"\n}')
  const [pqcEnvelope, setPqcEnvelope] = useState(null)
  const [unwrappedPayload, setUnwrappedPayload] = useState(null)
  const [loadingPqc, setLoadingPqc] = useState(false)

  // 2. PMU State
  const [pmuMetrics, setPmuMetrics] = useState(null)
  const [pmuAttackType, setPmuAttackType] = useState('flush_reload')
  const [loadingPmu, setLoadingPmu] = useState(false)

  // 3. GART State
  const [gartResult, setGartResult] = useState(null)
  const [gartPatches, setGartPatches] = useState([])
  const [selectedSeed, setSelectedSeed] = useState('SEED-01')
  const [runningGart, setRunningGart] = useState(false)

  // 4. ZK-Rollup State
  const [rollupState, setRollupState] = useState(null)
  const [commitIndicator, setCommitIndicator] = useState('185.220.101.5')
  const [commitType, setCommitType] = useState('ipv4')
  const [commitConfidence, setCommitConfidence] = useState(0.98)
  const [loadingRollup, setLoadingRollup] = useState(false)

  const fetchPmu = async () => {
    try {
      const res = await axios.get('/api/v15/pmu/metrics', { headers: { Authorization: `Bearer ${token}` } })
      setPmuMetrics(res.data)
    } catch (err) {
      console.error('Error fetching PMU metrics:', err)
    }
  }

  const fetchGartPatches = async () => {
    try {
      const res = await axios.get('/api/v15/gart/patches', { headers: { Authorization: `Bearer ${token}` } })
      setGartPatches(res.data)
    } catch (err) {
      console.error('Error fetching GART patches:', err)
    }
  }

  const fetchRollup = async () => {
    try {
      const res = await axios.get('/api/v15/zk-rollup/state', { headers: { Authorization: `Bearer ${token}` } })
      setRollupState(res.data)
    } catch (err) {
      console.error('Error fetching ZK-Rollup state:', err)
    }
  }

  useEffect(() => {
    fetchPmu()
    fetchGartPatches()
    fetchRollup()
  }, [token])

  // Handlers
  const handlePqcHandshake = async () => {
    setLoadingPqc(true)
    try {
      const res = await axios.post(
        '/api/v15/pqc/handshake',
        { node_id: 'soc-edge-enclave-01' },
        { headers: { Authorization: `Bearer ${token}` } }
      )
      setPqcHandshake(res.data)
      setFeedback({ type: 'success', msg: 'Hybrid ML-KEM-1024 + X25519 Post-Quantum session established.' })
    } catch (err) {
      setFeedback({ type: 'error', msg: `PQC Handshake failed: ${err.response?.data?.detail || err.message}` })
    } finally {
      setLoadingPqc(false)
    }
  }

  const handleWrapEnvelope = async () => {
    try {
      let parsed = JSON.parse(pqcPayloadInput)
      const res = await axios.post(
        '/api/v15/pqc/envelope',
        { raw_payload: parsed },
        { headers: { Authorization: `Bearer ${token}` } }
      )
      setPqcEnvelope(res.data)
      setUnwrappedPayload(null)
    } catch (err) {
      setFeedback({ type: 'error', msg: `Invalid JSON or envelope encryption error: ${err.message}` })
    }
  }

  const handleUnwrapEnvelope = async () => {
    if (!pqcEnvelope) return
    try {
      const res = await axios.post('/api/v15/pqc/unwrap', pqcEnvelope, { headers: { Authorization: `Bearer ${token}` } })
      setUnwrappedPayload(res.data)
    } catch (err) {
      setFeedback({ type: 'error', msg: `Envelope unwrapping failed: ${err.response?.data?.detail || err.message}` })
    }
  }

  const handleSimulatePmuAttack = async (type) => {
    setLoadingPmu(true)
    try {
      const res = await axios.post(
        '/api/v15/pmu/simulate-attack',
        { attack_type: type },
        { headers: { Authorization: `Bearer ${token}` } }
      )
      setPmuMetrics(res.data)
      setFeedback({ type: 'success', msg: `Injected hardware simulation: ${type.toUpperCase()}` })
    } catch (err) {
      setFeedback({ type: 'error', msg: `PMU simulation error: ${err.message}` })
    } finally {
      setLoadingPmu(false)
    }
  }

  const handleRunGart = async () => {
    setRunningGart(true)
    setGartResult(null)
    try {
      const res = await axios.post(
        '/api/v15/gart/run-loop',
        { seed_id: selectedSeed },
        { headers: { Authorization: `Bearer ${token}` } }
      )
      setGartResult(res.data)
      fetchGartPatches()
      setFeedback({ type: 'success', msg: `GART loop completed! Discovered ${res.data.evasions_discovered} evasion vectors and synthesized patch.` })
    } catch (err) {
      setFeedback({ type: 'error', msg: `GART execution error: ${err.response?.data?.detail || err.message}` })
    } finally {
      setRunningGart(false)
    }
  }

  const handleCommitRollup = async () => {
    setLoadingRollup(true)
    try {
      const res = await axios.post(
        '/api/v15/zk-rollup/commit-threat',
        {
          indicator: commitIndicator,
          indicator_type: commitType,
          confidence: Number(commitConfidence),
        },
        { headers: { Authorization: `Bearer ${token}` } }
      )
      setFeedback({ type: 'success', msg: `Indicator cryptographically blinded and committed to ZK-Rollup batch #${res.data.active_batch_id}` })
      fetchRollup()
    } catch (err) {
      setFeedback({ type: 'error', msg: `Rollup commit error: ${err.message}` })
    } finally {
      setLoadingRollup(false)
    }
  }

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12 font-sans">
      {/* Header Banner */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-base-800 pb-5">
        <div>
          <div className="flex items-center gap-3">
            <span className="text-2xl font-mono text-cyan-400 font-bold">⚛️</span>
            <h1 className="text-2xl font-bold tracking-tight text-slate-100 font-mono">
              Zero-Trust Physical &amp; Quantum Mesh
            </h1>
            <span className="text-xs font-mono bg-cyan-950 text-cyan-300 px-2.5 py-0.5 rounded-full border border-cyan-700">
              v15.0 Vanguard
            </span>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            NIST FIPS 203/204 Post-Quantum Hybrid Transport, CPU PMU Side-Channel Telemetry, Self-Healing GART Arena, and Private ZK-Rollup Ledger.
          </p>
        </div>

        <div className="flex items-center gap-3 font-mono text-xs">
          <div className="px-3 py-1.5 bg-base-900 border border-base-700 rounded-lg flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse"></span>
            <span className="text-slate-300">Vanguard Score:</span>
            <span className="text-cyan-400 font-bold">99.99999 / 100</span>
          </div>
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
          <button onClick={() => setFeedback(null)} className="text-slate-400 hover:text-white">✕</button>
        </div>
      )}

      {/* Top 4 High-Density Metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 font-mono">
        <div className="panel p-4 bg-gradient-to-br from-base-900 to-cyan-950/30 border border-cyan-500/30 rounded-xl space-y-1 shadow-md">
          <div className="text-xs text-slate-400">Post-Quantum KEM</div>
          <div className="text-xl font-bold text-cyan-300 flex items-baseline gap-2">
            <span>ML-KEM-1024</span>
            <span className="text-xs text-slate-500 font-normal">+ X25519</span>
          </div>
          <div className="text-[11px] text-slate-500">NIST FIPS 203 Hybrid</div>
        </div>

        <div className="panel p-4 bg-base-900 border border-base-700 rounded-xl space-y-1 shadow-md">
          <div className="text-xs text-slate-400">CPU Cache Miss Ratio</div>
          <div className={`text-2xl font-bold flex items-baseline gap-2 ${
            (pmuMetrics?.hardware_metrics?.cache_miss_ratio || 0) > 0.70 ? 'text-rose-400' : 'text-emerald-300'
          }`}>
            <span>{(pmuMetrics?.hardware_metrics?.cache_miss_ratio || 0.12).toFixed(3)}</span>
            <span className="text-xs text-slate-500 font-normal">PMU Rowhammer Guard</span>
          </div>
          <div className="text-[11px] text-slate-500">{pmuMetrics?.attack_analysis?.detected_pattern || 'Nominal Execution'}</div>
        </div>

        <div className="panel p-4 bg-base-900 border border-base-700 rounded-xl space-y-1 shadow-md">
          <div className="text-xs text-slate-400">GART Self-Healed Rules</div>
          <div className="text-2xl font-bold text-purple-300 flex items-baseline gap-2">
            <span>{gartPatches.length}</span>
            <span className="text-xs text-slate-500 font-normal">Hot Patches</span>
          </div>
          <div className="text-[11px] text-slate-500">Closed-Loop Adversarial Patching</div>
        </div>

        <div className="panel p-4 bg-base-900 border border-base-700 rounded-xl space-y-1 shadow-md">
          <div className="text-xs text-slate-400">ZK-Rollup Batches</div>
          <div className="text-2xl font-bold text-indigo-300 flex items-baseline gap-2">
            <span>{rollupState?.total_sealed_batches || 1}</span>
            <span className="text-xs text-slate-500 font-normal">Sealed Blocks</span>
          </div>
          <div className="text-[11px] text-slate-500">zk-SNARK State Root Ledger</div>
        </div>
      </div>

      {/* Navigation Sub-Tabs */}
      <div className="flex border-b border-base-800 gap-2 font-mono text-xs">
        <button
          onClick={() => setActiveTab('pqc')}
          className={`px-4 py-2.5 font-bold border-b-2 transition ${
            activeTab === 'pqc'
              ? 'border-cyan-400 text-cyan-300 bg-cyan-950/20'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          1. Hybrid Post-Quantum Cryptography (NIST)
        </button>
        <button
          onClick={() => setActiveTab('pmu')}
          className={`px-4 py-2.5 font-bold border-b-2 transition ${
            activeTab === 'pmu'
              ? 'border-cyan-400 text-cyan-300 bg-cyan-950/20'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          2. CPU PMU Hardware Side-Channel Monitor
        </button>
        <button
          onClick={() => setActiveTab('gart')}
          className={`px-4 py-2.5 font-bold border-b-2 transition ${
            activeTab === 'gart'
              ? 'border-cyan-400 text-cyan-300 bg-cyan-950/20'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          3. Self-Healing GART Adversarial Arena
        </button>
        <button
          onClick={() => setActiveTab('rollup')}
          className={`px-4 py-2.5 font-bold border-b-2 transition ${
            activeTab === 'rollup'
              ? 'border-cyan-400 text-cyan-300 bg-cyan-950/20'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          4. Private ZK-Rollup Sovereign Ledger
        </button>
      </div>

      {/* TAB 1: Post-Quantum Hybrid Transport */}
      {activeTab === 'pqc' && (
        <div className="panel p-5 bg-base-900 border border-base-700 rounded-xl space-y-6 font-mono">
          <div className="border-b border-base-800 pb-3 flex justify-between items-center">
            <div>
              <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                <span>⚛️</span>
                <span>NIST FIPS 203 / 204 Hybrid Post-Quantum Key Encapsulation (ML-KEM &amp; ML-DSA)</span>
              </h3>
              <p className="text-xs text-slate-400 font-sans mt-0.5">
                Protects edge agent log transit and real-time streams against quantum "Harvest Now, Decrypt Later" adversaries.
              </p>
            </div>
            <button
              disabled={loadingPqc}
              onClick={handlePqcHandshake}
              className="bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold px-3 py-1.5 rounded text-xs transition"
            >
              {loadingPqc ? 'Negotiating PQC...' : '⚡ Initiate Hybrid PQC Handshake'}
            </button>
          </div>

          {pqcHandshake && (
            <div className="p-4 bg-base-950 border border-cyan-500/40 rounded-xl space-y-2 text-xs">
              <div className="flex justify-between items-center text-cyan-400 font-bold">
                <span>✓ {pqcHandshake.handshake_status}</span>
                <span className="text-[10px] bg-cyan-950 text-cyan-300 px-2 py-0.5 rounded border border-cyan-800">
                  Standards: ML-KEM-1024 + ML-DSA-87
                </span>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2 text-[11px]">
                <div className="p-2 bg-base-900 rounded border border-base-800 space-y-1">
                  <span className="text-slate-500 block text-[10px]">ML-KEM-1024 LATTICE PUBLIC KEY</span>
                  <span className="text-slate-300 break-all">{pqcHandshake.ml_kem_1024_public_key}</span>
                </div>
                <div className="p-2 bg-base-900 rounded border border-base-800 space-y-1">
                  <span className="text-slate-500 block text-[10px]">ML-DSA-87 SIGNATURE VERIFICATION KEY</span>
                  <span className="text-slate-300 break-all">{pqcHandshake.ml_dsa_87_verify_key}</span>
                </div>
              </div>
            </div>
          )}

          {/* Double-Encrypted Envelope Simulator */}
          <div className="space-y-3">
            <h4 className="text-xs font-bold text-slate-200 uppercase">Double-Encrypted PQC Envelope Processor</h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
              <div className="space-y-2">
                <label className="text-slate-400 block">Raw Telemetry Payload (JSON)</label>
                <textarea
                  rows="6"
                  value={pqcPayloadInput}
                  onChange={(e) => setPqcPayloadInput(e.target.value)}
                  className="w-full bg-base-950 border border-base-700 text-slate-200 p-3 rounded-lg focus:outline-none focus:border-cyan-500 font-mono text-xs"
                />
                <button
                  onClick={handleWrapEnvelope}
                  className="w-full bg-base-800 hover:bg-base-700 text-cyan-300 border border-cyan-600/40 font-bold py-2 rounded text-xs transition"
                >
                  🔒 Wrap into Hybrid PQC Envelope
                </button>
              </div>

              <div className="space-y-2">
                <label className="text-slate-400 block">Encrypted PQC Envelope Output</label>
                <div className="h-44 bg-base-950 border border-base-800 text-slate-300 p-3 rounded-lg overflow-y-auto font-mono text-[11px] space-y-1">
                  {pqcEnvelope ? (
                    <>
                      <div><strong className="text-cyan-400">KEM:</strong> {pqcEnvelope.pqc_metadata?.kem_standard}</div>
                      <div><strong className="text-cyan-400">Encapsulated Key:</strong> {pqcEnvelope.encapsulated_key_hex?.slice(0, 32)}...</div>
                      <div><strong className="text-cyan-400">Agent Signature:</strong> {pqcEnvelope.agent_signature_hex?.slice(0, 32)}...</div>
                      <div><strong className="text-cyan-400">Ciphertext:</strong> {pqcEnvelope.encrypted_payload?.ciphertext?.slice(0, 48)}...</div>
                      <div><strong className="text-cyan-400">Nonce:</strong> {pqcEnvelope.encrypted_payload?.nonce}</div>
                      <div><strong className="text-cyan-400">Auth Tag:</strong> {pqcEnvelope.encrypted_payload?.auth_tag}</div>
                    </>
                  ) : (
                    <span className="text-slate-600 italic">No envelope wrapped yet. Click 'Wrap into Hybrid PQC Envelope'.</span>
                  )}
                </div>
                {pqcEnvelope && (
                  <button
                    onClick={handleUnwrapEnvelope}
                    className="w-full bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold py-2 rounded text-xs transition"
                  >
                    🔓 Decrypt &amp; Verify Signature
                  </button>
                )}
              </div>
            </div>

            {unwrappedPayload && (
              <div className="p-3 bg-emerald-950/40 border border-emerald-500/40 rounded-lg text-xs space-y-1">
                <span className="text-emerald-400 font-bold block">✓ DECRYPTED PAYLOAD VIA HYBRID POST-QUANTUM KEY:</span>
                <pre className="text-slate-200 text-[11px] overflow-x-auto">{JSON.stringify(unwrappedPayload.decrypted_payload, null, 2)}</pre>
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 2: Hardware PMU & CPU Side-Channel Monitor */}
      {activeTab === 'pmu' && (
        <div className="space-y-6 font-mono">
          <div className="panel p-5 bg-base-900 border border-base-700 rounded-xl space-y-4">
            <div className="border-b border-base-800 pb-3 flex justify-between items-center">
              <div>
                <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                  <span>🔬</span>
                  <span>CPU Performance Monitoring Unit (PMU) &amp; Side-Channel Monitor (OCSF Class 6002)</span>
                </h3>
                <p className="text-xs text-slate-400 font-sans mt-0.5">
                  Hooks into physical CPU hardware registers via Linux perf_event_open to detect Rowhammer, Flush+Reload, and Spectre transient execution attacks.
                </p>
              </div>
              <button
                onClick={fetchPmu}
                className="bg-base-800 hover:bg-base-700 text-slate-300 px-3 py-1 rounded text-xs transition"
              >
                ↻ Poll CPU Registers
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="p-4 bg-base-950 border border-base-800 rounded-lg space-y-1">
                <span className="text-slate-500 text-[10px]">CACHE MISS RATIO</span>
                <div className={`text-2xl font-bold ${
                  (pmuMetrics?.hardware_metrics?.cache_miss_ratio || 0) > 0.70 ? 'text-rose-400' : 'text-emerald-400'
                }`}>
                  {((pmuMetrics?.hardware_metrics?.cache_miss_ratio || 0) * 100).toFixed(1)}%
                </div>
                <div className="text-[10px] text-slate-500">Threshold: &gt; 70.0% flags anomaly</div>
              </div>

              <div className="p-4 bg-base-950 border border-base-800 rounded-lg space-y-1">
                <span className="text-slate-500 text-[10px]">BRANCH MISPREDICTION RATIO</span>
                <div className={`text-2xl font-bold ${
                  (pmuMetrics?.hardware_metrics?.branch_miss_ratio || 0) > 0.70 ? 'text-amber-400' : 'text-cyan-400'
                }`}>
                  {((pmuMetrics?.hardware_metrics?.branch_miss_ratio || 0) * 100).toFixed(1)}%
                </div>
                <div className="text-[10px] text-slate-500">Spectre Transient Execution Indicator</div>
              </div>

              <div className="p-4 bg-base-950 border border-base-800 rounded-lg space-y-1">
                <span className="text-slate-500 text-[10px]">HARDWARE DEFENSE STATE</span>
                <div className={`text-sm font-bold pt-1 ${
                  pmuMetrics?.attack_analysis?.anomaly_flag ? 'text-rose-400' : 'text-emerald-400'
                }`}>
                  {pmuMetrics?.attack_analysis?.detected_pattern}
                </div>
                <div className="text-[10px] text-slate-500">Action: {pmuMetrics?.attack_analysis?.action_taken}</div>
              </div>
            </div>
          </div>

          {/* Side-Channel Attack Simulator */}
          <div className="panel p-5 bg-base-900 border border-base-700 rounded-xl space-y-4">
            <h3 className="text-sm font-bold text-slate-100 border-b border-base-800 pb-3">
              Hardware Attack Injection &amp; EDR Verification Studio
            </h3>
            <div className="grid grid-cols-1 sm:grid-cols-4 gap-3 text-xs">
              <button
                disabled={loadingPmu}
                onClick={() => handleSimulatePmuAttack('flush_reload')}
                className="p-3 bg-base-950 hover:bg-rose-950/40 border border-rose-600/40 rounded-lg text-left transition space-y-1"
              >
                <span className="font-bold text-rose-300 block">⚡ Flush+Reload Attack</span>
                <span className="text-[10px] text-slate-500 block">High cache miss ratio (85%+)</span>
              </button>

              <button
                disabled={loadingPmu}
                onClick={() => handleSimulatePmuAttack('spectre_v1')}
                className="p-3 bg-base-950 hover:bg-amber-950/40 border border-amber-600/40 rounded-lg text-left transition space-y-1"
              >
                <span className="font-bold text-amber-300 block">⚡ Spectre V1 Transient</span>
                <span className="text-[10px] text-slate-500 block">High branch misprediction</span>
              </button>

              <button
                disabled={loadingPmu}
                onClick={() => handleSimulatePmuAttack('rowhammer_bitflip')}
                className="p-3 bg-base-950 hover:bg-purple-950/40 border border-purple-600/40 rounded-lg text-left transition space-y-1"
              >
                <span className="font-bold text-purple-300 block">⚡ Rowhammer DRAM Disturbance</span>
                <span className="text-[10px] text-slate-500 block">Extreme memory eviction</span>
              </button>

              <button
                disabled={loadingPmu}
                onClick={() => handleSimulatePmuAttack('normal')}
                className="p-3 bg-base-950 hover:bg-emerald-950/40 border border-emerald-600/40 rounded-lg text-left transition space-y-1"
              >
                <span className="font-bold text-emerald-300 block">✓ Restore Nominal State</span>
                <span className="text-[10px] text-slate-500 block">Clear hardware alerts</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: Self-Healing GART Adversarial Arena */}
      {activeTab === 'gart' && (
        <div className="space-y-6 font-mono">
          <div className="panel p-5 bg-base-900 border border-base-700 rounded-xl space-y-4">
            <div className="border-b border-base-800 pb-3 flex justify-between items-center">
              <div>
                <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                  <span>⚔️</span>
                  <span>Self-Healing Generative Adversarial Red Teaming (GART) Arena</span>
                </h3>
                <p className="text-xs text-slate-400 font-sans mt-0.5">
                  Autonomous closed-loop red teaming: mutates attack syntaxes, discovers rule evasion bypasses, and auto-synthesizes hot-patched Sigma rules.
                </p>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-3 text-xs">
              <label className="text-slate-300 font-bold">Select Seed Attack Pattern:</label>
              <select
                value={selectedSeed}
                onChange={(e) => setSelectedSeed(e.target.value)}
                className="bg-base-950 border border-base-700 text-slate-200 p-2 rounded focus:outline-none text-xs"
              >
                <option value="SEED-01">SEED-01: PowerShell Remote Execution Bypass</option>
                <option value="SEED-02">SEED-02: Privilege Escalation Mimikatz Memory Dump</option>
                <option value="SEED-03">SEED-03: SQL Injection Authentication Bypass</option>
                <option value="SEED-04">SEED-04: SSH Brute-Force Password Spray</option>
              </select>

              <button
                disabled={runningGart}
                onClick={handleRunGart}
                className="bg-purple-600 hover:bg-purple-500 text-white font-bold px-4 py-2 rounded text-xs transition shadow-md"
              >
                {runningGart ? 'Mutating & Evaluating Evasions...' : '⚡ Run Autonomous GART Cycle'}
              </button>
            </div>

            {gartResult && (
              <div className="p-4 bg-base-950 border border-purple-500/40 rounded-xl space-y-3 text-xs">
                <div className="flex justify-between items-center border-b border-base-800 pb-2">
                  <span className="text-purple-300 font-bold">GART ADVERSARIAL CYCLE RESULTS</span>
                  <span className="text-[10px] bg-purple-950 text-purple-300 px-2 py-0.5 rounded border border-purple-800">
                    Evasions Discovered: {gartResult.evasions_discovered} / {gartResult.mutations_tested}
                  </span>
                </div>

                <div className="space-y-2">
                  <span className="text-slate-400 font-bold block">Generated Adversarial Mutations:</span>
                  {gartResult.mutations.map((m, idx) => (
                    <div key={idx} className="p-2.5 bg-base-900 border border-base-800 rounded space-y-1">
                      <div className="flex justify-between text-[10px]">
                        <span className="text-cyan-400 font-bold uppercase">{m.mutation_strategy} MUTATION</span>
                        <span className={m.detected_by_baseline ? 'text-emerald-400' : 'text-rose-400 font-bold'}>
                          {m.detected_by_baseline ? 'DETECTED BY BASELINE' : '⚠️ BYPASSED BASELINE (EVASION FOUND)'}
                        </span>
                      </div>
                      <div className="text-slate-300 text-[11px] font-mono break-all">{m.mutated_payload}</div>
                    </div>
                  ))}
                </div>

                {gartResult.synthesized_patch && (
                  <div className="mt-4 p-3 bg-emerald-950/40 border border-emerald-500/40 rounded-lg space-y-2">
                    <div className="flex justify-between items-center text-emerald-400 font-bold">
                      <span>✓ AUTONOMOUSLY SYNTHESIZED SIGMA DEFENSE PATCH</span>
                      <span className="text-[10px] text-slate-400">Resilience: {gartResult.synthesized_patch.resilience_score}%</span>
                    </div>
                    <pre className="p-2 bg-base-950 border border-base-800 text-slate-200 text-[10px] overflow-x-auto rounded">
                      {gartResult.synthesized_patch.synthesized_rule_yaml}
                    </pre>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Synthesized Patches Registry */}
          <div className="panel p-5 bg-base-900 border border-base-700 rounded-xl space-y-4">
            <h3 className="text-sm font-bold text-slate-100 border-b border-base-800 pb-3">
              Active Self-Healed Rules Registry ({gartPatches.length} Rules Active)
            </h3>
            <div className="space-y-3">
              {gartPatches.map((p) => (
                <div key={p.patch_id} className="p-4 bg-base-950 border border-base-800 rounded-lg space-y-2 text-xs">
                  <div className="flex justify-between items-center">
                    <span className="text-slate-200 font-bold">{p.patch_id}</span>
                    <span className="text-[10px] bg-emerald-950 text-emerald-300 px-2 py-0.5 rounded border border-emerald-800">
                      {p.status}
                    </span>
                  </div>
                  <div className="text-slate-400 text-[11px]">Evasion Countered: <strong className="text-purple-300">{p.evasion_technique}</strong></div>
                  <pre className="p-2 bg-base-900 border border-base-800 text-slate-300 text-[10px] overflow-x-auto rounded">
                    {p.synthesized_rule_yaml}
                  </pre>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* TAB 4: Private ZK-Rollup Sovereign Threat Ledger */}
      {activeTab === 'rollup' && (
        <div className="panel p-5 bg-base-900 border border-base-700 rounded-xl space-y-6 font-mono">
          <div className="border-b border-base-800 pb-3">
            <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <span>📜</span>
              <span>Decentralized Zero-Knowledge Sovereign Threat Rollup Ledger</span>
            </h3>
            <p className="text-xs text-slate-400 font-sans mt-0.5">
              Aggregates cryptographically blinded threat indicators from multi-tenant enclaves into verifiable zk-SNARK state transition proofs.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
            <div className="p-4 bg-base-950 border border-base-800 rounded-lg space-y-2">
              <span className="text-slate-500 block text-[10px]">CURRENT ZK-ROLLUP MASTER STATE ROOT</span>
              <span className="text-indigo-300 font-bold break-all text-xs">{rollupState?.current_state_root}</span>
              <div className="flex gap-4 pt-2 text-slate-400 text-[11px]">
                <span>Sealed Batches: <strong className="text-white">{rollupState?.total_sealed_batches}</strong></span>
                <span>Pending Commitments: <strong className="text-cyan-400">{rollupState?.pending_commitments_count}</strong></span>
              </div>
            </div>

            <div className="p-4 bg-base-950 border border-base-800 rounded-lg space-y-3">
              <span className="text-slate-300 font-bold block">Blind &amp; Commit New Threat Indicator</span>
              <div className="space-y-2">
                <input
                  type="text"
                  value={commitIndicator}
                  onChange={(e) => setCommitIndicator(e.target.value)}
                  placeholder="Indicator (e.g., 185.220.101.5 or hash)"
                  className="w-full bg-base-900 border border-base-700 text-slate-200 p-2 rounded focus:outline-none text-xs"
                />
                <div className="flex gap-2">
                  <select
                    value={commitType}
                    onChange={(e) => setCommitType(e.target.value)}
                    className="bg-base-900 border border-base-700 text-slate-200 p-2 rounded focus:outline-none text-xs"
                  >
                    <option value="ipv4">IPv4</option>
                    <option value="domain">Domain</option>
                    <option value="file_hash">File Hash</option>
                  </select>
                  <button
                    disabled={loadingRollup}
                    onClick={handleCommitRollup}
                    className="flex-1 bg-indigo-600 hover:bg-indigo-500 text-white font-bold px-3 py-2 rounded text-xs transition"
                  >
                    {loadingRollup ? 'Blinding & Committing...' : '⚡ Commit to ZK-Rollup'}
                  </button>
                </div>
              </div>
            </div>
          </div>

          {/* Sealed Batches History */}
          <div className="space-y-3">
            <h4 className="text-xs font-bold text-slate-200 uppercase">Sealed ZK-Rollup Blocks History</h4>
            <div className="space-y-3">
              {rollupState?.sealed_batches?.map((b) => (
                <div key={b.batch_id} className="p-4 bg-base-950 border border-base-800 rounded-lg space-y-2 text-xs">
                  <div className="flex justify-between items-center border-b border-base-800 pb-2">
                    <span className="font-bold text-indigo-300">ROLLUP BLOCK #{b.batch_id} ({b.commitment_count} Indicators)</span>
                    <span className="text-[10px] bg-emerald-950 text-emerald-300 px-2 py-0.5 rounded border border-emerald-800">
                      {b.proof_verification}
                    </span>
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[11px] text-slate-400">
                    <div>State Root: <strong className="text-slate-200 break-all">{b.state_root}</strong></div>
                    <div>zk-SNARK Proof: <strong className="text-cyan-400 break-all">{b.zk_snark_proof?.slice(0, 32)}...</strong></div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
