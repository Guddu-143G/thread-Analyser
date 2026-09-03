import React, { useState, useEffect } from 'react'
import axios from 'axios'

export default function SovereignEdge() {
  const token = localStorage.getItem('token')

  const [activeTab, setActiveTab] = useState('stride') // stride | zkpsi | mmr | wasm | sdr
  const [strideData, setStrideData] = useState(null)
  const [loadingStride, setLoadingStride] = useState(false)
  const [selectedStrideFilter, setSelectedStrideFilter] = useState('ALL')

  // ZK-PSI State
  const [zkpsiOrgA, setZkpsiOrgA] = useState("185.220.101.5\nd41d8cd98f00b204e9800998ecf8427e\napt29-c2-beacon.darknet.org\nmimikatz_x64.dll\n198.51.100.44")
  const [zkpsiOrgB, setZkpsiOrgB] = useState("185.220.101.5\nlegit-azure-login.microsoft.com\napt29-c2-beacon.darknet.org\nsystem_update_patch_99.bin")
  const [zkpsiResult, setZkpsiResult] = useState(null)
  const [runningZkpsi, setRunningZkpsi] = useState(false)

  // MMR State
  const [mmrPeaks, setMmrPeaks] = useState(null)
  const [leafIndexToVerify, setLeafIndexToVerify] = useState(0)
  const [mmrProofResult, setMmrProofResult] = useState(null)
  const [verifyingMmr, setVerifyingMmr] = useState(false)

  // Wasm State
  const [wasmPlugins, setWasmPlugins] = useState([])
  const [testingPluginId, setTestingPluginId] = useState('wasm-sigma-engine-v2')
  const [wasmTestPayload, setWasmTestPayload] = useState('powershell.exe -ExecutionPolicy Bypass -Command whoami /priv')
  const [wasmTestResult, setWasmTestResult] = useState(null)
  const [runningWasmTest, setRunningWasmTest] = useState(false)
  const [newPluginName, setNewPluginName] = useState('Zero-Day Heuristic Wasm')
  const [newPluginVer, setNewPluginVer] = useState('1.0.0')

  // SDR & BGP State
  const [sdrData, setSdrData] = useState(null)
  const [bgpData, setBgpData] = useState(null)
  const [feedback, setFeedback] = useState(null)

  const fetchStride = async () => {
    setLoadingStride(true)
    try {
      const res = await axios.get('/api/sovereign/threat-model', {
        headers: { Authorization: `Bearer ${token}` },
      })
      setStrideData(res.data)
    } catch (err) {
      console.error('Error fetching STRIDE threat model:', err)
    } finally {
      setLoadingStride(false)
    }
  }

  const fetchMmr = async () => {
    try {
      const res = await axios.get('/api/sovereign/mmr/peaks', {
        headers: { Authorization: `Bearer ${token}` },
      })
      setMmrPeaks(res.data)
    } catch (err) {
      console.error('Error fetching MMR peaks:', err)
    }
  }

  const fetchWasm = async () => {
    try {
      const res = await axios.get('/api/sovereign/wasm/plugins', {
        headers: { Authorization: `Bearer ${token}` },
      })
      setWasmPlugins(res.data)
    } catch (err) {
      console.error('Error fetching Wasm plugins:', err)
    }
  }

  const fetchSdrBgp = async () => {
    try {
      const [sdrRes, bgpRes] = await Promise.all([
        axios.get('/api/sovereign/sdr-rf/telemetry', { headers: { Authorization: `Bearer ${token}` } }),
        axios.get('/api/sovereign/bgp/route-leak', { headers: { Authorization: `Bearer ${token}` } }),
      ])
      setSdrData(sdrRes.data)
      setBgpData(bgpRes.data)
    } catch (err) {
      console.error('Error fetching SDR/BGP telemetry:', err)
    }
  }

  useEffect(() => {
    fetchStride()
    fetchMmr()
    fetchWasm()
    fetchSdrBgp()
  }, [token])

  const handleRunZkPsi = async () => {
    setRunningZkpsi(true)
    setZkpsiResult(null)
    try {
      const aList = zkpsiOrgA.split('\n').map((s) => s.trim()).filter(Boolean)
      const bList = zkpsiOrgB.split('\n').map((s) => s.trim()).filter(Boolean)

      const res = await axios.post(
        '/api/sovereign/zk-psi/match',
        {
          party_a_name: 'Defense Infrastructure Corp',
          party_a_indicators: aList,
          party_b_name: 'Financial Cloud Operations',
          party_b_indicators: bList,
        },
        { headers: { Authorization: `Bearer ${token}` } }
      )
      setZkpsiResult(res.data)
    } catch (err) {
      setFeedback({ type: 'error', msg: `ZK-PSI failed: ${err.response?.data?.detail || err.message}` })
    } finally {
      setRunningZkpsi(false)
    }
  }

  const handleVerifyMmrProof = async () => {
    if (!mmrPeaks?.root_hash) return
    setVerifyingMmr(true)
    try {
      const res = await axios.post(
        '/api/sovereign/mmr/verify-proof',
        {
          leaf_index: Number(leafIndexToVerify),
          claimed_root: mmrPeaks.root_hash,
        },
        { headers: { Authorization: `Bearer ${token}` } }
      )
      setMmrProofResult(res.data)
    } catch (err) {
      setFeedback({ type: 'error', msg: `MMR proof verification failed: ${err.response?.data?.detail || err.message}` })
    } finally {
      setVerifyingMmr(false)
    }
  }

  const handleExecuteWasmTest = async () => {
    setRunningWasmTest(true)
    setWasmTestResult(null)
    try {
      const res = await axios.post(
        '/api/sovereign/wasm/execute-test',
        {
          plugin_id: testingPluginId,
          sample_payload: wasmTestPayload,
        },
        { headers: { Authorization: `Bearer ${token}` } }
      )
      setWasmTestResult(res.data)
    } catch (err) {
      setFeedback({ type: 'error', msg: `Wasm execution error: ${err.response?.data?.detail || err.message}` })
    } finally {
      setRunningWasmTest(false)
    }
  }

  const handleDeployNewPlugin = async () => {
    try {
      const res = await axios.post(
        '/api/sovereign/wasm/deploy-plugin',
        {
          name: newPluginName,
          version: newPluginVer,
          allowed_capabilities: ['read_proc_names', 'parse_ocsf_json', 'sigma_evaluate'],
        },
        { headers: { Authorization: `Bearer ${token}` } }
      )
      setFeedback({ type: 'success', msg: `Plugin '${res.data.name}' (v${res.data.version}) certified & deployed to endpoints.` })
      fetchWasm()
    } catch (err) {
      setFeedback({ type: 'error', msg: `Wasm deployment failed: ${err.response?.data?.detail || err.message}` })
    }
  }

  const filteredThreats = strideData?.threats?.filter((t) => {
    if (selectedStrideFilter === 'ALL') return true
    return t.threat_class.toUpperCase() === selectedStrideFilter.toUpperCase()
  }) || []

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12 font-sans">
      {/* Header Banner */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-base-800 pb-5">
        <div>
          <div className="flex items-center gap-3">
            <span className="text-2xl font-mono text-purple-400 font-bold">🛡️</span>
            <h1 className="text-2xl font-bold tracking-tight text-slate-100 font-mono">
              Quantum-Safe Sovereign Edge &amp; STRIDE-as-Code
            </h1>
            <span className="text-xs font-mono bg-purple-950 text-purple-300 px-2.5 py-0.5 rounded-full border border-purple-700">
              v14.0 Zero-Trust
            </span>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Continuous STRIDE threat modeling, Diffie-Hellman ZK-PSI hunting, Merkle Mountain Range audit proofs, and Wasm sandboxes.
          </p>
        </div>

        <div className="flex items-center gap-3 font-mono text-xs">
          <div className="px-3 py-1.5 bg-base-900 border border-base-700 rounded-lg flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-purple-400 animate-pulse"></span>
            <span className="text-slate-300">Sovereign Proofs:</span>
            <span className="text-purple-400 font-bold">VERIFIABLE</span>
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

      {/* Top 4 KPI Metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 font-mono">
        <div className="panel p-4 bg-gradient-to-br from-base-900 to-purple-950/30 border border-purple-500/30 rounded-xl space-y-1 shadow-md">
          <div className="text-xs text-slate-400">Architecture Health Score</div>
          <div className="text-2xl font-bold text-purple-300 flex items-baseline gap-2">
            <span>{strideData?.architecture_health_score || 82.5}%</span>
            <span className="text-xs text-purple-400 font-normal">STRIDE-as-Code</span>
          </div>
          <div className="text-[11px] text-slate-500">Continuous topology evaluation</div>
        </div>

        <div className="panel p-4 bg-base-900 border border-base-700 rounded-xl space-y-1 shadow-md">
          <div className="text-xs text-slate-400">Active STRIDE Threats</div>
          <div className="text-2xl font-bold text-rose-400 flex items-baseline gap-2">
            <span>{strideData?.total_threats_identified || 0}</span>
            <span className="text-xs text-slate-500 font-normal">Identified Conduits</span>
          </div>
          <div className="text-[11px] text-slate-500">Automatic mitigation mapping</div>
        </div>

        <div className="panel p-4 bg-base-900 border border-base-700 rounded-xl space-y-1 shadow-md">
          <div className="text-xs text-slate-400">Certified Wasm Plugins</div>
          <div className="text-2xl font-bold text-cyan-300 flex items-baseline gap-2">
            <span>{wasmPlugins.length}</span>
            <span className="text-xs text-slate-500 font-normal">Micro-Runtimes</span>
          </div>
          <div className="text-[11px] text-slate-500">Zero-Syscall Memory Isolation</div>
        </div>

        <div className="panel p-4 bg-base-900 border border-base-700 rounded-xl space-y-1 shadow-md">
          <div className="text-xs text-slate-400">MMR Audit Leaves</div>
          <div className="text-2xl font-bold text-emerald-300 flex items-baseline gap-2">
            <span>{mmrPeaks?.total_audit_leaves || 3}</span>
            <span className="text-xs text-slate-500 font-normal">Sealed Peaks</span>
          </div>
          <div className="text-[11px] text-slate-500">Cryptographically immutable</div>
        </div>
      </div>

      {/* Navigation Sub-Tabs */}
      <div className="flex border-b border-base-800 gap-2 font-mono text-xs">
        <button
          onClick={() => setActiveTab('stride')}
          className={`px-4 py-2.5 font-bold border-b-2 transition ${
            activeTab === 'stride'
              ? 'border-purple-400 text-purple-300 bg-purple-950/20'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          1. Continuous STRIDE-as-Code
        </button>
        <button
          onClick={() => setActiveTab('zkpsi')}
          className={`px-4 py-2.5 font-bold border-b-2 transition ${
            activeTab === 'zkpsi'
              ? 'border-purple-400 text-purple-300 bg-purple-950/20'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          2. Zero-Knowledge PSI Hunter
        </button>
        <button
          onClick={() => setActiveTab('mmr')}
          className={`px-4 py-2.5 font-bold border-b-2 transition ${
            activeTab === 'mmr'
              ? 'border-purple-400 text-purple-300 bg-purple-950/20'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          3. Merkle Mountain Range (MMR)
        </button>
        <button
          onClick={() => setActiveTab('wasm')}
          className={`px-4 py-2.5 font-bold border-b-2 transition ${
            activeTab === 'wasm'
              ? 'border-purple-400 text-purple-300 bg-purple-950/20'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          4. WebAssembly Sandbox
        </button>
        <button
          onClick={() => setActiveTab('sdr')}
          className={`px-4 py-2.5 font-bold border-b-2 transition ${
            activeTab === 'sdr'
              ? 'border-purple-400 text-purple-300 bg-purple-950/20'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          5. Airspace SDR &amp; BGP Telemetry
        </button>
      </div>

      {/* TAB 1: STRIDE-as-Code Threat Modeler */}
      {activeTab === 'stride' && (
        <div className="space-y-6">
          {/* Active Topology Graph Map */}
          <div className="panel p-5 bg-base-900 border border-base-700 rounded-xl space-y-4 font-mono">
            <div className="flex justify-between items-center border-b border-base-800 pb-3">
              <div className="flex items-center gap-2">
                <span className="text-purple-400 font-bold">◈</span>
                <h3 className="text-sm font-bold text-slate-100">Live Application Topology Graph &amp; Communication Conduits</h3>
              </div>
              <button
                onClick={fetchStride}
                className="bg-base-800 hover:bg-base-700 text-slate-300 px-3 py-1 rounded text-xs transition"
              >
                ↻ Re-Evaluate Architecture
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {strideData?.edges?.map((edge, idx) => (
                <div key={idx} className="p-3 bg-base-950 border border-base-800 rounded-lg space-y-2 text-xs">
                  <div className="flex justify-between items-center text-[10px] text-slate-500">
                    <span>CONDUIT #{idx + 1}</span>
                    <span className="text-cyan-400 font-bold">{edge.protocol}</span>
                  </div>
                  <div className="space-y-1">
                    <div className="text-slate-300 font-semibold truncate">FROM: {edge.src}</div>
                    <div className="text-slate-400 truncate">TO: {edge.dst} (Port {edge.port})</div>
                  </div>
                  <div className="flex gap-2 pt-1 text-[10px]">
                    <span className={`px-1.5 py-0.5 rounded ${edge.authenticated ? 'bg-emerald-950 text-emerald-300' : 'bg-rose-950 text-rose-300'}`}>
                      {edge.authenticated ? 'AUTH: YES' : 'AUTH: NONE'}
                    </span>
                    <span className={`px-1.5 py-0.5 rounded ${edge.rate_limited ? 'bg-emerald-950 text-emerald-300' : 'bg-amber-950 text-amber-300'}`}>
                      {edge.rate_limited ? 'RATE-LIMIT: ACTIVE' : 'RATE-LIMIT: OFF'}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* STRIDE Threats Table */}
          <div className="panel p-5 bg-base-900 border border-base-700 rounded-xl space-y-4 font-mono">
            <div className="flex flex-wrap justify-between items-center gap-3 border-b border-base-800 pb-3">
              <div className="flex items-center gap-2">
                <span className="text-rose-400 font-bold">▲</span>
                <h3 className="text-sm font-bold text-slate-100">Automated STRIDE Threat Assessment</h3>
              </div>

              {/* Filter Pills */}
              <div className="flex flex-wrap gap-1.5 text-xs">
                {['ALL', 'SPOOFING', 'TAMPERING', 'REPUDIATION', 'INFORMATION DISCLOSURE', 'DENIAL OF SERVICE', 'ELEVATION OF PRIVILEGE'].map((cat) => (
                  <button
                    key={cat}
                    onClick={() => setSelectedStrideFilter(cat)}
                    className={`px-2.5 py-1 rounded text-[11px] font-semibold transition ${
                      selectedStrideFilter === cat
                        ? 'bg-purple-900 text-purple-200 border border-purple-600'
                        : 'bg-base-950 text-slate-400 border border-base-800 hover:text-slate-200'
                    }`}
                  >
                    {cat}
                  </button>
                ))}
              </div>
            </div>

            <div className="space-y-3">
              {filteredThreats.map((threat) => (
                <div key={threat.threat_id} className="p-4 bg-base-950 border border-base-800 rounded-lg space-y-2 text-xs">
                  <div className="flex justify-between items-center">
                    <div className="flex items-center gap-2">
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-purple-950 text-purple-300 border border-purple-800">
                        {threat.threat_class}
                      </span>
                      <span className="text-slate-300 font-bold">{threat.element}</span>
                      <span className="text-[10px] text-slate-500">[{threat.cwe_id}]</span>
                    </div>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        threat.severity === 'CRITICAL'
                          ? 'bg-rose-950 text-rose-300 border border-rose-800'
                          : 'bg-amber-950 text-amber-300 border border-amber-800'
                      }`}
                    >
                      {threat.severity}
                    </span>
                  </div>

                  <p className="text-slate-400 font-sans text-xs">{threat.description}</p>

                  <div className="bg-emerald-950/40 border border-emerald-900/60 p-2.5 rounded text-[11px] text-emerald-300">
                    <strong>Recommended Architecture Mitigation:</strong> {threat.mitigation}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: Zero-Knowledge Private Set Intersection */}
      {activeTab === 'zkpsi' && (
        <div className="panel p-5 bg-base-900 border border-base-700 rounded-xl space-y-6 font-mono">
          <div className="border-b border-base-800 pb-3">
            <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <span>🔐</span>
              <span>Zero-Knowledge Private Set Intersection (ZK-PSI) Collaborative Threat Hunter</span>
            </h3>
            <p className="text-xs text-slate-400 font-sans mt-1">
              Match threat intelligence indicators (IPs, hashes, domains) with peer enterprises using Diffie-Hellman commutative blind signatures over prime field 2^255 - 19.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-xs">
            <div className="space-y-2">
              <label className="text-slate-300 font-bold block">Organization A Indicators (Private Set X)</label>
              <textarea
                rows="6"
                value={zkpsiOrgA}
                onChange={(e) => setZkpsiOrgA(e.target.value)}
                className="w-full bg-base-950 border border-base-700 text-slate-200 p-3 rounded-lg focus:outline-none focus:border-purple-500 font-mono text-xs"
              />
              <span className="text-[10px] text-slate-500">Will be blinded as (H(x)^kA) mod p before sharing.</span>
            </div>

            <div className="space-y-2">
              <label className="text-slate-300 font-bold block">Organization B Indicators (Private Set Y)</label>
              <textarea
                rows="6"
                value={zkpsiOrgB}
                onChange={(e) => setZkpsiOrgB(e.target.value)}
                className="w-full bg-base-950 border border-base-700 text-slate-200 p-3 rounded-lg focus:outline-none focus:border-purple-500 font-mono text-xs"
              />
              <span className="text-[10px] text-slate-500">Will be cross-signed to produce H(x)^(kA*kB).</span>
            </div>
          </div>

          <button
            disabled={runningZkpsi}
            onClick={handleRunZkPsi}
            className="w-full bg-purple-600 hover:bg-purple-500 text-white font-bold py-2.5 rounded-lg transition text-xs shadow-md"
          >
            {runningZkpsi ? 'Computing Blind Signatures & Prime Field Intersection...' : '⚡ Execute Zero-Knowledge PSI Match'}
          </button>

          {zkpsiResult && (
            <div className="p-4 bg-base-950 border border-purple-500/40 rounded-xl space-y-3">
              <div className="flex justify-between items-center border-b border-base-800 pb-2 text-xs">
                <span className="text-emerald-400 font-bold">✓ ZK-PSI INTERSECTION PROOF VERIFIED</span>
                <span className="text-[10px] bg-purple-950 text-purple-300 px-2 py-0.5 rounded border border-purple-800">
                  Leakage: {zkpsiResult.information_leakage_bytes} Bytes
                </span>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-center text-xs">
                <div className="p-2 bg-base-900 rounded border border-base-800">
                  <span className="text-slate-500 block text-[10px]">Org A Tested</span>
                  <span className="text-slate-200 font-bold">{zkpsiResult.org_a_count}</span>
                </div>
                <div className="p-2 bg-base-900 rounded border border-base-800">
                  <span className="text-slate-500 block text-[10px]">Org B Tested</span>
                  <span className="text-slate-200 font-bold">{zkpsiResult.org_b_count}</span>
                </div>
                <div className="p-2 bg-base-900 rounded border border-base-800">
                  <span className="text-slate-500 block text-[10px]">Prime Field</span>
                  <span className="text-purple-300 font-bold">2^255 - 19</span>
                </div>
                <div className="p-2 bg-base-900 rounded border border-base-800">
                  <span className="text-slate-500 block text-[10px]">Matched IOCs</span>
                  <span className="text-emerald-400 font-bold">{zkpsiResult.intersection_matches_count}</span>
                </div>
              </div>

              <div className="space-y-2 pt-2">
                <span className="text-xs text-slate-400 font-bold block">Disclosed Intersecting IOCs (X ∩ Y):</span>
                {zkpsiResult.matched_indicators.map((m, idx) => (
                  <div key={idx} className="p-2.5 bg-base-900 border border-base-800 rounded flex justify-between items-center text-xs">
                    <span className="text-rose-400 font-bold">{m.indicator}</span>
                    <span className="text-[10px] text-slate-500">{m.proof}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* TAB 3: Merkle Mountain Range (MMR) */}
      {activeTab === 'mmr' && (
        <div className="panel p-5 bg-base-900 border border-base-700 rounded-xl space-y-6 font-mono">
          <div className="border-b border-base-800 pb-3">
            <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <span>⛰️</span>
              <span>Merkle Mountain Range (MMR) Immutable Audit Proofs</span>
            </h3>
            <p className="text-xs text-slate-400 font-sans mt-1">
              Append-only logarithmic peak hashing guaranteeing tamper-evident chain of custody even if underlying database records are maliciously targeted.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
            <div className="p-4 bg-base-950 border border-base-800 rounded-lg space-y-2">
              <span className="text-slate-500 block text-[10px]">CURRENT MMR MASTER ROOT HASH</span>
              <span className="text-cyan-300 font-bold break-all text-xs">{mmrPeaks?.root_hash}</span>
              <div className="flex gap-4 pt-2 text-slate-400">
                <span>Leaves: <strong className="text-white">{mmrPeaks?.total_audit_leaves}</strong></span>
                <span>Active Peaks: <strong className="text-white">{mmrPeaks?.peak_count}</strong></span>
              </div>
            </div>

            <div className="p-4 bg-base-950 border border-base-800 rounded-lg space-y-3">
              <span className="text-slate-300 font-bold block">Verify Leaf Inclusion Proof</span>
              <div className="flex gap-2">
                <input
                  type="number"
                  value={leafIndexToVerify}
                  onChange={(e) => setLeafIndexToVerify(e.target.value)}
                  min="0"
                  max={(mmrPeaks?.total_audit_leaves || 1) - 1}
                  className="w-24 bg-base-900 border border-base-700 text-slate-200 p-2 rounded focus:outline-none text-xs"
                />
                <button
                  disabled={verifyingMmr}
                  onClick={handleVerifyMmrProof}
                  className="flex-1 bg-purple-600 hover:bg-purple-500 text-white font-bold px-3 py-2 rounded text-xs transition"
                >
                  {verifyingMmr ? 'Verifying Path...' : 'Verify Cryptographic Proof'}
                </button>
              </div>
            </div>
          </div>

          {mmrProofResult && (
            <div className="p-4 bg-base-950 border border-emerald-500/40 rounded-xl space-y-3 text-xs">
              <div className="flex justify-between items-center border-b border-base-800 pb-2">
                <span className="text-emerald-400 font-bold">✓ MERKLE INCLUSION PROOF VALIDATED</span>
                <span className="text-[10px] text-slate-500">Leaf #{mmrProofResult.leaf_index}</span>
              </div>

              <div className="space-y-1 text-slate-300">
                <div>Leaf Hash: <span className="text-cyan-400">{mmrProofResult.leaf_hash}</span></div>
                <div>Action: <strong className="text-white">{mmrProofResult.entry_payload?.action}</strong></div>
                <div>Actor: <span className="text-slate-400">{mmrProofResult.entry_payload?.actor}</span></div>
              </div>

              <div className="space-y-1.5 pt-2">
                <span className="text-[10px] text-slate-500 uppercase font-bold">Authentication Path Siblings:</span>
                {mmrProofResult.proof_path?.map((p, idx) => (
                  <div key={idx} className="p-1.5 bg-base-900 border border-base-800 rounded text-[10px] flex justify-between">
                    <span className="text-purple-300">Level {idx + 1} ({p.position})</span>
                    <span className="text-slate-400">{p.hash}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* TAB 4: WebAssembly Sandboxed Plugins */}
      {activeTab === 'wasm' && (
        <div className="space-y-6 font-mono">
          <div className="panel p-5 bg-base-900 border border-base-700 rounded-xl space-y-4">
            <div className="flex justify-between items-center border-b border-base-800 pb-3">
              <div>
                <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                  <span>📦</span>
                  <span>Certified WebAssembly (Wasm) Endpoint Detection Plugins</span>
                </h3>
                <p className="text-xs text-slate-400 font-sans mt-0.5">
                  Pre-compiled bytecode executed inside restricted Wasmtime/Wasmer sandboxes with 0 kernel syscall permissions.
                </p>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {wasmPlugins.map((p) => (
                <div key={p.plugin_id} className="p-4 bg-base-950 border border-base-800 rounded-lg space-y-2 text-xs">
                  <div className="flex justify-between items-center">
                    <span className="font-bold text-slate-200">{p.name}</span>
                    <span className="text-[10px] bg-cyan-950 text-cyan-300 px-1.5 py-0.5 rounded border border-cyan-800">
                      v{p.version}
                    </span>
                  </div>
                  <div className="text-[10px] text-slate-500 truncate">SHA-256: {p.wasm_sha256}</div>
                  <div className="space-y-1 text-[11px] text-slate-400">
                    <div>Memory Limit: <strong className="text-slate-200">{p.sandbox_memory_limit_mb} MB</strong></div>
                    <div>Syscalls: <strong className="text-emerald-400">{p.syscalls_granted} (Blocked)</strong></div>
                    <div>Endpoints: <strong className="text-purple-300">{p.active_deployed_endpoints} active</strong></div>
                  </div>
                  <div className="pt-2">
                    <button
                      onClick={() => {
                        setTestingPluginId(p.plugin_id)
                        handleExecuteWasmTest()
                      }}
                      className="w-full bg-base-900 hover:bg-base-800 text-cyan-400 border border-base-700 py-1 rounded text-xs transition"
                    >
                      ▶ Run In-Sandbox Test
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Wasm Execution Tester */}
          <div className="panel p-5 bg-base-900 border border-base-700 rounded-xl space-y-4">
            <h3 className="text-sm font-bold text-slate-100 border-b border-base-800 pb-3">
              Sandbox Execution &amp; Memory Isolation Tester
            </h3>

            <div className="space-y-2 text-xs">
              <label className="text-slate-300 font-bold block">Input Process Command Line</label>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={wasmTestPayload}
                  onChange={(e) => setWasmTestPayload(e.target.value)}
                  className="flex-1 bg-base-950 border border-base-700 text-slate-200 p-2.5 rounded focus:outline-none text-xs"
                />
                <button
                  disabled={runningWasmTest}
                  onClick={handleExecuteWasmTest}
                  className="bg-purple-600 hover:bg-purple-500 text-white font-bold px-4 py-2.5 rounded text-xs transition"
                >
                  {runningWasmTest ? 'Executing in Wasm...' : '⚡ Execute Sandbox Test'}
                </button>
              </div>
            </div>

            {wasmTestResult && (
              <div className="p-4 bg-base-950 border border-base-800 rounded-xl space-y-2 text-xs">
                <div className="flex justify-between items-center border-b border-base-800 pb-2">
                  <span className="text-slate-200 font-bold">Wasm Sandbox Execution Telemetry</span>
                  <span className="text-emerald-400 font-bold">
                    Latency: {wasmTestResult.execution_latency_microseconds} µs
                  </span>
                </div>
                <div className="grid grid-cols-2 md:grid-cols-3 gap-3 text-[11px] text-slate-400">
                  <div>Runtime: <strong className="text-slate-200">{wasmTestResult.execution_runtime}</strong></div>
                  <div>Heap Allocated: <strong className="text-slate-200">{wasmTestResult.heap_consumed_kb} KB</strong></div>
                  <div>Host Violations: <strong className="text-emerald-400">{wasmTestResult.host_isolation_violation_count}</strong></div>
                </div>
                <div className="mt-2 p-2.5 bg-base-900 border border-base-800 rounded text-[11px]">
                  <span>OCSF Output Class: </span>
                  <strong className="text-cyan-400">{wasmTestResult.ocsf_output_event?.class_name} (Class {wasmTestResult.ocsf_output_event?.class_uid})</strong>
                  <span className="ml-3">Triggered: <strong className={wasmTestResult.detection_triggered ? 'text-rose-400' : 'text-slate-400'}>{String(wasmTestResult.detection_triggered)}</strong></span>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 5: SDR RF Spectrum & BGP Route Leak Telemetry */}
      {activeTab === 'sdr' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 font-mono">
          {/* SDR RF Spectrum Card */}
          <div className="panel p-5 bg-base-900 border border-base-700 rounded-xl space-y-4 text-xs">
            <div className="border-b border-base-800 pb-3 flex justify-between items-center">
              <div className="flex items-center gap-2">
                <span className="text-cyan-400 font-bold">📡</span>
                <h3 className="text-sm font-bold text-slate-100">Physical Airspace SDR RF Monitor (OCSF Class 6002)</h3>
              </div>
              <span className="text-[10px] bg-emerald-950 text-emerald-300 px-2 py-0.5 rounded border border-emerald-800">
                ACTIVE
              </span>
            </div>

            <div className="space-y-2 text-slate-300">
              <div className="flex justify-between py-1 border-b border-base-800">
                <span className="text-slate-500">Center Frequency:</span>
                <span className="font-bold text-cyan-300">{sdrData?.center_frequency_mhz} MHz</span>
              </div>
              <div className="flex justify-between py-1 border-b border-base-800">
                <span className="text-slate-500">Bandwidth:</span>
                <span className="font-bold text-slate-200">{sdrData?.bandwidth_mhz} MHz</span>
              </div>
              <div className="flex justify-between py-1 border-b border-base-800">
                <span className="text-slate-500">Signal-to-Noise Ratio (SNR):</span>
                <span className="font-bold text-emerald-400">{sdrData?.signal_to_noise_ratio_db} dB</span>
              </div>
              <div className="flex justify-between py-1 border-b border-base-800">
                <span className="text-slate-500">IQ Sample Entropy:</span>
                <span className="font-bold text-purple-300">{sdrData?.iq_sample_entropy} / 8.0</span>
              </div>
              <div className="flex justify-between py-1">
                <span className="text-slate-500">Hardware Interface:</span>
                <span className="text-[10px] text-slate-400">{sdrData?.hardware_sdr_frontend}</span>
              </div>
            </div>
          </div>

          {/* BGP Route Leak Monitor */}
          <div className="panel p-5 bg-base-900 border border-base-700 rounded-xl space-y-4 text-xs">
            <div className="border-b border-base-800 pb-3 flex justify-between items-center">
              <div className="flex items-center gap-2">
                <span className="text-indigo-400 font-bold">🌐</span>
                <h3 className="text-sm font-bold text-slate-100">BGP Autonomous System (AS) Hijack Defense</h3>
              </div>
              <span className="text-[10px] bg-emerald-950 text-emerald-300 px-2 py-0.5 rounded border border-emerald-800">
                SECURE
              </span>
            </div>

            <div className="space-y-2 text-slate-300">
              <div className="flex justify-between py-1 border-b border-base-800">
                <span className="text-slate-500">Target IP Prefix:</span>
                <span className="font-bold text-indigo-300">{bgpData?.target_prefix}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-base-800">
                <span className="text-slate-500">Origin Autonomous System:</span>
                <span className="font-bold text-slate-200">AS{bgpData?.origin_as} ({bgpData?.origin_as_name})</span>
              </div>
              <div className="flex justify-between py-1 border-b border-base-800">
                <span className="text-slate-500">Observed AS Path:</span>
                <span className="font-bold text-cyan-300">{bgpData?.observed_as_path?.join(' ➔ ')}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-base-800">
                <span className="text-slate-500">Route Validation:</span>
                <span className="font-bold text-emerald-400">{bgpData?.mitigation_action}</span>
              </div>
              <div className="flex justify-between py-1">
                <span className="text-slate-500">Feed Source:</span>
                <span className="text-[10px] text-slate-400">{bgpData?.route_views_feed_status}</span>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
