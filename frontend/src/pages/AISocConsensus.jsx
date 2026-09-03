import React, { useState, useEffect } from 'react'
import api from '../api/client'

export default function AISocConsensus() {
  const [activeTab, setActiveTab] = useState('consensus') // 'consensus' | 'deception' | 'hardware_mesh'
  
  // Consensus State
  const [evalLoading, setEvalLoading] = useState(false)
  const [evalResult, setEvalResult] = useState(null)
  const [evalHistory, setEvalHistory] = useState([])
  
  // Custom Triage Inputs
  const [hostname, setHostname] = useState('finance-workstation-01')
  const [processCmd, setProcessCmd] = useState('powershell.exe -EncodedCommand JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA4ADUALgAyADIAMAAuADEAMAAxAC4ANQAiACwANAA0ADQANAApAA==')
  const [srcIp, setSrcIp] = useState('185.220.101.5')
  const [severity, setSeverity] = useState(4)

  // Deception State
  const [decoyLoading, setDecoyLoading] = useState(false)
  const [activeDecoys, setActiveDecoys] = useState([])
  const [targetStack, setTargetStack] = useState('PostgreSQL 16.1 (Production Cluster)')
  const [attackerIp, setAttackerIp] = useState('198.51.100.44')
  const [targetPort, setTargetPort] = useState(5432)
  const [latestDecoy, setLatestDecoy] = useState(null)

  // Hardware DPU & GNN State
  const [dpuData, setDpuData] = useState(null)
  const [gnnData, setGnnData] = useState(null)
  const [copiedSig, setCopiedSig] = useState(false)

  // Presets for quick demonstration
  const presets = [
    {
      name: 'Critical: Encoded PowerShell (Hostile IOC)',
      host: 'finance-workstation-01',
      cmd: 'powershell.exe -EncodedCommand JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AC...',
      ip: '185.220.101.5',
      sev: 4
    },
    {
      name: 'Critical Asset: Production DB SQL Injection',
      host: 'prod-db-cluster-01',
      cmd: 'postgres: worker process - SELECT * FROM users WHERE 1=1; DROP TABLE logs; --',
      ip: '45.227.254.12',
      sev: 4
    },
    {
      name: 'Benign: Normal Scheduled Maintenance',
      host: 'backup-worker-node-03',
      cmd: '/usr/bin/rsync -avz /var/log/ /mnt/backup/ --delete',
      ip: '10.0.4.15',
      sev: 1
    }
  ]

  const loadData = async () => {
    try {
      const [histRes, decoysRes, dpuRes, gnnRes] = await Promise.all([
        api.get('/consensus/history?limit=10'),
        api.get('/consensus/active-decoys'),
        api.get('/consensus/dpu-status'),
        api.get('/consensus/gnn-mesh')
      ])
      setEvalHistory(histRes.data || [])
      setActiveDecoys(decoysRes.data || [])
      setDpuData(dpuRes.data || null)
      setGnnData(gnnRes.data || null)
    } catch (err) {
      console.error('Failed to load v13 consensus telemetry:', err)
    }
  }

  useEffect(() => {
    loadData()
    const interval = setInterval(loadData, 10000)
    return () => clearInterval(interval)
  }, [])

  const handleRunTriage = async (customPayload = null) => {
    setEvalLoading(true)
    try {
      const payload = customPayload || {
        hostname,
        process_cmd: processCmd,
        src_ip: srcIp,
        severity: Number(severity)
      }
      const res = await api.post('/consensus/triage', payload)
      setEvalResult(res.data)
      loadData()
    } catch (err) {
      alert('Triage assessment failed: ' + (err.response?.data?.detail || err.message))
    } finally {
      setEvalLoading(false)
    }
  }

  const handleTriggerDecoy = async () => {
    setDecoyLoading(true)
    try {
      const res = await api.post('/consensus/orchestrate-decoy', {
        attacker_ip: attackerIp,
        target_port: Number(targetPort),
        target_stack: targetStack
      })
      setLatestDecoy(res.data)
      loadData()
    } catch (err) {
      alert('Decoy dynamic assembly failed: ' + (err.response?.data?.detail || err.message))
    } finally {
      setDecoyLoading(false)
    }
  }

  const applyPreset = (p) => {
    setHostname(p.host)
    setProcessCmd(p.cmd)
    setSrcIp(p.ip)
    setSeverity(p.sev)
  }

  const copySignature = (sig) => {
    if (!sig) return
    navigator.clipboard.writeText(sig)
    setCopiedSig(true)
    setTimeout(() => setCopiedSig(false), 2000)
  }

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-base-800 pb-5">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold tracking-tight text-slate-100 font-mono flex items-center gap-2">
              <span className="text-cyan-400">⚡</span>
              Autonomous AI SOC Consensus &amp; Deception (v13.0)
            </h1>
            <span className="px-2.5 py-0.5 text-xs font-mono font-bold rounded bg-cyan-950/80 text-cyan-400 border border-cyan-700/60 shadow-sm">
              Sovereign Mesh
            </span>
          </div>
          <p className="text-slate-400 text-xs mt-1 font-sans">
            Multi-Agent AI investigative voting, Self-Assembling Cognitive Honey-Infrastructure, SmartNIC DPU Ingest &amp; Cross-Tenant Differential Privacy GNN.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
          <div className="px-3 py-1.5 rounded-lg bg-base-900 border border-cyan-800/60 text-cyan-300 flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping"></span>
            <span>2/3 AI Consensus: ACTIVE</span>
          </div>
          <div className="px-3 py-1.5 rounded-lg bg-base-900 border border-emerald-800/60 text-emerald-300 flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
            <span>SmartNIC DPU Ingest: 124.5k EPS</span>
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex items-center gap-2 border-b border-base-800 pb-3 font-mono text-xs">
        <button
          onClick={() => setActiveTab('consensus')}
          className={`px-4 py-2 rounded-lg font-semibold transition-all ${
            activeTab === 'consensus'
              ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-lg shadow-cyan-500/10'
              : 'text-slate-400 hover:text-slate-200 hover:bg-base-900'
          }`}
        >
          🤖 Multi-Agent Consensus Panel
        </button>
        <button
          onClick={() => setActiveTab('deception')}
          className={`px-4 py-2 rounded-lg font-semibold transition-all ${
            activeTab === 'deception'
              ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40 shadow-lg shadow-amber-500/10'
              : 'text-slate-400 hover:text-slate-200 hover:bg-base-900'
          }`}
        >
          🕸️ Self-Assembling Deception Studio
        </button>
        <button
          onClick={() => setActiveTab('hardware_mesh')}
          className={`px-4 py-2 rounded-lg font-semibold transition-all ${
            activeTab === 'hardware_mesh'
              ? 'bg-indigo-500/20 text-indigo-300 border border-indigo-500/40 shadow-lg shadow-indigo-500/10'
              : 'text-slate-400 hover:text-slate-200 hover:bg-base-900'
          }`}
        >
          🎛️ SmartNIC DPU &amp; Diff-Privacy GNN
        </button>
      </div>

      {/* TAB 1: Multi-Agent AI SOC Consensus Panel */}
      {activeTab === 'consensus' && (
        <div className="space-y-6">
          {/* Preset Buttons */}
          <div className="panel p-4 bg-base-900/60 border border-base-800 space-y-2">
            <div className="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider">
              Quick Test Attack Scenarios:
            </div>
            <div className="flex flex-wrap gap-2">
              {presets.map((p, idx) => (
                <button
                  key={idx}
                  onClick={() => applyPreset(p)}
                  className="px-3 py-1.5 rounded text-xs font-mono bg-base-950 hover:bg-base-800 text-slate-300 border border-base-700 transition-colors"
                >
                  ⚡ {p.name}
                </button>
              ))}
            </div>
          </div>

          {/* Interactive Trigger Form & Live Assessment */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            {/* Input Config Form (5 Cols) */}
            <div className="lg:col-span-5 panel p-5 bg-base-900/90 border border-base-800 space-y-4 font-mono">
              <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                <span>🎯 Target Alert Telemetry Payload</span>
              </h3>

              <div className="space-y-3 text-xs">
                <div>
                  <label className="block text-slate-400 mb-1">Target Hostname</label>
                  <input
                    type="text"
                    value={hostname}
                    onChange={(e) => setHostname(e.target.value)}
                    className="w-full px-3 py-2 bg-base-950 border border-base-700 rounded text-slate-200 focus:border-cyan-500 outline-none"
                  />
                </div>

                <div>
                  <label className="block text-slate-400 mb-1">Source IP Address (Ingress)</label>
                  <input
                    type="text"
                    value={srcIp}
                    onChange={(e) => setSrcIp(e.target.value)}
                    className="w-full px-3 py-2 bg-base-950 border border-base-700 rounded text-slate-200 focus:border-cyan-500 outline-none"
                  />
                </div>

                <div>
                  <label className="block text-slate-400 mb-1">Executed Command / Process</label>
                  <textarea
                    rows={3}
                    value={processCmd}
                    onChange={(e) => setProcessCmd(e.target.value)}
                    className="w-full px-3 py-2 bg-base-950 border border-base-700 rounded text-slate-200 focus:border-cyan-500 outline-none font-mono text-[11px]"
                  />
                </div>

                <div>
                  <label className="block text-slate-400 mb-1">OCSF Severity Level (1 - 5)</label>
                  <select
                    value={severity}
                    onChange={(e) => setSeverity(e.target.value)}
                    className="w-full px-3 py-2 bg-base-950 border border-base-700 rounded text-slate-200 focus:border-cyan-500 outline-none"
                  >
                    <option value={1}>1 - Informational</option>
                    <option value={2}>2 - Low</option>
                    <option value={3}>3 - Medium</option>
                    <option value={4}>4 - High</option>
                    <option value={5}>5 - Critical</option>
                  </select>
                </div>
              </div>

              <button
                onClick={() => handleRunTriage()}
                disabled={evalLoading}
                className="w-full py-2.5 px-4 rounded font-mono text-xs font-bold uppercase tracking-wider bg-gradient-to-r from-cyan-600 to-cyan-500 hover:from-cyan-500 hover:to-cyan-400 text-slate-950 shadow-lg shadow-cyan-500/20 disabled:opacity-50 transition-all"
              >
                {evalLoading ? 'Executing Multi-Agent Voting…' : 'Run Autonomous Consensus Triage →'}
              </button>
            </div>

            {/* Assessment Verdict & Agent Breakdown (7 Cols) */}
            <div className="lg:col-span-7 space-y-4">
              {evalResult ? (
                <div className="panel p-5 bg-base-900/90 border border-base-800 space-y-5">
                  {/* Verdict Banner */}
                  <div className={`p-4 rounded-xl border font-mono ${
                    evalResult.consensus_action === 'ACTIVE_ISOLATE_HOST'
                      ? 'bg-severity-critical/15 border-severity-critical/50 text-severity-critical'
                      : 'bg-emerald-950/40 border-emerald-500/40 text-emerald-300'
                  }`}>
                    <div className="flex flex-wrap items-center justify-between gap-3">
                      <div>
                        <div className="text-[10px] uppercase font-bold tracking-wider opacity-80">
                          Autonomous Consensus Decision
                        </div>
                        <div className="text-lg font-extrabold mt-0.5 flex items-center gap-2">
                          <span>{evalResult.consensus_action === 'ACTIVE_ISOLATE_HOST' ? '🚨 ISOLATE HOST ACTION APPROVED' : '🛡️ PASSIVE MONITOR FLOW'}</span>
                        </div>
                      </div>
                      <div className="text-right">
                        <span className="text-xs font-bold px-2.5 py-1 rounded bg-base-950/70 border border-current">
                          {evalResult.majority_verdict}
                        </span>
                      </div>
                    </div>

                    {/* Metrics Bar */}
                    <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 mt-4 pt-3 border-t border-current/20 text-xs">
                      <div>
                        <span className="opacity-70 text-[10px] block">Composite Risk:</span>
                        <span className="font-bold text-sm">{(evalResult.composite_risk_score * 100).toFixed(1)}%</span>
                      </div>
                      <div>
                        <span className="opacity-70 text-[10px] block">Panel Confidence:</span>
                        <span className="font-bold text-sm">{(evalResult.evaluation_confidence * 100).toFixed(1)}%</span>
                      </div>
                      <div>
                        <span className="opacity-70 text-[10px] block">Execution SLA:</span>
                        <span className="font-bold text-sm">Instant (&lt;50ms)</span>
                      </div>
                    </div>

                    {/* Cryptographic Signature */}
                    {evalResult.authorized_signature && (
                      <div className="mt-3 pt-3 border-t border-current/20 text-[11px] flex items-center justify-between gap-2">
                        <div className="truncate">
                          <span className="font-bold">Signed Token: </span>
                          <span className="font-mono opacity-80">{evalResult.authorized_signature}</span>
                        </div>
                        <button
                          onClick={() => copySignature(evalResult.authorized_signature)}
                          className="px-2 py-1 rounded bg-base-950 text-[10px] font-mono hover:bg-base-800 text-slate-200 shrink-0"
                        >
                          {copiedSig ? 'Copied!' : 'Copy'}
                        </button>
                      </div>
                    )}
                  </div>

                  {/* 3 Specialized Agent Voting Breakdown */}
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                    {/* Agent Alpha: Investigator */}
                    <div className="p-3.5 rounded-lg bg-base-950 border border-base-800 space-y-2 font-mono text-xs">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-cyan-400">Agent Alpha</span>
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                          evalResult.agent_votes.investigator.vote_isolate ? 'bg-severity-critical/20 text-severity-critical' : 'bg-emerald-950 text-emerald-400'
                        }`}>
                          {evalResult.agent_votes.investigator.vote_isolate ? 'VOTE: ISOLATE' : 'VOTE: PASS'}
                        </span>
                      </div>
                      <div className="text-[11px] text-slate-400">
                        <strong>Role:</strong> Process Provenance &amp; Entropy
                      </div>
                      <div className="text-[11px] text-slate-300 font-sans line-clamp-3">
                        {evalResult.agent_votes.investigator.detail}
                      </div>
                      <div className="pt-2 border-t border-base-800 flex justify-between text-[10px] text-slate-500">
                        <span>Risk: {(evalResult.agent_votes.investigator.risk * 100).toFixed(0)}%</span>
                        <span>Conf: {(evalResult.agent_votes.investigator.confidence * 100).toFixed(0)}%</span>
                      </div>
                    </div>

                    {/* Agent Beta: Threat Intel */}
                    <div className="p-3.5 rounded-lg bg-base-950 border border-base-800 space-y-2 font-mono text-xs">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-amber-400">Agent Beta</span>
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                          evalResult.agent_votes.intel_aggregator.vote_isolate ? 'bg-severity-critical/20 text-severity-critical' : 'bg-emerald-950 text-emerald-400'
                        }`}>
                          {evalResult.agent_votes.intel_aggregator.vote_isolate ? 'VOTE: ISOLATE' : 'VOTE: PASS'}
                        </span>
                      </div>
                      <div className="text-[11px] text-slate-400">
                        <strong>Role:</strong> Global IOC &amp; Threat Feeds
                      </div>
                      <div className="text-[11px] text-slate-300 font-sans line-clamp-3">
                        {evalResult.agent_votes.intel_aggregator.detail}
                      </div>
                      <div className="pt-2 border-t border-base-800 flex justify-between text-[10px] text-slate-500">
                        <span>Risk: {(evalResult.agent_votes.intel_aggregator.risk * 100).toFixed(0)}%</span>
                        <span>Conf: {(evalResult.agent_votes.intel_aggregator.confidence * 100).toFixed(0)}%</span>
                      </div>
                    </div>

                    {/* Agent Gamma: Containment Specialist */}
                    <div className="p-3.5 rounded-lg bg-base-950 border border-base-800 space-y-2 font-mono text-xs">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-indigo-400">Agent Gamma</span>
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                          evalResult.agent_votes.containment_specialist.vote_isolate ? 'bg-severity-critical/20 text-severity-critical' : 'bg-emerald-950 text-emerald-400'
                        }`}>
                          {evalResult.agent_votes.containment_specialist.vote_isolate ? 'VOTE: ISOLATE' : 'VOTE: PASS'}
                        </span>
                      </div>
                      <div className="text-[11px] text-slate-400">
                        <strong>Role:</strong> Blast Radius &amp; Business Impact
                      </div>
                      <div className="text-[11px] text-slate-300 font-sans line-clamp-3">
                        {evalResult.agent_votes.containment_specialist.detail}
                      </div>
                      <div className="pt-2 border-t border-base-800 flex justify-between text-[10px] text-slate-500">
                        <span>Risk: {(evalResult.agent_votes.containment_specialist.risk * 100).toFixed(0)}%</span>
                        <span>Conf: {(evalResult.agent_votes.containment_specialist.confidence * 100).toFixed(0)}%</span>
                      </div>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="panel p-12 text-center bg-base-900/60 border border-base-800 text-slate-500 font-mono text-xs">
                  <div className="text-3xl mb-2">⚖️</div>
                  <p className="font-bold text-slate-300">Awaiting Autonomous Triage Trigger</p>
                  <p className="mt-1">Configure telemetry on the left or click a quick scenario to run the multi-agent AI panel.</p>
                </div>
              )}

              {/* Historical Decisions Ledger */}
              <div className="panel p-4 bg-base-900/60 border border-base-800 space-y-3 font-mono">
                <div className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center justify-between">
                  <span>Recent Autonomous Consensus Log</span>
                  <span className="text-slate-500 font-normal">{evalHistory.length} Records</span>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-[11px] text-left">
                    <thead>
                      <tr className="border-b border-base-800 text-slate-400">
                        <th className="pb-2 font-medium">Event UID</th>
                        <th className="pb-2 font-medium">Risk Score</th>
                        <th className="pb-2 font-medium">Action</th>
                        <th className="pb-2 font-medium">Majority</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-base-800/60 text-slate-300">
                      {evalHistory.map((h, i) => (
                        <tr key={i} className="hover:bg-base-950/40">
                          <td className="py-2 text-cyan-400">{h.event_uid}</td>
                          <td className="py-2 font-bold">{(h.composite_risk_score * 100).toFixed(1)}%</td>
                          <td className="py-2">
                            <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                              h.consensus_action === 'ACTIVE_ISOLATE_HOST' ? 'bg-severity-critical/20 text-severity-critical' : 'bg-emerald-950 text-emerald-400'
                            }`}>
                              {h.consensus_action}
                            </span>
                          </td>
                          <td className="py-2 text-slate-400">{h.majority_verdict}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: Self-Assembling Cognitive Deception Studio */}
      {activeTab === 'deception' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            {/* Decoy Provisioning Controls (5 Cols) */}
            <div className="lg:col-span-5 panel p-5 bg-base-900/90 border border-base-800 space-y-4 font-mono">
              <h3 className="text-sm font-bold text-amber-400 flex items-center gap-2">
                <span>⚡ eBPF Ingress Scan Trigger</span>
              </h3>

              <div className="space-y-3 text-xs">
                <div>
                  <label className="block text-slate-400 mb-1">Target Tech Stack to Clone</label>
                  <select
                    value={targetStack}
                    onChange={(e) => setTargetStack(e.target.value)}
                    className="w-full px-3 py-2 bg-base-950 border border-base-700 rounded text-slate-200 focus:border-amber-500 outline-none"
                  >
                    <option value="PostgreSQL 16.1 (Production Cluster)">PostgreSQL 16.1 (Production Cluster)</option>
                    <option value="FastAPI 0.100.0 Microservice">FastAPI 0.100.0 Microservice</option>
                    <option value="Redis 7.0.12 Cache / Queue">Redis 7.0.12 Cache / Queue</option>
                    <option value="Spring Boot 2.7.14 Enterprise API">Spring Boot 2.7.14 Enterprise API</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-400 mb-1">Attacker Recon Source IP</label>
                  <input
                    type="text"
                    value={attackerIp}
                    onChange={(e) => setAttackerIp(e.target.value)}
                    className="w-full px-3 py-2 bg-base-950 border border-base-700 rounded text-slate-200 focus:border-amber-500 outline-none"
                  />
                </div>

                <div>
                  <label className="block text-slate-400 mb-1">Target Ingress Port</label>
                  <input
                    type="number"
                    value={targetPort}
                    onChange={(e) => setTargetPort(e.target.value)}
                    className="w-full px-3 py-2 bg-base-950 border border-base-700 rounded text-slate-200 focus:border-amber-500 outline-none"
                  />
                </div>
              </div>

              <div className="p-3 bg-base-950 rounded border border-base-800 text-[11px] text-slate-400">
                <span className="text-amber-400 font-bold">eBPF Redirection:</span> Transparently manipulates TCP ingress headers via XDP, trapping attacker into an isolated canary container.
              </div>

              <button
                onClick={handleTriggerDecoy}
                disabled={decoyLoading}
                className="w-full py-2.5 px-4 rounded font-mono text-xs font-bold uppercase tracking-wider bg-gradient-to-r from-amber-600 to-amber-500 hover:from-amber-500 hover:to-amber-400 text-slate-950 shadow-lg shadow-amber-500/20 disabled:opacity-50 transition-all"
              >
                {decoyLoading ? 'Spawning Ephemeral Sandbox…' : 'Trigger Dynamic Decoy Assembly →'}
              </button>
            </div>

            {/* Live Assembled Decoy & eBPF Rules (7 Cols) */}
            <div className="lg:col-span-7 space-y-4 font-mono">
              {latestDecoy ? (
                <div className="panel p-5 bg-base-900/90 border border-amber-500/40 space-y-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="text-[10px] uppercase font-bold text-amber-400">Decoy Infrastructure Active</div>
                      <div className="text-base font-bold text-slate-100">{latestDecoy.target_stack}</div>
                    </div>
                    <span className="px-2 py-1 rounded bg-amber-500/20 text-amber-300 text-xs font-bold border border-amber-500/40">
                      Bootstrap: {latestDecoy.spawn_latency_ms} ms
                    </span>
                  </div>

                  {/* Redirection Rule Preview */}
                  <div className="p-3 rounded bg-base-950 border border-base-800 text-xs space-y-1">
                    <div className="text-slate-400 text-[10px] uppercase font-bold">eBPF Ingress Hook &amp; Socket Reroute</div>
                    <pre className="text-[11px] text-emerald-400 overflow-x-auto">
                      {JSON.stringify(latestDecoy.ebpf_redirection_rule, null, 2)}
                    </pre>
                  </div>

                  {/* Canary Credentials Seeded */}
                  <div className="p-3 rounded bg-base-950 border border-base-800 text-xs space-y-1">
                    <div className="text-slate-400 text-[10px] uppercase font-bold">Seeded Canary Credentials &amp; Synthetic Tables</div>
                    <div className="text-slate-300 text-[11px] space-y-1">
                      <p><strong>Canary User:</strong> <span className="text-cyan-400">{latestDecoy.canary_credentials.database_user}</span></p>
                      <p><strong>Tables:</strong> <span className="text-slate-400">{latestDecoy.canary_credentials.seeded_synthetic_tables?.join(', ')}</span></p>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="panel p-10 text-center bg-base-900/60 border border-base-800 text-slate-500 text-xs">
                  <div className="text-3xl mb-2">🕸️</div>
                  <p className="font-bold text-slate-300">No Ephemeral Decoy Active</p>
                  <p className="mt-1">Trigger an eBPF port scan on the left to dynamically self-assemble a honeypot clone.</p>
                </div>
              )}

              {/* Active Decoy Ledger */}
              <div className="panel p-4 bg-base-900/60 border border-base-800 space-y-3 font-mono">
                <div className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center justify-between">
                  <span>Active Sandboxed Decoys</span>
                  <span className="text-slate-500">{activeDecoys.length} Active</span>
                </div>
                <div className="space-y-2">
                  {activeDecoys.map((d, i) => (
                    <div key={i} className="p-3 rounded bg-base-950 border border-base-800 flex items-center justify-between text-xs">
                      <div>
                        <span className="font-bold text-slate-200">{d.target_stack}</span>
                        <span className="text-slate-500 block text-[10px]">ID: {d.decoy_id} | Port: {d.port}</span>
                      </div>
                      <div className="text-right">
                        <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 text-[10px] font-bold">
                          {d.status}
                        </span>
                        <span className="text-[10px] text-slate-400 block mt-0.5">Trapped Events: {d.trapped_interactions_count}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: SmartNIC DPU & Diff-Privacy GNN Mesh */}
      {activeTab === 'hardware_mesh' && (
        <div className="space-y-6 font-mono">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* DPU SmartNIC Telemetry */}
            <div className="panel p-5 bg-base-900/90 border border-cyan-500/30 space-y-4">
              <div className="flex items-center justify-between border-b border-base-800 pb-3">
                <div>
                  <span className="text-[10px] uppercase font-bold text-cyan-400">Hardware Offload Accelerator</span>
                  <h3 className="text-sm font-bold text-slate-100">SmartNIC DPU Ingest Pipeline</h3>
                </div>
                <span className="px-2 py-1 rounded bg-cyan-950 text-cyan-300 text-xs font-bold border border-cyan-800">
                  {dpuData?.status || 'ONLINE_LINE_RATE'}
                </span>
              </div>

              <div className="space-y-2 text-xs">
                <div className="flex justify-between py-1.5 border-b border-base-800">
                  <span className="text-slate-400">DPU Hardware Engine:</span>
                  <span className="text-slate-200 font-bold">{dpuData?.dpu_model}</span>
                </div>
                <div className="flex justify-between py-1.5 border-b border-base-800">
                  <span className="text-slate-400">Ingestion Throughput:</span>
                  <span className="text-cyan-400 font-bold">{dpuData?.current_eps?.toLocaleString()} EPS</span>
                </div>
                <div className="flex justify-between py-1.5 border-b border-base-800">
                  <span className="text-slate-400">Average Hardware Latency:</span>
                  <span className="text-emerald-400 font-bold">{dpuData?.avg_latency_microseconds} µs</span>
                </div>
                <div className="flex justify-between py-1.5 border-b border-base-800">
                  <span className="text-slate-400">Hardware mTLS Termination:</span>
                  <span className="text-slate-200">Enclave Verified (BlueField ARM)</span>
                </div>
                <div className="flex justify-between py-1.5">
                  <span className="text-slate-400">Zero-Copy DMA Normalization:</span>
                  <span className="text-slate-200">Host CPU Bypass Direct-to-RAM</span>
                </div>
              </div>
            </div>

            {/* Differential Privacy GNN Mesh */}
            <div className="panel p-5 bg-base-900/90 border border-indigo-500/30 space-y-4">
              <div className="flex items-center justify-between border-b border-base-800 pb-3">
                <div>
                  <span className="text-[10px] uppercase font-bold text-indigo-400">Federated Graph Intelligence</span>
                  <h3 className="text-sm font-bold text-slate-100">Differential Privacy GNN Mesh</h3>
                </div>
                <span className="px-2 py-1 rounded bg-indigo-950 text-indigo-300 text-xs font-bold border border-indigo-800">
                  {gnnData?.global_threat_level || 'ELEVATED'}
                </span>
              </div>

              <div className="space-y-2 text-xs">
                <div className="flex justify-between py-1.5 border-b border-base-800">
                  <span className="text-slate-400">Topology Protocol:</span>
                  <span className="text-slate-200 font-bold">{gnnData?.mesh_topology}</span>
                </div>
                <div className="flex justify-between py-1.5 border-b border-base-800">
                  <span className="text-slate-400">Connected Sovereign Tenants:</span>
                  <span className="text-indigo-300 font-bold">{gnnData?.active_tenant_nodes} Active Nodes</span>
                </div>
                <div className="flex justify-between py-1.5 border-b border-base-800">
                  <span className="text-slate-400">Differential Privacy Guarantee:</span>
                  <span className="text-slate-200 font-bold">Laplace ε={gnnData?.differential_privacy_epsilon}</span>
                </div>
                <div className="flex justify-between py-1.5 border-b border-base-800">
                  <span className="text-slate-400">SMPC Cryptographic Engine:</span>
                  <span className="text-emerald-400 font-bold">{gnnData?.smpc_aggregation_status}</span>
                </div>
                <div className="flex justify-between py-1.5">
                  <span className="text-slate-400">Cross-Tenant Campaigns Detected:</span>
                  <span className="text-amber-400 font-bold">{gnnData?.coordinated_campaigns_detected} Coordinated Threats</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
