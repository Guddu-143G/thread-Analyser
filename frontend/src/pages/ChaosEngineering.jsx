import React, { useState, useEffect } from 'react'
import api from '../api/client'

export default function ChaosEngineering() {
  const [activeTab, setActiveTab] = useState('arena') // 'arena' | 'terminal' | 'profiles' | 'report'
  const [selectedClass, setSelectedClass] = useState('ALL')
  const [taxonomy, setTaxonomy] = useState([])
  const [profiles, setProfiles] = useState([])
  const [history, setHistory] = useState([])
  const [report, setReport] = useState(null)
  const [loading, setLoading] = useState(false)
  const [injecting, setInjecting] = useState(false)
  
  // Simulation form inputs
  const [selectedVariety, setSelectedVariety] = useState('Tenant Isolation Bypass')
  const [targetOrgId, setTargetOrgId] = useState('org_target_isolated_99')
  const [targetMac, setTargetMac] = useState('00:1A:7D:DA:99:88')
  const [baselineRate, setBaselineRate] = useState(1.0)
  
  // Real-time terminal log feed
  const [terminalLogs, setTerminalLogs] = useState([
    { time: new Date().toLocaleTimeString(), type: 'SYS', msg: 'Security Chaos Engineering (SCE) Daemon initialized.' },
    { time: new Date().toLocaleTimeString(), type: 'INFO', msg: 'Listening for synthetic defect injection triggers on OCSF and Sigma test harness.' },
    { time: new Date().toLocaleTimeString(), type: 'READY', msg: 'SLA Watchdog threshold: < 5,000ms. DCI engine ready.' }
  ])

  useEffect(() => {
    fetchInitialData()
  }, [])

  const fetchInitialData = async () => {
    setLoading(true)
    try {
      const [taxRes, profRes, histRes, repRes] = await Promise.allSettled([
        api.get('/chaos/taxonomy'),
        api.get('/chaos/version-profiles'),
        api.get('/chaos/history?limit=25'),
        api.get('/chaos/report')
      ])

      if (taxRes.status === 'fulfilled') setTaxonomy(taxRes.value.data)
      if (profRes.status === 'fulfilled') setProfiles(profRes.value.data)
      if (histRes.status === 'fulfilled') setHistory(histRes.value.data)
      if (repRes.status === 'fulfilled') setReport(repRes.value.data)
    } catch (err) {
      console.error('Failed to load chaos engineering data', err)
    } finally {
      setLoading(false)
    }
  }

  const appendTerminalLog = (type, msg) => {
    setTerminalLogs(prev => [
      ...prev.slice(-40),
      { time: new Date().toLocaleTimeString(), type, msg }
    ])
  }

  const handleInjectFault = async (varietyName = null) => {
    const varietyToRun = varietyName || selectedVariety
    setInjecting(true)
    appendTerminalLog('INJECT', `Initiating controlled fault injection: [${varietyToRun}]...`)

    try {
      const resp = await api.post('/chaos/inject', {
        bug_variety: varietyToRun,
        target_org_id: targetOrgId,
        target_mac: targetMac,
        baseline_rate_eps: parseFloat(baselineRate)
      })

      const data = resp.data
      appendTerminalLog('EXEC', `[eBPF Trace] Injected ${data.cwe_class} (${data.severity}) payload ID: ${data.simulation_id}`)
      appendTerminalLog('SLA', `Detection loop finished in ${data.detection_latency_ms}ms | SLA Status: ${data.sla_compliance}`)
      
      if (data.alert_triggered) {
        appendTerminalLog('ALERT', `SIEM Alert created: [${data.alert_id || 'RESOLVED'}] - ${data.execution_notes}`)
      } else {
        appendTerminalLog('WARN', `[UNDETECTED BLIND SPOT] Simulated payload evaded active threshold!`)
      }

      // Refresh history & report
      const [newHist, newRep] = await Promise.all([
        api.get('/chaos/history?limit=25'),
        api.get('/chaos/report')
      ])
      setHistory(newHist.data)
      setReport(newRep.data)
    } catch (err) {
      appendTerminalLog('ERR', `Fault injection error: ${err?.response?.data?.detail || err.message}`)
    } finally {
      setInjecting(false)
    }
  }

  const handleRunFullSuite = async () => {
    setInjecting(true)
    appendTerminalLog('SUITE', '⚡ Executing automated full-suite Defect Taxonomy battery...')
    const tests = [
      'Tenant Isolation Bypass',
      'Buffer Overflow Attempt',
      'BlueBorne L2CAP Overflow',
      'SQL / Command Injection Attempt',
      'Model Evasion Attempt'
    ]

    for (const testName of tests) {
      await handleInjectFault(testName)
    }
    setInjecting(false)
    setActiveTab('report')
  }

  const copyMarkdownReport = () => {
    if (report?.markdown_report) {
      navigator.clipboard.writeText(report.markdown_report)
      alert('Resilience Report Markdown copied to clipboard!')
    }
  }

  const downloadMarkdownReport = () => {
    if (!report?.markdown_report) return
    const blob = new Blob([report.markdown_report], { type: 'text/markdown;charset=utf-8;' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.setAttribute('href', url)
    link.setAttribute('download', `Security_Resilience_Report_${report.report_reference}.md`)
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
  }

  // Filter taxonomy
  const filteredTaxonomy = taxonomy.filter(t => {
    if (selectedClass === 'ALL') return true
    if (selectedClass === 'LOGICAL' && t.defect_class.includes('Logical')) return true
    if (selectedClass === 'SYSTEM' && t.defect_class.includes('System')) return true
    if (selectedClass === 'RF' && t.defect_class.includes('Over-the-Air')) return true
    if (selectedClass === 'CRYPTO' && t.defect_class.includes('Cryptographic')) return true
    if (selectedClass === 'ML' && t.defect_class.includes('ML')) return true
    return true
  })

  return (
    <div className="space-y-6 pb-12">
      {/* Top Banner / Hero */}
      <div className="panel p-6 bg-gradient-to-r from-base-900 via-base-900 to-rose-950/40 border border-rose-500/30 rounded-xl space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="text-rose-400 text-xl font-mono">💥</span>
              <h1 className="text-xl font-bold text-slate-100 font-mono">Security Chaos Engineering (SCE) &amp; Defect Simulation</h1>
              <span className="text-[10px] bg-rose-950 text-rose-300 px-2.5 py-0.5 rounded border border-rose-800 font-mono font-bold">
                Version 10.0 (Target: 99.99/100)
              </span>
            </div>
            <p className="text-xs text-slate-400 max-w-3xl">
              Safely inject synthetic defects, protocol overflows, and adversarial evasion vectors into your testing sandbox to continuously verify SIEM rule responsiveness, SLA latency (&lt;5000ms), and automated containment loops.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2 font-mono">
            <button
              disabled={injecting}
              onClick={handleRunFullSuite}
              className="bg-rose-600 hover:bg-rose-500 disabled:opacity-50 text-white text-xs px-3.5 py-2 rounded font-bold transition-all shadow-md flex items-center gap-1.5"
            >
              <span>{injecting ? '⚡ Executing Suite...' : '⚡ Run Full Chaos Suite'}</span>
            </button>
            <button
              onClick={downloadMarkdownReport}
              disabled={!report}
              className="bg-base-800 hover:bg-base-700 disabled:opacity-50 text-slate-200 text-xs px-3 py-2 rounded border border-base-600 font-semibold transition-all flex items-center gap-1.5"
            >
              <span>📥 Export Audit Report</span>
            </button>
          </div>
        </div>

        {/* Resilience Scoreboard Highlights */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 pt-2">
          <div className="p-3 bg-base-950/80 border border-base-800 rounded-lg">
            <div className="text-[10px] text-slate-500 uppercase font-mono">Defensive Coverage Index (DCI)</div>
            <div className="text-2xl font-bold text-emerald-400 font-mono mt-1">
              {report?.metrics?.defensive_coverage_index ?? 100.0}%
            </div>
            <div className="text-[10px] text-slate-400 mt-0.5">{report?.compliance_evaluation?.assessment_tier || 'SOC2 Ready'}</div>
          </div>

          <div className="p-3 bg-base-950/80 border border-base-800 rounded-lg">
            <div className="text-[10px] text-slate-500 uppercase font-mono">Total Simulations Run</div>
            <div className="text-2xl font-bold text-slate-100 font-mono mt-1">
              {report?.metrics?.total_fault_simulations_run ?? history.length}
            </div>
            <div className="text-[10px] text-emerald-400 mt-0.5">
              ✓ {report?.metrics?.successfully_blocked_and_logged ?? history.filter(h => h.alert_triggered).length} Triggered
            </div>
          </div>

          <div className="p-3 bg-base-950/80 border border-base-800 rounded-lg">
            <div className="text-[10px] text-slate-500 uppercase font-mono">Average Detection Latency</div>
            <div className="text-2xl font-bold text-cyan-400 font-mono mt-1">
              {report?.metrics?.avg_detection_latency_ms ?? 124} <span className="text-xs text-slate-400 font-sans">ms</span>
            </div>
            <div className="text-[10px] text-emerald-400 mt-0.5">SLA Threshold: &lt;5000ms</div>
          </div>

          <div className="p-3 bg-base-950/80 border border-base-800 rounded-lg">
            <div className="text-[10px] text-slate-500 uppercase font-mono">Unique CWEs Tested</div>
            <div className="text-2xl font-bold text-purple-300 font-mono mt-1">
              {report?.metrics?.unique_cwe_classes_tested ?? 5} / 9
            </div>
            <div className="text-[10px] text-slate-400 mt-0.5">Beizer &amp; IEEE 1044 Mapped</div>
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex border-b border-base-700 gap-2 text-xs font-mono">
        <button
          onClick={() => setActiveTab('arena')}
          className={`px-4 py-2.5 font-bold border-b-2 transition-all flex items-center gap-2 ${
            activeTab === 'arena'
              ? 'border-rose-500 text-rose-400 bg-rose-950/20'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <span>🎯 Defect Injection Arena</span>
        </button>
        <button
          onClick={() => setActiveTab('terminal')}
          className={`px-4 py-2.5 font-bold border-b-2 transition-all flex items-center gap-2 ${
            activeTab === 'terminal'
              ? 'border-cyan-500 text-cyan-400 bg-cyan-950/20'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <span>💻 Real-Time Attack Stream</span>
          <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse"></span>
        </button>
        <button
          onClick={() => setActiveTab('profiles')}
          className={`px-4 py-2.5 font-bold border-b-2 transition-all flex items-center gap-2 ${
            activeTab === 'profiles'
              ? 'border-purple-500 text-purple-300 bg-purple-950/20'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <span>🔬 Dynamic Bug Versioning</span>
          <span className="px-1.5 py-0.2 bg-purple-950 text-purple-300 rounded text-[10px]">{profiles.length}</span>
        </button>
        <button
          onClick={() => setActiveTab('report')}
          className={`px-4 py-2.5 font-bold border-b-2 transition-all flex items-center gap-2 ${
            activeTab === 'report'
              ? 'border-emerald-500 text-emerald-400 bg-emerald-950/20'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <span>📊 Resilience Audit Report</span>
        </button>
      </div>

      {/* Tab 1: Defect Injection Arena */}
      {activeTab === 'arena' && (
        <div className="space-y-6">
          {/* Class Filter Pills */}
          <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
            <span className="text-slate-500 mr-1">Filter Class:</span>
            {['ALL', 'LOGICAL', 'SYSTEM', 'RF', 'CRYPTO', 'ML'].map(cat => (
              <button
                key={cat}
                onClick={() => setSelectedClass(cat)}
                className={`px-2.5 py-1 rounded text-[11px] font-semibold transition-colors ${
                  selectedClass === cat
                    ? 'bg-rose-600 text-white'
                    : 'bg-base-800 text-slate-400 hover:bg-base-700 hover:text-slate-200'
                }`}
              >
                {cat === 'ALL' ? 'All Classes' : cat}
              </button>
            ))}
          </div>

          {/* Interactive Defect Cards Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {filteredTaxonomy.map(tax => (
              <div
                key={tax.bug_variety}
                className={`panel p-4 rounded-xl border transition-all flex flex-col justify-between ${
                  selectedVariety === tax.bug_variety
                    ? 'bg-rose-950/20 border-rose-500 shadow-lg shadow-rose-950/30'
                    : 'bg-base-900 border-base-800 hover:border-base-700'
                }`}
              >
                <div className="space-y-2">
                  <div className="flex items-start justify-between gap-2">
                    <span className="text-[10px] text-slate-500 uppercase font-mono">{tax.defect_class}</span>
                    <span className="text-[10px] bg-rose-950 text-rose-300 px-2 py-0.5 rounded border border-rose-800 font-mono font-bold">
                      {tax.cwe_mapping}
                    </span>
                  </div>

                  <h3 className="text-sm font-bold text-slate-100">{tax.bug_variety}</h3>
                  <p className="text-xs text-slate-400">{tax.description}</p>

                  <div className="p-2 bg-base-950 rounded border border-base-800/80 text-[11px] font-mono text-slate-300">
                    <span className="text-slate-500 block text-[9px] uppercase">Payload Simulation Method:</span>
                    {tax.simulation_method}
                  </div>
                </div>

                <div className="pt-4 flex items-center justify-between border-t border-base-800 mt-3">
                  <span className={`text-[10px] font-mono font-bold ${
                    tax.severity === 'CRITICAL' ? 'text-rose-400' : tax.severity === 'HIGH' ? 'text-amber-400' : 'text-blue-400'
                  }`}>
                    ● {tax.severity}
                  </span>

                  <button
                    disabled={injecting}
                    onClick={() => {
                      setSelectedVariety(tax.bug_variety)
                      handleInjectFault(tax.bug_variety)
                    }}
                    className="bg-rose-600 hover:bg-rose-500 disabled:opacity-50 text-white text-xs px-3 py-1.5 rounded font-mono font-bold transition-all shadow flex items-center gap-1"
                  >
                    <span>⚡ Inject Fault</span>
                  </button>
                </div>
              </div>
            ))}
          </div>

          {/* Parameters Drawer */}
          <div className="panel p-4 bg-base-900 border border-base-700 rounded-xl space-y-3 font-mono text-xs">
            <h3 className="font-bold text-slate-200 uppercase text-[11px] tracking-wider text-rose-400 flex items-center gap-2">
              <span>⚙ Dynamic Simulation Parameters</span>
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <div>
                <label className="text-[10px] text-slate-400 block mb-1">Target Organization (CWE-639 BOLA)</label>
                <input
                  type="text"
                  value={targetOrgId}
                  onChange={e => setTargetOrgId(e.target.value)}
                  className="w-full bg-base-950 border border-base-700 rounded px-2.5 py-1.5 text-slate-200"
                />
              </div>
              <div>
                <label className="text-[10px] text-slate-400 block mb-1">Target Wireless MAC (CWE-119 RF)</label>
                <input
                  type="text"
                  value={targetMac}
                  onChange={e => setTargetMac(e.target.value)}
                  className="w-full bg-base-950 border border-base-700 rounded px-2.5 py-1.5 text-slate-200"
                />
              </div>
              <div>
                <label className="text-[10px] text-slate-400 block mb-1">Lookback Baseline Rate EPS (CWE-1039)</label>
                <input
                  type="number"
                  step="0.1"
                  value={baselineRate}
                  onChange={e => setBaselineRate(e.target.value)}
                  className="w-full bg-base-950 border border-base-700 rounded px-2.5 py-1.5 text-slate-200"
                />
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Tab 2: Real-Time Attack Terminal */}
      {activeTab === 'terminal' && (
        <div className="space-y-4 font-mono">
          <div className="panel p-4 bg-black border border-cyan-500/40 rounded-xl space-y-3 shadow-2xl">
            <div className="flex items-center justify-between border-b border-base-800 pb-2">
              <div className="flex items-center gap-2">
                <span className="w-3 h-3 rounded-full bg-rose-500"></span>
                <span className="w-3 h-3 rounded-full bg-amber-500"></span>
                <span className="w-3 h-3 rounded-full bg-emerald-500"></span>
                <span className="text-xs font-bold text-cyan-400 ml-2">chaos-daemon@edge-sandbox: ~ /live-telemetry</span>
              </div>
              <button
                onClick={() => setTerminalLogs([])}
                className="text-[10px] text-slate-500 hover:text-slate-300"
              >
                Clear Terminal
              </button>
            </div>

            <div className="h-96 overflow-y-auto space-y-1.5 text-xs text-slate-300 p-2 font-mono">
              {terminalLogs.map((log, i) => (
                <div key={i} className="flex items-start gap-2 leading-relaxed">
                  <span className="text-slate-600 select-none">[{log.time}]</span>
                  <span className={`px-1.5 py-0.2 rounded text-[10px] font-bold ${
                    log.type === 'INJECT' ? 'bg-rose-950 text-rose-300 border border-rose-800' :
                    log.type === 'EXEC' ? 'bg-purple-950 text-purple-300 border border-purple-800' :
                    log.type === 'SLA' ? 'bg-blue-950 text-blue-300 border border-blue-800' :
                    log.type === 'ALERT' ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' :
                    log.type === 'WARN' ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                    'bg-base-800 text-slate-300'
                  }`}>
                    {log.type}
                  </span>
                  <span className="text-slate-200">{log.msg}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Tab 3: Dynamic Bug Versioning Profiles */}
      {activeTab === 'profiles' && (
        <div className="space-y-4 font-mono">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-bold text-slate-200 uppercase tracking-wider">
              Discovered Tech Stack — Versioned Vulnerability Profiles
            </h2>
            <span className="text-xs text-slate-400">{profiles.length} Active Profiles Mapped</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {profiles.map(prof => (
              <div key={prof.software_id} className="panel p-5 bg-base-900 border border-base-800 rounded-xl space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="text-purple-400 text-lg">📦</span>
                    <div>
                      <h3 className="text-sm font-bold text-slate-100">{prof.software_name}</h3>
                      <span className="text-[10px] text-cyan-300">{prof.detected_version}</span>
                    </div>
                  </div>
                  <button
                    disabled={injecting}
                    onClick={() => handleInjectFault(prof.vulnerabilities[0]?.cwe_class.includes('639') ? 'Tenant Isolation Bypass' : 'Buffer Overflow Attempt')}
                    className="bg-purple-600 hover:bg-purple-500 disabled:opacity-50 text-white text-xs px-3 py-1.5 rounded font-bold transition-all shadow"
                  >
                    <span>Run Verification Test</span>
                  </button>
                </div>

                <div className="space-y-2 pt-2 border-t border-base-800">
                  <span className="text-[10px] text-slate-500 uppercase">Known Vulnerability Signatures (CVE / CWE):</span>
                  {prof.vulnerabilities.map(vuln => (
                    <div key={vuln.id} className="p-2.5 bg-base-950 rounded border border-base-800/80 text-xs space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-rose-300">{vuln.id} ({vuln.cwe_class})</span>
                        <span className="text-[10px] bg-rose-950 text-rose-400 px-1.5 py-0.5 rounded border border-rose-800 font-bold">
                          CVSS {vuln.severity}
                        </span>
                      </div>
                      <div className="text-slate-300 font-sans text-[11px]">{vuln.name}</div>
                      <div className="text-[10px] text-emerald-400 font-sans">
                        <span className="font-bold">Remediation:</span> {vuln.remediation}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tab 4: Model Security Resilience Report */}
      {activeTab === 'report' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between font-mono">
            <div>
              <h2 className="text-sm font-bold text-slate-200 uppercase tracking-wider">
                Model Security Resilience Report (Audit-Ready)
              </h2>
              <span className="text-xs text-slate-400">Reference: {report?.report_reference || 'SRR-2026-09-03'}</span>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={copyMarkdownReport}
                className="bg-base-800 hover:bg-base-700 text-slate-200 text-xs px-3 py-1.5 rounded border border-base-600 font-semibold transition-all flex items-center gap-1.5"
              >
                <span>📋 Copy Markdown</span>
              </button>
              <button
                onClick={downloadMarkdownReport}
                className="bg-emerald-600 hover:bg-emerald-500 text-white text-xs px-3 py-1.5 rounded font-bold transition-all shadow flex items-center gap-1.5"
              >
                <span>📥 Download .md</span>
              </button>
            </div>
          </div>

          {/* Formatted Markdown Preview */}
          <div className="panel p-6 bg-base-950 border border-base-800 rounded-xl space-y-4 font-mono text-xs">
            <pre className="whitespace-pre-wrap font-mono text-slate-300 bg-base-900/60 p-4 rounded-lg border border-base-800 overflow-x-auto leading-relaxed">
              {report?.markdown_report || 'Compiling model resilience report...'}
            </pre>
          </div>
        </div>
      )}

      {/* Historical Simulation Ledger Table */}
      <div className="panel p-5 bg-base-900 border border-base-700 rounded-xl space-y-3 font-mono">
        <div className="flex items-center justify-between border-b border-base-800 pb-3">
          <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
            <span>📋 Simulation Execution Ledger &amp; SLA Compliance</span>
          </h3>
          <span className="text-[11px] text-slate-400">{history.length} Total Runs</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="text-[10px] text-slate-500 uppercase border-b border-base-800 bg-base-950/50">
              <tr>
                <th className="py-2.5 px-3">Simulation ID</th>
                <th className="py-2.5 px-3">Bug Variety</th>
                <th className="py-2.5 px-3">CWE Class</th>
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3">Latency</th>
                <th className="py-2.5 px-3">SLA Status</th>
                <th className="py-2.5 px-3">Alert Trigger</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-base-800 text-slate-300 text-[11px]">
              {history.length === 0 ? (
                <tr>
                  <td colSpan="7" className="py-4 text-center text-slate-500">
                    No simulations executed yet. Click "Inject Fault" or "Run Full Chaos Suite" above.
                  </td>
                </tr>
              ) : (
                history.map(h => (
                  <tr key={h.id} className="hover:bg-base-800/40 transition-colors">
                    <td className="py-2.5 px-3 font-bold text-slate-200">{h.simulation_id}</td>
                    <td className="py-2.5 px-3">{h.bug_variety}</td>
                    <td className="py-2.5 px-3 text-rose-400 font-bold">{h.cwe_class}</td>
                    <td className="py-2.5 px-3">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                        h.severity === 'CRITICAL' ? 'bg-rose-950 text-rose-300' :
                        h.severity === 'HIGH' ? 'bg-amber-950 text-amber-300' : 'bg-blue-950 text-blue-300'
                      }`}>
                        {h.severity}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 font-bold text-cyan-300">{h.detection_latency_ms} ms</td>
                    <td className="py-2.5 px-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        h.sla_compliance === 'MET' ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-rose-950 text-rose-400 border border-rose-800'
                      }`}>
                        {h.sla_compliance}
                      </span>
                    </td>
                    <td className="py-2.5 px-3">
                      {h.alert_triggered ? (
                        <span className="text-emerald-400 font-bold">✅ TRIGGERED</span>
                      ) : (
                        <span className="text-rose-400 font-bold">❌ UNDETECTED</span>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
