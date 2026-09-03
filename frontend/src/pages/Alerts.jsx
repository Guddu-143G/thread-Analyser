import { useEffect, useState, useCallback } from 'react'
import client from '../api/client'
import SeverityBadge from '../components/SeverityBadge'

const STATUS_OPTIONS = ['open', 'acknowledged', 'resolved', 'false_positive']
const SEVERITY_OPTIONS = ['critical', 'high', 'medium', 'low']

export default function Alerts() {
  const [alerts, setAlerts] = useState([])
  const [loading, setLoading] = useState(true)
  const [statusFilter, setStatusFilter] = useState('')
  const [severityFilter, setSeverityFilter] = useState('')
  const [searchQuery, setSearchQuery] = useState('')
  const [selectedAlert, setSelectedAlert] = useState(null)
  
  // Triage Action Modal / Comment state
  const [triageAction, setTriageAction] = useState(null) // { id, status }
  const [analystComment, setAnalystComment] = useState('')
  const [actionLoading, setActionLoading] = useState(false)

  const [soarModal, setSoarModal] = useState(null) // { action, alert }
  const [soarParam, setSoarParam] = useState('')
  const [soarJustification, setSoarJustification] = useState('')
  const [soarFeedback, setSoarFeedback] = useState(null)
  const [aiPlaybookModal, setAiPlaybookModal] = useState(null)
  const [aiSynthesizing, setAiSynthesizing] = useState(false)
  const [aiExecuting, setAiExecuting] = useState(false)
  const [provenanceModal, setProvenanceModal] = useState(null)
  const [provenanceLoading, setProvenanceLoading] = useState(false)

  // V7 Forensic Time-Travel State
  const [timeTravelModal, setTimeTravelModal] = useState(null)
  const [timeTravelLoading, setTimeTravelLoading] = useState(false)
  const [currentFrameIdx, setCurrentFrameIdx] = useState(0)
  const [isPlayingTimeline, setIsPlayingTimeline] = useState(false)




  const load = useCallback(() => {
    setLoading(true)
    const params = {}
    if (statusFilter) params.status = statusFilter
    if (severityFilter) params.severity = severityFilter
    if (searchQuery) params.search = searchQuery

    client
      .get('/alerts', { params })
      .then(({ data }) => {
        setAlerts(data)
        if (data.length > 0) {
          setSelectedAlert((prev) => {
            const found = data.find((a) => a.id === prev?.id)
            return found || data[0]
          })
        } else {
          setSelectedAlert(null)
        }
      })
      .finally(() => setLoading(false))
  }, [statusFilter, severityFilter, searchQuery])

  useEffect(() => {
    load()
  }, [load])

  const handleOpenTriage = (status) => {
    if (!selectedAlert) return
    setTriageAction({ id: selectedAlert.id, status })
    setAnalystComment('')
  }

  const submitTriageAction = async (e) => {
    e.preventDefault()
    if (!triageAction) return
    setActionLoading(true)
    try {
      const { data } = await client.patch(`/alerts/${triageAction.id}`, {
        status: triageAction.status,
        comment: analystComment.trim() || undefined,
      })
      setSelectedAlert(data)
      setTriageAction(null)
      load()
    } catch (err) {
      alert('Failed to update alert status: ' + (err.response?.data?.detail || err.message))
    } finally {
      setActionLoading(false)
    }
  }

  const handleOpenSOAR = (actionType) => {
    if (!selectedAlert) return
    const defaultTarget = selectedAlert.device_id || selectedAlert.evidence?.src_ip || 'host-endpoint'
    setSoarModal({
      action: actionType,
      alert: selectedAlert,
    })
    setSoarParam(defaultTarget)
    setSoarJustification(`Automated containment for alert ${selectedAlert.id.slice(0, 8)}`)
  }

  const submitSOARAction = async (e) => {
    e.preventDefault()
    if (!soarModal) return
    setActionLoading(true)
    try {
      const { data } = await client.post(`/alerts/${soarModal.alert.id}/mitigate`, {
        action: soarModal.action,
        target: soarParam.trim() || undefined,
        comment: soarJustification.trim() || undefined,
      })
      setSoarFeedback({
        type: 'success',
        message: data.message,
        timestamp: new Date().toLocaleTimeString(),
      })
      setSoarModal(null)
      const refreshed = await client.get(`/alerts/${soarModal.alert.id}`)
      setSelectedAlert(refreshed.data)
      load()
    } catch (err) {
      setSoarFeedback({
        type: 'error',
        message: 'SOAR Action failed: ' + (err.response?.data?.detail || err.message),
        timestamp: new Date().toLocaleTimeString(),
      })
    } finally {
      setActionLoading(false)
    }
  }

  const handleSynthesizeAIPlaybook = async () => {
    if (!selectedAlert) return
    setAiSynthesizing(true)
    try {
      const { data } = await client.post(`/alerts/${selectedAlert.id}/ai-synthesize`)
      setAiPlaybookModal(data)
    } catch (err) {
      alert('AI Playbook synthesis failed: ' + (err.response?.data?.detail || err.message))
    } finally {
      setAiSynthesizing(false)
    }
  }

  const handleExecuteAIPlaybook = async () => {
    if (!selectedAlert || !aiPlaybookModal) return
    setAiExecuting(true)
    try {
      const { data } = await client.post(`/alerts/${selectedAlert.id}/ai-execute`, aiPlaybookModal)
      setSoarFeedback({
        type: 'success',
        message: data.message,
        timestamp: new Date().toLocaleTimeString(),
      })
      setAiPlaybookModal(null)
      const refreshed = await client.get(`/alerts/${selectedAlert.id}`)
      setSelectedAlert(refreshed.data)
      load()
    } catch (err) {
      alert('Execution failed: ' + (err.response?.data?.detail || err.message))
    } finally {
      setAiExecuting(false)
    }
  }

  const handleOpenProvenance = async () => {
    if (!selectedAlert) return
    setProvenanceLoading(true)
    try {
      const { data } = await client.get(`/alerts/${selectedAlert.id}/provenance`)
      setProvenanceModal(data)
    } catch (err) {
      alert('Failed to load provenance DAG: ' + (err.response?.data?.detail || err.message))
    } finally {
      setProvenanceLoading(false)
    }
  }

  const handleOpenTimeTravel = async () => {
    if (!selectedAlert) return
    setTimeTravelLoading(true)
    try {
      const devId = selectedAlert.device_id || 'srv-ecommerce-01'
      const { data } = await client.get(`/forensics/timeline/${devId}`, {
        params: { alert_id: selectedAlert.id }
      })
      setTimeTravelModal(data)
      setCurrentFrameIdx(data.patient_zero_sequence_id ? data.patient_zero_sequence_id - 1 : 0)
    } catch (err) {
      alert('Failed to load forensic timeline: ' + (err.response?.data?.detail || err.message))
    } finally {
      setTimeTravelLoading(false)
    }
  }

  useEffect(() => {
    let interval = null
    if (isPlayingTimeline && timeTravelModal?.timeline_frames?.length) {
      interval = setInterval(() => {
        setCurrentFrameIdx((prev) => {
          if (prev >= timeTravelModal.timeline_frames.length - 1) {
            setIsPlayingTimeline(false)
            return prev
          }
          return prev + 1
        })
      }, 1500)
    }
    return () => clearInterval(interval)
  }, [isPlayingTimeline, timeTravelModal])


  const isCompoundIncident = (a) => {

    return (
      a?.title?.toLowerCase().includes('compound') ||
      Boolean(a?.evidence?.compound_risk_score) ||
      Boolean(a?.evidence?.mitre_mapping)
    )
  }


  return (
    <div className="space-y-4 h-[calc(100vh-3.5rem)] flex flex-col">
      {/* Header Bar */}
      <div className="flex items-center justify-between shrink-0">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <span>Alert Triage &amp; Incident Console</span>
            <span className="text-xs font-mono font-normal bg-accent/15 text-accent px-2 py-0.5 rounded border border-accent/30 flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-accent animate-pulse"></span>
              MITRE ATT&CK Graph &amp; SOAR
            </span>
          </h1>
          <p className="text-slate-400 text-xs mt-0.5">
            Real-time multi-stage threat correlation, OCSF telemetry trace, and cryptographic SOAR containment
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={load} className="btn-secondary text-xs px-3 py-1.5 flex items-center gap-1.5 font-mono">
            <span>⟳</span> Refresh Stream
          </button>
        </div>
      </div>

      {/* Filter Toolbar */}
      <div className="flex flex-wrap items-center gap-3 bg-base-900 p-3 rounded-lg border border-base-700 shrink-0">
        <div className="flex-1 min-w-[240px]">
          <input
            className="input-field text-xs py-1.5"
            placeholder="Search alerts by title, MITRE tactic, keyword, IP, user, or threat..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>

        <select
          className="input-field w-auto text-xs py-1.5 font-mono"
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
        >
          <option value="">All Statuses ({alerts.length})</option>
          {STATUS_OPTIONS.map((s) => (
            <option key={s} value={s}>{s.replace('_', ' ').toUpperCase()}</option>
          ))}
        </select>

        <select
          className="input-field w-auto text-xs py-1.5 font-mono"
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
        >
          <option value="">All Severities</option>
          {SEVERITY_OPTIONS.map((s) => (
            <option key={s} value={s}>{s.toUpperCase()}</option>
          ))}
        </select>
      </div>

      {/* Dual-Pane Workspace */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 flex-1 min-h-0 overflow-hidden">
        {/* LEFT PANE: Alert List Stream (5 cols) */}
        <div className="lg:col-span-5 bg-base-900 border border-base-700 rounded-lg flex flex-col overflow-hidden">
          <div className="px-4 py-2.5 bg-base-950/60 border-b border-base-700 flex items-center justify-between text-xs font-medium text-slate-400">
            <span>Active Incident Stream ({alerts.length})</span>
            <span className="font-mono text-[11px] text-slate-500">Sorted by newest</span>
          </div>

          <div className="flex-1 overflow-y-auto divide-y divide-base-700/60">
            {loading && <div className="p-8 text-center text-slate-500 text-sm">Loading security telemetry…</div>}
            {!loading && alerts.length === 0 && (
              <div className="p-8 text-center text-slate-500 text-sm">No security incidents match the active filters.</div>
            )}
            {alerts.map((a) => {
              const isSelected = selectedAlert?.id === a.id
              const isCompound = isCompoundIncident(a)
              return (
                <div
                  key={a.id}
                  onClick={() => setSelectedAlert(a)}
                  className={`p-3.5 cursor-pointer transition-all ${
                    isSelected
                      ? 'bg-base-800 border-l-4 border-l-accent shadow-inner'
                      : 'hover:bg-base-800/60 border-l-4 border-l-transparent'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2 mb-1.5">
                    <div className="flex items-center gap-1.5 flex-wrap">
                      <SeverityBadge severity={a.severity} />
                      <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded uppercase font-semibold ${
                        a.status === 'open' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' :
                        a.status === 'acknowledged' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30' :
                        a.status === 'resolved' ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' :
                        'bg-slate-500/20 text-slate-400 border border-slate-500/30'
                      }`}>
                        {a.status.replace('_', ' ')}
                      </span>
                      {isCompound && (
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-700/80 font-bold flex items-center gap-1">
                          <span>⚡</span> COMPOUND DAG
                        </span>
                      )}
                    </div>
                    <span className="text-[11px] text-slate-500 font-mono">
                      {new Date(a.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                    </span>
                  </div>

                  <h3 className={`text-sm font-semibold truncate ${isSelected ? 'text-accent' : 'text-slate-200'}`}>
                    {a.title}
                  </h3>

                  {a.description && (
                    <p className="text-xs text-slate-400 line-clamp-1 mt-0.5">{a.description}</p>
                  )}

                  <div className="flex items-center justify-between mt-2 text-[11px] font-mono text-slate-500">
                    <span>Host: {a.device_id?.slice(0, 8) || a.evidence?.ocsf?.device?.hostname || a.evidence?.correlated_asset || 'sensor'}</span>
                    {a.evidence?.src_ip && <span>IP: {a.evidence.src_ip}</span>}
                    {a.evidence?.compound_risk_score && (
                      <span className="text-rose-400 font-bold">Score: {a.evidence.compound_risk_score}/100</span>
                    )}
                  </div>
                </div>
              )
            })}
          </div>
        </div>

        {/* RIGHT PANE: Deep Trace Viewer & Triage Deck (7 cols) */}
        <div className="lg:col-span-7 bg-base-900 border border-base-700 rounded-lg flex flex-col overflow-hidden">
          {selectedAlert ? (
            <div className="flex-1 flex flex-col overflow-hidden">
              {/* Header & Meta */}
              <div className="p-4 bg-base-950/80 border-b border-base-700 shrink-0">
                <div className="flex items-start justify-between gap-3">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <SeverityBadge severity={selectedAlert.severity} />
                      <span className="text-xs font-mono uppercase bg-base-800 text-slate-300 px-2 py-0.5 rounded border border-base-600">
                        STATUS: {selectedAlert.status.replace('_', ' ')}
                      </span>
                      {isCompoundIncident(selectedAlert) && (
                        <span className="text-xs font-mono bg-purple-950 text-purple-300 px-2 py-0.5 rounded border border-purple-700 font-bold">
                          ⚡ MITRE ATT&CK COMPOUND INCIDENT
                        </span>
                      )}
                      <span className="text-xs font-mono text-slate-500">ID: {selectedAlert.id}</span>
                    </div>
                    <h2 className="text-lg font-bold text-slate-100">{selectedAlert.title}</h2>
                    <p className="text-xs text-slate-300">{selectedAlert.description}</p>
                  </div>
                </div>

                {/* Quick Info Strip */}
                <div className="grid grid-cols-3 gap-2 mt-3 pt-3 border-t border-base-800 text-xs font-mono text-slate-400">
                  <div>
                    <span className="text-slate-500 block text-[10px] uppercase">Sensor / Target</span>
                    <span className="text-slate-200 font-semibold">{selectedAlert.device_id || selectedAlert.evidence?.ocsf?.device?.hostname || selectedAlert.evidence?.correlated_asset || 'Global Gateway'}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block text-[10px] uppercase">Timestamp (UTC)</span>
                    <span className="text-slate-200">{new Date(selectedAlert.created_at).toUTCString()}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block text-[10px] uppercase">Rule / Correlator Source</span>
                    <span className="text-slate-200 truncate block">
                      {isCompoundIncident(selectedAlert)
                        ? 'MITRE Correlation DAG'
                        : selectedAlert.rule_id
                        ? `Rule: ${selectedAlert.rule_id.slice(0, 8)}`
                        : selectedAlert.ioc_id
                        ? `IOC: ${selectedAlert.ioc_id.slice(0, 8)}`
                        : 'ML Anomaly Model'}
                    </span>
                  </div>
                </div>
              </div>

              {/* Feedback Banner */}
              {soarFeedback && (
                <div className={`px-4 py-2 text-xs flex items-center justify-between ${
                  soarFeedback.type === 'success' ? 'bg-emerald-950/80 text-emerald-300 border-b border-emerald-800 font-mono' : 'bg-rose-950/80 text-rose-300 border-b border-rose-800 font-mono'
                }`}>
                  <span>[SOAR Orchestration Dispatch]: {soarFeedback.message}</span>
                  <button onClick={() => setSoarFeedback(null)} className="text-slate-400 hover:text-slate-200">✕</button>
                </div>
              )}

              {/* Scrollable Trace Content */}
              <div className="flex-1 overflow-y-auto p-4 space-y-4">
                {/* Compound Attack DAG Breakdown if applicable */}
                {isCompoundIncident(selectedAlert) && (
                  <div className="p-3.5 bg-purple-950/40 border border-purple-800/60 rounded-lg space-y-3 font-mono">
                    <div className="flex items-center justify-between text-xs border-b border-purple-800/40 pb-2">
                      <span className="text-purple-300 font-bold flex items-center gap-1.5">
                        <span>🕸</span> MITRE ATT&CK Multi-Stage Threat Correlation
                      </span>
                      {selectedAlert.evidence?.compound_risk_score && (
                        <span className="bg-rose-950 text-rose-300 px-2 py-0.5 rounded border border-rose-800 font-bold">
                          Asset Risk: {selectedAlert.evidence.compound_risk_score}/100
                        </span>
                      )}
                    </div>

                    {selectedAlert.evidence?.mitre_mapping?.phases && (
                      <div>
                        <div className="text-[11px] text-purple-400 font-semibold mb-1.5 uppercase">Kill Chain Progression:</div>
                        <div className="flex items-center gap-2 flex-wrap">
                          {selectedAlert.evidence.mitre_mapping.phases.map((phase, idx) => (
                            <span key={idx} className="flex items-center gap-2">
                              <span className="bg-base-950 text-slate-200 px-2 py-1 rounded border border-purple-700/60 text-xs">
                                {phase}
                              </span>
                              {idx < selectedAlert.evidence.mitre_mapping.phases.length - 1 && (
                                <span className="text-purple-400 text-xs font-bold">➔</span>
                              )}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    {selectedAlert.evidence?.child_alert_ids && (
                      <div className="text-[11px] text-slate-400">
                        <span>Correlated Child Incidents: </span>
                        <span className="text-purple-300 font-semibold">{selectedAlert.evidence.child_alert_ids.length} alerts linked</span>
                      </div>
                    )}
                  </div>
                )}

                {/* OCSF Semantic Class Header if available */}
                {selectedAlert.evidence?.ocsf && (
                  <div className="p-3 bg-base-950 border border-base-700/80 rounded-lg space-y-2 font-mono">
                    <div className="flex items-center justify-between text-xs border-b border-base-800 pb-2">
                      <span className="text-accent font-semibold flex items-center gap-1.5">
                        <span>🛡</span> OCSF Semantic Data Classification
                      </span>
                      <span className="text-slate-400 text-[11px]">
                        Class UID: {selectedAlert.evidence.ocsf.class_uid} | v{selectedAlert.evidence.ocsf.metadata?.version || '1.1.0'}
                      </span>
                    </div>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs">
                      <div>
                        <span className="text-slate-500 block text-[10px]">Actor User</span>
                        <span className="text-slate-300 truncate block">{selectedAlert.evidence.ocsf.actor?.user?.name || selectedAlert.evidence.ocsf.user?.name || 'N/A'}</span>
                      </div>
                      <div>
                        <span className="text-slate-500 block text-[10px]">Source Endpoint</span>
                        <span className="text-slate-300 truncate block">{selectedAlert.evidence.ocsf.src_endpoint?.ip || selectedAlert.evidence.ocsf.network_activity?.src_endpoint?.ip || 'N/A'}</span>
                      </div>
                      <div>
                        <span className="text-slate-500 block text-[10px]">Process / Target</span>
                        <span className="text-slate-300 truncate block">{selectedAlert.evidence.ocsf.process?.name || selectedAlert.evidence.ocsf.command || 'N/A'}</span>
                      </div>
                      <div>
                        <span className="text-slate-500 block text-[10px]">Protocol / Status</span>
                        <span className="text-slate-300 truncate block">{selectedAlert.evidence.ocsf.auth_protocol || selectedAlert.evidence.ocsf.network_activity?.protocol || 'Logged'}</span>
                      </div>
                    </div>
                  </div>
                )}

                {/* Evidence & Raw Telemetry */}
                <div>
                  <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-400 mb-1.5 flex items-center justify-between">
                    <span>Forensic Evidence &amp; Trace Telemetry</span>
                    <button
                      onClick={() => navigator.clipboard.writeText(JSON.stringify(selectedAlert.evidence, null, 2))}
                      className="text-[11px] text-accent hover:underline font-mono"
                    >
                      Copy JSON
                    </button>
                  </h3>
                  <pre className="bg-base-950 border border-base-700 rounded-lg p-3 text-xs text-emerald-400/90 font-mono overflow-x-auto max-h-60">
                    {JSON.stringify(selectedAlert.evidence, null, 2)}
                  </pre>
                </div>

                {/* Triage Comments History */}
                {selectedAlert.evidence?.triage_comments && selectedAlert.evidence.triage_comments.length > 0 && (
                  <div className="space-y-2">
                    <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-400">Analyst Triage Trail</h3>
                    <div className="space-y-1.5">
                      {selectedAlert.evidence.triage_comments.map((c, i) => (
                        <div key={i} className="p-2.5 bg-base-950 border border-base-800 rounded text-xs font-mono">
                          <div className="flex items-center justify-between text-slate-400 mb-1">
                            <span className="font-semibold text-slate-200">{c.user}</span>
                            <span className="text-[10px] text-slate-500">{new Date(c.timestamp).toLocaleString()}</span>
                          </div>
                          <p className="text-slate-300 font-sans">{c.comment}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Triage Action Command Deck & SOAR Buttons */}
              <div className="p-3 bg-base-950 border-t border-base-700 shrink-0 space-y-2">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  {/* Status buttons */}
                  <div className="flex items-center gap-1.5">
                    <span className="text-xs font-mono text-slate-500 mr-1">Triage:</span>
                    <button
                      disabled={actionLoading || selectedAlert.status === 'acknowledged'}
                      onClick={() => handleOpenTriage('acknowledged')}
                      className="btn-secondary text-xs px-2.5 py-1.5 hover:border-amber-400 hover:text-amber-300 font-mono"
                    >
                      Acknowledge
                    </button>
                    <button
                      disabled={actionLoading || selectedAlert.status === 'resolved'}
                      onClick={() => handleOpenTriage('resolved')}
                      className="btn-secondary text-xs px-2.5 py-1.5 hover:border-emerald-400 hover:text-emerald-300 font-mono"
                    >
                      Resolve
                    </button>
                    <button
                      disabled={actionLoading || selectedAlert.status === 'false_positive'}
                      onClick={() => handleOpenTriage('false_positive')}
                      className="btn-secondary text-xs px-2.5 py-1.5 hover:border-slate-400 font-mono"
                    >
                      Mark False+
                    </button>
                  </div>

                  {/* SOAR Active Response Actions */}
                  <div className="flex items-center gap-1.5 flex-wrap">
                    <span className="text-xs font-mono text-slate-500 mr-1">SOAR:</span>
                    <button
                      disabled={actionLoading || aiSynthesizing}
                      onClick={handleSynthesizeAIPlaybook}
                      className="bg-gradient-to-r from-purple-900/60 to-indigo-900/60 text-purple-200 border border-purple-500/50 hover:border-purple-400 text-xs px-2.5 py-1.5 rounded font-mono font-bold transition-all shadow-sm flex items-center gap-1"
                      title="Dynamically generate cognitive multi-step containment playbook"
                    >
                      <span>✨</span>
                      <span>{aiSynthesizing ? 'Synthesizing...' : 'AI Playbook'}</span>
                    </button>
                    <button
                      disabled={actionLoading}
                      onClick={() => handleOpenSOAR('isolate_host')}
                      className="bg-rose-950/60 text-rose-300 border border-rose-700/60 hover:bg-rose-900/60 text-xs px-2.5 py-1.5 rounded font-mono font-medium transition-colors"
                      title="Trigger host isolation on endpoint agent"
                    >
                      🔒 Isolate Host
                    </button>
                    <button
                      disabled={actionLoading}
                      onClick={() => handleOpenSOAR('terminate_process')}
                      className="bg-amber-950/60 text-amber-300 border border-amber-700/60 hover:bg-amber-900/60 text-xs px-2.5 py-1.5 rounded font-mono font-medium transition-colors"
                      title="Terminate suspicious process via agent API"
                    >
                      🛑 Kill Process
                    </button>
                    <button
                      disabled={actionLoading || provenanceLoading}
                      onClick={handleOpenProvenance}
                      className="bg-cyan-950/60 text-cyan-300 border border-cyan-700/60 hover:bg-cyan-900/60 text-xs px-2.5 py-1.5 rounded font-mono font-medium transition-colors flex items-center gap-1"
                      title="Trace system call provenance DAG back to Patient Zero"
                    >
                      <span>🕸</span>
                      <span>{provenanceLoading ? 'Tracing...' : 'Provenance DAG'}</span>
                    </button>
                    <button
                      disabled={actionLoading || timeTravelLoading}
                      onClick={handleOpenTimeTravel}
                      className="bg-purple-950/60 text-purple-300 border border-purple-700/60 hover:bg-purple-900/60 text-xs px-2.5 py-1.5 rounded font-mono font-medium transition-colors flex items-center gap-1"
                      title="Launch deterministic forensic time-travel flight recorder"
                    >
                      <span>⏱️</span>
                      <span>{timeTravelLoading ? 'Loading Flight Recorder...' : 'Forensic Time-Travel'}</span>
                    </button>

                    <button
                      disabled={actionLoading}
                      onClick={() => handleOpenSOAR('revoke_session')}
                      className="bg-indigo-950/60 text-indigo-300 border border-indigo-700/60 hover:bg-indigo-900/60 text-xs px-2.5 py-1.5 rounded font-mono font-medium transition-colors"
                      title="Invalidate session tokens and force MFA"
                    >
                      ⚡ Revoke Sessions
                    </button>
                    <button
                      disabled={actionLoading}
                      onClick={() => handleOpenSOAR('cloud_mesh_quarantine')}
                      className="bg-rose-950/60 text-rose-300 border border-rose-700/60 hover:bg-rose-900/60 text-xs px-2.5 py-1.5 rounded font-mono font-medium transition-colors"
                      title="AWS Security Group & K8s NetworkPolicy self-healing cloud mesh lockdown"
                    >
                      🌐 Cloud Mesh Quarantine
                    </button>
                  </div>
                </div>

              </div>
            </div>
          ) : (
            <div className="flex-1 flex flex-col items-center justify-center p-8 text-center text-slate-500">
              <span className="text-4xl mb-2 font-mono">▲</span>
              <p className="text-sm font-medium text-slate-300">Select an incident from the stream</p>
              <p className="text-xs text-slate-500 max-w-sm mt-1">Deep forensic trace, MITRE correlation DAG, and SOAR response options will appear here.</p>
            </div>
          )}
        </div>
      </div>

      {/* Triage Comment Modal */}
      {triageAction && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
          <form onSubmit={submitTriageAction} className="bg-base-900 border border-base-600 rounded-lg p-5 max-w-md w-full space-y-4 shadow-2xl">
            <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
              <span>Triage Incident:</span>
              <span className="uppercase text-accent font-mono">{triageAction.status.replace('_', ' ')}</span>
            </h3>
            <p className="text-xs text-slate-400">
              Record a mandatory analyst justification comment for the immutable compliance audit trail:
            </p>
            <textarea
              required
              rows={3}
              className="input-field text-xs font-sans"
              placeholder="e.g., Verified threat vector. Host network isolated and firewall rules updated."
              value={analystComment}
              onChange={(e) => setAnalystComment(e.target.value)}
              autoFocus
            />
            <div className="flex items-center justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => setTriageAction(null)}
                className="btn-secondary text-xs px-3 py-1.5 font-mono"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={actionLoading}
                className="btn-primary text-xs px-4 py-1.5 font-mono"
              >
                {actionLoading ? 'Saving...' : 'Confirm Status Transition'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* SOAR Active Response Modal */}
      {soarModal && (
        <div className="fixed inset-0 bg-black/75 flex items-center justify-center z-50 p-4">
          <form onSubmit={submitSOARAction} className="bg-base-900 border border-base-600 rounded-lg p-5 max-w-lg w-full space-y-4 shadow-2xl font-mono">
            <div className="flex items-center justify-between border-b border-base-700 pb-3">
              <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
                <span>⚡ SOAR Orchestration:</span>
                <span className="uppercase text-rose-400">{soarModal.action.replace('_', ' ')}</span>
              </h3>
              <span className="text-[10px] bg-emerald-950 text-emerald-400 border border-emerald-800 px-2 py-0.5 rounded">
                HMAC-SHA256 Signed
              </span>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <label className="text-slate-400 block mb-1">Target Endpoint / Resource:</label>
                <input
                  required
                  className="input-field text-xs py-1.5"
                  value={soarParam}
                  onChange={(e) => setSoarParam(e.target.value)}
                  placeholder="e.g., srv-db-01 or 192.168.1.50 or PID"
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Analyst Justification / Audit Note:</label>
                <textarea
                  required
                  rows={2}
                  className="input-field text-xs font-sans"
                  value={soarJustification}
                  onChange={(e) => setSoarJustification(e.target.value)}
                  placeholder="Justification for containment action..."
                />
              </div>

              <div className="p-3 bg-base-950 border border-base-800 rounded text-[11px] text-slate-400 space-y-1">
                <div className="text-slate-300 font-semibold uppercase">Cryptographic Playbook Header</div>
                <div>Algorithm: <span className="text-cyan-300">HMAC-SHA256</span></div>
                <div>Envelope Action: <span className="text-amber-300">{soarModal.action}</span></div>
                <div>Destination Agent: <span className="text-slate-200">{soarParam || 'N/A'}</span></div>
              </div>
            </div>

            <div className="flex items-center justify-end gap-2 pt-2 border-t border-base-800">
              <button
                type="button"
                onClick={() => setSoarModal(null)}
                className="btn-secondary text-xs px-3 py-1.5"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={actionLoading}
                className="bg-rose-600 hover:bg-rose-500 text-white text-xs px-4 py-1.5 rounded font-bold transition-colors"
              >
                {actionLoading ? 'Dispatching...' : '🚀 Dispatch Containment Playbook'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* AI Cognitive Playbook Synthesizer Modal */}
      {aiPlaybookModal && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center z-50 p-4">
          <div className="bg-base-900 border border-purple-500/60 rounded-xl p-6 max-w-2xl w-full space-y-4 shadow-2xl font-mono animate-fade-in max-h-[90vh] flex flex-col">
            <div className="flex items-center justify-between border-b border-purple-900/60 pb-3 shrink-0">
              <div>
                <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
                  <span className="text-purple-400">✨</span>
                  <span>Cognitive AI-SOAR Playbook</span>
                  <span className="text-[10px] bg-purple-950 text-purple-300 px-2 py-0.5 rounded border border-purple-800">
                    {aiPlaybookModal.ai_engine_model}
                  </span>
                </h3>
                <p className="text-[11px] text-slate-400 mt-0.5">
                  Dynamic mitigation plan generated from real-time threat vector and entity telemetry.
                </p>
              </div>
              <div className="text-right">
                <span className="text-[10px] text-slate-500 uppercase block">Risk Mitigation Score</span>
                <span className="text-base font-bold text-emerald-400">
                  {((aiPlaybookModal.risk_mitigation_score || 0.9) * 100).toFixed(0)}% Reduction
                </span>
              </div>
            </div>

            <div className="space-y-4 overflow-y-auto pr-1 flex-1 text-xs">
              {/* Summary and Reasoning */}
              <div className="p-3 bg-base-950 border border-base-800 rounded-lg space-y-1.5">
                <div className="text-purple-300 font-bold flex items-center gap-1.5">
                  <span>◈ Threat Vector Analysis:</span>
                  <span className="text-slate-200 font-normal">{aiPlaybookModal.threat_summary}</span>
                </div>
                <div className="text-slate-400 text-[11px] font-sans">
                  {aiPlaybookModal.triage_rationale}
                </div>
              </div>

              {/* Synthesized Steps */}
              <div className="space-y-2">
                <div className="text-xs font-bold text-slate-300 uppercase tracking-wide">
                  Orchestrated Containment Steps ({aiPlaybookModal.orchestrated_actions?.length || 0}):
                </div>
                {aiPlaybookModal.orchestrated_actions?.map((step) => (
                  <div
                    key={step.step}
                    className="p-3 bg-base-950 border border-base-800 rounded-lg space-y-2 hover:border-purple-800/80 transition-colors"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-slate-200 flex items-center gap-2">
                        <span className="w-5 h-5 rounded-full bg-purple-900/60 text-purple-300 flex items-center justify-center text-[10px]">
                          {step.step}
                        </span>
                        <span className="text-cyan-300 uppercase">{step.action.replace('_', ' ')}</span>
                      </span>
                      <span className={`text-[10px] px-2 py-0.5 rounded font-bold ${
                        step.criticality === 'HIGH' ? 'bg-rose-950 text-rose-300 border border-rose-800' : 'bg-base-900 text-slate-400 border border-base-700'
                      }`}>
                        {step.criticality || 'STANDARD'}
                      </span>
                    </div>

                    <div className="grid grid-cols-2 gap-2 text-[11px] text-slate-400">
                      <div>Target: <strong className="text-slate-200">{step.target}</strong></div>
                      <div>Parameters: <code className="text-amber-300">{JSON.stringify(step.parameters)}</code></div>
                    </div>

                    {step.command_preview && (
                      <div className="p-2 bg-black/60 rounded border border-base-800 text-[11px] text-emerald-400 font-mono overflow-x-auto">
                        $ {step.command_preview}
                      </div>
                    )}
                  </div>
                ))}
              </div>

              <div className="flex justify-between items-center text-[10px] text-slate-500 pt-1">
                <span>Cryptographic Signature: <code className="text-slate-400">{aiPlaybookModal.playbook_signature}</code></span>
                <span>Confidence: {((aiPlaybookModal.confidence_score || 0.95) * 100).toFixed(0)}%</span>
              </div>
            </div>

            <div className="flex items-center justify-end gap-2 pt-3 border-t border-base-800 shrink-0">
              <button
                type="button"
                onClick={() => setAiPlaybookModal(null)}
                className="btn-secondary text-xs px-3 py-1.5"
              >
                Dismiss
              </button>
              <button
                type="button"
                disabled={aiExecuting}
                onClick={handleExecuteAIPlaybook}
                className="bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white text-xs px-4 py-1.5 rounded font-bold transition-all shadow-md flex items-center gap-1.5"
              >
                <span>⚡</span>
                <span>{aiExecuting ? 'Executing Containment...' : 'Execute AI Playbook (All Steps)'}</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Provenance DAG & Patient Zero Trace Modal */}
      {provenanceModal && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center z-50 p-4">
          <div className="bg-base-900 border border-cyan-500/60 rounded-xl p-6 max-w-3xl w-full space-y-4 shadow-2xl font-mono animate-fade-in max-h-[90vh] flex flex-col">
            <div className="flex items-center justify-between border-b border-cyan-900/60 pb-3 shrink-0">
              <div>
                <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
                  <span className="text-cyan-400">🕸</span>
                  <span>System Call Provenance DAG &amp; Patient Zero</span>
                </h3>
                <p className="text-[11px] text-slate-400 mt-0.5">
                  eBPF kernel telemetry stitched into a stateful directed acyclic lineage graph.
                </p>
              </div>
              <button
                onClick={() => setProvenanceModal(null)}
                className="text-slate-400 hover:text-slate-200 text-sm font-sans"
              >
                ✕
              </button>
            </div>

            <div className="space-y-4 overflow-y-auto pr-1 flex-1 text-xs">
              {/* Root Cause Banner */}
              <div className="p-3.5 bg-cyan-950/40 border border-cyan-800/80 rounded-lg space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="text-cyan-300 font-bold uppercase">Root Cause Identification:</span>
                  <span className="text-[10px] bg-cyan-900/60 text-cyan-200 px-2 py-0.5 rounded border border-cyan-700">
                    Blast Radius: {provenanceModal.blast_radius_count} Entities
                  </span>
                </div>
                <div className="text-slate-200 text-[11px] font-sans">
                  {provenanceModal.root_cause_explanation}
                </div>
              </div>

              {/* Patient Zero Backward Lineage Flow */}
              <div className="space-y-2">
                <div className="text-xs font-bold text-slate-300 uppercase tracking-wide flex items-center justify-between">
                  <span>Backward Lineage Traversal (Patient Zero Origin):</span>
                  <span className="text-[10px] text-slate-500 font-normal">Parent ➔ Target</span>
                </div>

                <div className="flex flex-col gap-2">
                  {provenanceModal.patient_zero_lineage?.map((node, idx) => (
                    <div
                      key={node.id}
                      className={`p-3 rounded-lg border text-xs flex items-center justify-between ${
                        idx === provenanceModal.patient_zero_lineage.length - 1
                          ? 'bg-rose-950/50 border-rose-600 text-rose-200'
                          : 'bg-base-950 border-base-800 text-slate-300'
                      }`}
                    >
                      <div className="flex items-center gap-2">
                        <span className={`w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-bold ${
                          idx === provenanceModal.patient_zero_lineage.length - 1 ? 'bg-rose-600 text-white' : 'bg-base-800 text-slate-300'
                        }`}>
                          {idx + 1}
                        </span>
                        <div>
                          <span className="font-bold uppercase text-cyan-300">[{node.label}] </span>
                          <span className="text-slate-200 font-semibold">{node.metadata?.name || node.metadata?.type || node.id}</span>
                          {node.metadata?.args && <code className="text-amber-300 text-[10px] ml-2">{node.metadata.args}</code>}
                        </div>
                      </div>

                      <div className="text-[10px] text-slate-500">
                        {idx === provenanceModal.patient_zero_lineage.length - 1 ? (
                          <span className="bg-rose-500/20 text-rose-300 px-2 py-0.5 rounded border border-rose-500/40 font-bold">
                            PATIENT ZERO ENTRY
                          </span>
                        ) : (
                          <span>Spawns child process</span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Graph Nodes & Edges Visualizer */}
              <div className="p-3 bg-base-950 border border-base-800 rounded-lg space-y-2">
                <div className="text-xs font-bold text-slate-400 uppercase">
                  Connected Lineage Graph ({provenanceModal.nodes?.length || 0} nodes, {provenanceModal.edges?.length || 0} edges):
                </div>
                <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
                  {provenanceModal.nodes?.map((n) => (
                    <div key={n.id} className="p-2 bg-base-900 border border-base-800 rounded text-[11px]">
                      <div className="text-[10px] text-cyan-400 uppercase font-bold">{n.label}: {n.id}</div>
                      <div className="text-slate-300 text-[10px] truncate">{JSON.stringify(n.metadata)}</div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            <div className="flex justify-end pt-3 border-t border-base-800 shrink-0">
              <button
                type="button"
                onClick={() => setProvenanceModal(null)}
                className="btn-secondary text-xs px-4 py-1.5"
              >
                Close Provenance View
              </button>
            </div>
          </div>
        </div>
      )}

      {/* V7 Forensic Time-Travel Flight Recorder Modal */}
      {timeTravelModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4">
          <div className="bg-base-900 border border-purple-500/50 rounded-xl max-w-4xl w-full p-6 space-y-4 shadow-2xl animate-fade-in font-mono max-h-[90vh] flex flex-col">
            <div className="flex items-center justify-between border-b border-base-800 pb-3 shrink-0">
              <div>
                <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
                  <span className="text-purple-400">⏱️</span>
                  <span>Incident Time-Travel Forensic Player (v7.0)</span>
                </h3>
                <p className="text-xs text-slate-400 font-sans mt-0.5">
                  Deterministic endpoint state flight recorder. Scrub, rewind, and replay microsecond mutations to isolate Patient Zero.
                </p>
              </div>
              <div className="text-right">
                <span className="text-[10px] text-slate-500 block uppercase">Target Host</span>
                <span className="text-xs font-bold text-purple-300">{timeTravelModal.device_id}</span>
              </div>
            </div>

            {/* Time-Player Scrubbing Controls */}
            <div className="p-4 bg-base-950 border border-base-800 rounded-xl space-y-3 shrink-0">
              <div className="flex items-center justify-between text-xs">
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setCurrentFrameIdx(0)}
                    className="p-1.5 bg-base-900 hover:bg-base-800 text-slate-300 rounded border border-base-700 text-xs"
                    title="Rewind to start"
                  >
                    ⏮
                  </button>
                  <button
                    onClick={() => setCurrentFrameIdx((p) => Math.max(0, p - 1))}
                    className="p-1.5 bg-base-900 hover:bg-base-800 text-slate-300 rounded border border-base-700 text-xs"
                    title="Step Backward"
                  >
                    ◀
                  </button>
                  <button
                    onClick={() => setIsPlayingTimeline(!isPlayingTimeline)}
                    className={`px-3 py-1.5 rounded font-bold text-xs flex items-center gap-1 transition-all ${
                      isPlayingTimeline ? 'bg-amber-600 text-white' : 'bg-purple-600 hover:bg-purple-500 text-white'
                    }`}
                  >
                    <span>{isPlayingTimeline ? '⏸ Pause' : '▶ Play Replay'}</span>
                  </button>
                  <button
                    onClick={() => setCurrentFrameIdx((p) => Math.min((timeTravelModal.timeline_frames?.length || 1) - 1, p + 1))}
                    className="p-1.5 bg-base-900 hover:bg-base-800 text-slate-300 rounded border border-base-700 text-xs"
                    title="Step Forward"
                  >
                    ▶
                  </button>
                  <button
                    onClick={() => setCurrentFrameIdx((timeTravelModal.timeline_frames?.length || 1) - 1)}
                    className="p-1.5 bg-base-900 hover:bg-base-800 text-slate-300 rounded border border-base-700 text-xs"
                    title="Fast forward to latest"
                  >
                    ⏭
                  </button>
                </div>

                <div className="text-slate-400 text-xs">
                  Frame <strong>{currentFrameIdx + 1}</strong> of <strong>{timeTravelModal.timeline_frames?.length || 0}</strong> | 
                  Time: <strong className="text-cyan-300">{timeTravelModal.timeline_frames?.[currentFrameIdx]?.timestamp}</strong> ({timeTravelModal.timeline_frames?.[currentFrameIdx]?.relative_offset_sec}s)
                </div>
              </div>

              {/* Slider Scrubber */}
              <input
                type="range"
                min="0"
                max={(timeTravelModal.timeline_frames?.length || 1) - 1}
                value={currentFrameIdx}
                onChange={(e) => setCurrentFrameIdx(parseInt(e.target.value))}
                className="w-full h-2 bg-base-800 rounded-lg appearance-none cursor-pointer accent-purple-500"
              />
            </div>

            {/* Active Frame Inspection Deck */}
            <div className="flex-1 overflow-y-auto space-y-3">
              {(() => {
                const frame = timeTravelModal.timeline_frames?.[currentFrameIdx]
                if (!frame) return null
                const isPatientZero = frame.sequence_id === timeTravelModal.patient_zero_sequence_id

                return (
                  <div className={`p-4 rounded-xl border space-y-2 transition-all ${
                    isPatientZero
                      ? 'bg-rose-950/70 border-rose-500 text-rose-200 shadow-lg shadow-rose-950/50'
                      : frame.badge_color === 'amber'
                      ? 'bg-amber-950/50 border-amber-600 text-amber-200'
                      : 'bg-base-950 border-base-800 text-slate-300'
                  }`}>
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-bold px-2 py-0.5 rounded bg-base-900 border border-base-700">
                          {frame.mutation_type}
                        </span>
                        <span className="text-xs text-slate-400">{frame.timestamp}</span>
                      </div>

                      {isPatientZero && (
                        <span className="bg-rose-600 text-white font-extrabold text-[10px] px-2 py-0.5 rounded animate-pulse">
                          🚨 PATIENT ZERO COMPROMISE
                        </span>
                      )}
                    </div>

                    <div className="text-sm font-bold text-slate-100 font-mono break-all">
                      {frame.entity}
                    </div>

                    <p className="text-xs text-slate-300 font-sans">
                      {frame.details}
                    </p>

                    <div className="pt-2 border-t border-base-800/80 flex items-center justify-between text-[11px]">
                      <span>State Classification: <strong className="text-purple-300">{frame.state_risk}</strong></span>
                      <span className="text-slate-500">Offset: {frame.relative_offset_sec}s from alert trigger</span>
                    </div>
                  </div>
                )
              })()}

              {/* Sequential Tape Strip */}
              <div className="p-3 bg-base-950 border border-base-800 rounded-lg space-y-2">
                <div className="text-[10px] text-slate-400 uppercase font-bold">Chronological Flight Frames</div>
                <div className="grid grid-cols-1 md:grid-cols-5 gap-2">
                  {timeTravelModal.timeline_frames?.map((f, idx) => (
                    <button
                      key={f.sequence_id}
                      onClick={() => setCurrentFrameIdx(idx)}
                      className={`p-2 rounded border text-left text-[10px] space-y-1 transition-all ${
                        currentFrameIdx === idx
                          ? 'border-purple-500 bg-purple-950/60 text-purple-200 ring-1 ring-purple-500'
                          : f.sequence_id === timeTravelModal.patient_zero_sequence_id
                          ? 'border-rose-700 bg-rose-950/40 text-rose-300'
                          : 'border-base-800 bg-base-900 text-slate-400 hover:border-base-700'
                      }`}
                    >
                      <div className="font-bold flex justify-between">
                        <span>Frame #{f.sequence_id}</span>
                        <span>{f.timestamp}</span>
                      </div>
                      <div className="truncate text-slate-300">{f.mutation_type}</div>
                    </button>
                  ))}
                </div>
              </div>
            </div>

            <div className="flex justify-end pt-3 border-t border-base-800 shrink-0">
              <button
                type="button"
                onClick={() => { setTimeTravelModal(null); setIsPlayingTimeline(false); }}
                className="btn-secondary text-xs px-4 py-1.5"
              >
                Close Time-Travel Player
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}



