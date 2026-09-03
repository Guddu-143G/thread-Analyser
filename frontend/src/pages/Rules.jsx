import { useEffect, useState, useCallback } from 'react'
import client from '../api/client'
import SeverityBadge from '../components/SeverityBadge'

const EVENT_TYPE_PRESETS = [
  { label: 'Authentication Failure (Brute Force)', value: 'auth_failure', defaultGroup: 'src_ip', defaultThreshold: 5, defaultWindow: 300 },
  { label: 'Suspicious Process Creation', value: 'process_creation', defaultGroup: 'user', defaultThreshold: 3, defaultWindow: 120 },
  { label: 'High Egress Network Connection', value: 'network_connection', defaultGroup: 'src_ip', defaultThreshold: 10, defaultWindow: 60 },
  { label: 'Privilege Escalation (Sudo / Admin)', value: 'privilege_escalation', defaultGroup: 'user', defaultThreshold: 3, defaultWindow: 300 },
  { label: 'Custom / Generic Event', value: 'custom', defaultGroup: 'src_ip', defaultThreshold: 5, defaultWindow: 300 },
]

export default function Rules() {
  const [rules, setRules] = useState([])
  const [loading, setLoading] = useState(true)
  const [showForm, setShowForm] = useState(false)
  const [mode, setMode] = useState('visual') // 'visual' or 'advanced'

  // Form fields
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [severity, setSeverity] = useState('medium')
  
  // Visual Builder fields
  const [selectedEventType, setSelectedEventType] = useState('auth_failure')
  const [groupBy, setGroupBy] = useState('src_ip')
  const [thresholdCount, setThresholdCount] = useState(5)
  const [windowSeconds, setWindowSeconds] = useState(300)
  
  // Advanced Editor field
  const [rawDefinition, setRawDefinition] = useState('{\n  "type": "threshold",\n  "conditions": [{"field": "event_type", "op": "eq", "value": "auth_failure"}],\n  "group_by": "src_ip",\n  "count": 5,\n  "window_seconds": 300\n}')
  const [error, setError] = useState('')

  const loadRules = useCallback(() => {
    setLoading(true)
    client.get('/rules').then(({ data }) => setRules(data)).finally(() => setLoading(false))
  }, [])

  useEffect(() => {
    loadRules()
  }, [loadRules])

  const handleEventTypeChange = (eType) => {
    setSelectedEventType(eType)
    const preset = EVENT_TYPE_PRESETS.find((p) => p.value === eType)
    if (preset) {
      setGroupBy(preset.defaultGroup)
      setThresholdCount(preset.defaultThreshold)
      setWindowSeconds(preset.defaultWindow)
    }
  }

  // Compute live JSON generated from visual builder
  const generatedVisualDefinition = {
    type: 'threshold',
    conditions: [
      {
        field: 'event_type',
        op: 'eq',
        value: selectedEventType,
      },
    ],
    group_by: groupBy,
    count: Number(thresholdCount),
    window_seconds: Number(windowSeconds),
  }

  const submit = async (e) => {
    e.preventDefault()
    setError('')
    let finalDef
    if (mode === 'visual') {
      finalDef = generatedVisualDefinition
    } else {
      try {
        finalDef = JSON.parse(rawDefinition)
      } catch {
        setError('Rule definition must be valid JSON')
        return
      }
    }

    try {
      await client.post('/rules', {
        name,
        description,
        severity,
        definition: finalDef,
        enabled: true,
      })
      setName('')
      setDescription('')
      setShowForm(false)
      loadRules()
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to create rule')
    }
  }

  const toggleEnabled = async (rule) => {
    try {
      await client.put(`/rules/${rule.id}`, { enabled: !rule.enabled })
      loadRules()
    } catch {
      alert('Global/Built-in rules cannot be modified.')
    }
  }

  const removeRule = async (id) => {
    if (!confirm('Delete this detection rule?')) return
    try {
      await client.delete(`/rules/${id}`)
      loadRules()
    } catch {
      alert('Global built-in rules cannot be deleted.')
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <span>Detection Rule Engine</span>
            <span className="text-xs font-mono bg-base-800 text-slate-300 px-2 py-0.5 rounded border border-base-700">
              Sigma &amp; Threshold
            </span>
          </h1>
          <p className="text-slate-400 text-xs mt-0.5">Author low-code threshold rules, sliding-window frequency logic, and Sigma detection rules</p>
        </div>
        <button
          onClick={() => setShowForm(!showForm)}
          className="btn-primary text-xs px-4 py-2 flex items-center gap-1.5"
        >
          {showForm ? '✕ Close Builder' : '+ New Detection Rule'}
        </button>
      </div>

      {/* Visual / Advanced Rule Builder Modal/Panel */}
      {showForm && (
        <form onSubmit={submit} className="bg-base-900 border border-base-700 rounded-lg p-5 space-y-4 shadow-xl">
          <div className="flex items-center justify-between border-b border-base-800 pb-3">
            <h2 className="text-sm font-bold text-slate-100 uppercase tracking-wider flex items-center gap-2">
              <span>⚙ Detection Rule Authoring Studio</span>
            </h2>
            <div className="flex items-center gap-1 bg-base-950 p-1 rounded border border-base-700 text-xs font-mono">
              <button
                type="button"
                onClick={() => setMode('visual')}
                className={`px-3 py-1 rounded transition-colors ${
                  mode === 'visual' ? 'bg-accent text-base-950 font-bold' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Visual Builder
              </button>
              <button
                type="button"
                onClick={() => setMode('advanced')}
                className={`px-3 py-1 rounded transition-colors ${
                  mode === 'advanced' ? 'bg-accent text-base-950 font-bold' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Advanced JSON / Sigma
              </button>
            </div>
          </div>

          {error && <div className="p-3 bg-rose-950/80 border border-rose-800 text-rose-300 text-xs rounded">{error}</div>}

          {/* Rule Metadata */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div className="md:col-span-2">
              <label className="text-[11px] font-mono uppercase text-slate-400 block mb-1">Rule Name</label>
              <input
                required
                className="input-field text-xs"
                placeholder="e.g. SSH Brute Force Multi-Account Failure"
                value={name}
                onChange={(e) => setName(e.target.value)}
              />
            </div>
            <div>
              <label className="text-[11px] font-mono uppercase text-slate-400 block mb-1">Severity</label>
              <select
                className="input-field text-xs uppercase"
                value={severity}
                onChange={(e) => setSeverity(e.target.value)}
              >
                {['low', 'medium', 'high', 'critical'].map((s) => (
                  <option key={s} value={s}>{s}</option>
                ))}
              </select>
            </div>
          </div>

          <div>
            <label className="text-[11px] font-mono uppercase text-slate-400 block mb-1">Description</label>
            <input
              className="input-field text-xs"
              placeholder="e.g. Triggers an incident when more than 5 authentication failures occur within 5 minutes from the same IP"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
            />
          </div>

          {/* Visual Step-by-Step Builder */}
          {mode === 'visual' ? (
            <div className="space-y-3 pt-2">
              <div className="grid grid-cols-1 md:grid-cols-4 gap-3 bg-base-950 p-4 rounded-lg border border-base-800 text-xs">
                {/* Step 1 */}
                <div>
                  <span className="text-[10px] font-mono uppercase text-accent font-bold block mb-1">Step 1: Event Type</span>
                  <select
                    className="input-field text-xs"
                    value={selectedEventType}
                    onChange={(e) => handleEventTypeChange(e.target.value)}
                  >
                    {EVENT_TYPE_PRESETS.map((p) => (
                      <option key={p.value} value={p.value}>{p.label}</option>
                    ))}
                  </select>
                </div>

                {/* Step 2 */}
                <div>
                  <span className="text-[10px] font-mono uppercase text-accent font-bold block mb-1">Step 2: Group By Key</span>
                  <select
                    className="input-field text-xs font-mono"
                    value={groupBy}
                    onChange={(e) => setGroupBy(e.target.value)}
                  >
                    <option value="src_ip">src_ip (Source IP)</option>
                    <option value="user">user (Account Name)</option>
                    <option value="device_id">device_id (Host Sensor)</option>
                    <option value="process">process (Process / Binary)</option>
                  </select>
                </div>

                {/* Step 3 */}
                <div>
                  <span className="text-[10px] font-mono uppercase text-accent font-bold block mb-1">Step 3: Threshold Count</span>
                  <input
                    type="number"
                    min={1}
                    className="input-field text-xs font-mono"
                    value={thresholdCount}
                    onChange={(e) => setThresholdCount(e.target.value)}
                  />
                </div>

                {/* Step 4 */}
                <div>
                  <span className="text-[10px] font-mono uppercase text-accent font-bold block mb-1">Step 4: Lookback Window (Sec)</span>
                  <select
                    className="input-field text-xs font-mono"
                    value={windowSeconds}
                    onChange={(e) => setWindowSeconds(e.target.value)}
                  >
                    <option value={60}>60s (1 minute)</option>
                    <option value={300}>300s (5 minutes)</option>
                    <option value={900}>900s (15 minutes)</option>
                    <option value={3600}>3600s (1 hour)</option>
                  </select>
                </div>
              </div>

              {/* Generated Logic Preview */}
              <div>
                <span className="text-[11px] font-mono uppercase text-slate-400 block mb-1">Generated Rule Definition (Live Preview)</span>
                <pre className="bg-base-950 border border-base-800 rounded p-3 text-xs text-emerald-400 font-mono">
                  {JSON.stringify(generatedVisualDefinition, null, 2)}
                </pre>
              </div>
            </div>
          ) : (
            <div>
              <label className="block text-[11px] font-mono uppercase text-slate-400 mb-1">Rule Definition (JSON / Sigma AST)</label>
              <textarea
                className="input-field font-mono text-xs h-48"
                value={rawDefinition}
                onChange={(e) => setRawDefinition(e.target.value)}
                spellCheck={false}
              />
            </div>
          )}

          <div className="flex justify-end gap-2 pt-2 border-t border-base-800">
            <button
              type="button"
              onClick={() => setShowForm(false)}
              className="btn-secondary text-xs px-4 py-2"
            >
              Cancel
            </button>
            <button type="submit" className="btn-primary text-xs px-5 py-2">
              Save Detection Rule
            </button>
          </div>
        </form>
      )}

      {/* Rules List Grid */}
      <div className="panel divide-y divide-base-700">
        {loading && <div className="p-8 text-center text-slate-500 text-sm">Loading detection rules…</div>}
        {!loading && rules.length === 0 && (
          <div className="p-8 text-center text-slate-500 text-sm">No detection rules created yet.</div>
        )}
        {rules.map((r) => (
          <div key={r.id} className="p-4 transition-colors hover:bg-base-800/40">
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2 mb-1">
                  <SeverityBadge severity={r.severity} />
                  <span className="text-sm font-bold text-slate-200">{r.name}</span>
                  {!r.enabled && (
                    <span className="text-[10px] font-mono uppercase bg-rose-950 text-rose-400 px-1.5 py-0.5 rounded border border-rose-800">
                      Disabled
                    </span>
                  )}
                  {r.id.startsWith('global-') && (
                    <span className="text-[10px] font-mono uppercase bg-base-950 text-accent px-1.5 py-0.5 rounded border border-base-700">
                      Built-in Global
                    </span>
                  )}
                </div>

                {r.description && <p className="text-xs text-slate-400 mt-0.5">{r.description}</p>}

                <div className="flex flex-wrap items-center gap-4 mt-2 text-[11px] font-mono text-slate-500">
                  <span>Type: <strong className="text-slate-300">{r.definition?.type || 'threshold'}</strong></span>
                  {r.definition?.group_by && <span>Group: <strong className="text-cyan-400">{r.definition.group_by}</strong></span>}
                  {r.definition?.count && <span>Count: <strong className="text-amber-300">{r.definition.count}</strong></span>}
                  {r.definition?.window_seconds && <span>Window: <strong className="text-slate-300">{r.definition.window_seconds}s</strong></span>}
                </div>
              </div>

              <div className="flex items-center gap-2 shrink-0">
                <button
                  onClick={() => toggleEnabled(r)}
                  className="btn-secondary text-xs px-3 py-1.5 font-mono"
                >
                  {r.enabled ? 'Disable' : 'Enable'}
                </button>
                <button
                  onClick={() => removeRule(r.id)}
                  className="btn-secondary text-xs px-3 py-1.5 text-rose-400 hover:bg-rose-950/60 font-mono"
                >
                  Delete
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
