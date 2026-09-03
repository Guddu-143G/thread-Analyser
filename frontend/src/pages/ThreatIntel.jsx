import { useEffect, useState, useCallback, useRef } from 'react'
import client from '../api/client'
import SeverityBadge from '../components/SeverityBadge'

export default function ThreatIntel() {
  const [iocs, setIocs] = useState([])
  const [loading, setLoading] = useState(true)
  const [form, setForm] = useState({ type: 'ip', value: '', severity: 'medium', description: '' })
  const [error, setError] = useState('')
  const [importMsg, setImportMsg] = useState('')
  const fileRef = useRef(null)

  const load = useCallback(() => {
    setLoading(true)
    client.get('/ioc').then(({ data }) => setIocs(data)).finally(() => setLoading(false))
  }, [])

  useEffect(() => {
    load()
  }, [load])

  const submit = async (e) => {
    e.preventDefault()
    setError('')
    try {
      await client.post('/ioc', form)
      setForm({ type: 'ip', value: '', severity: 'medium', description: '' })
      load()
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to add indicator')
    }
  }

  const handleImport = async (e) => {
    const file = e.target.files[0]
    if (!file) return
    const fd = new FormData()
    fd.append('file', file)
    try {
      const { data } = await client.post('/ioc/import-csv', fd, { headers: { 'Content-Type': 'multipart/form-data' } })
      setImportMsg(`Imported ${data.imported} indicators.`)
      load()
    } catch (err) {
      setImportMsg(err.response?.data?.detail || 'Import failed')
    } finally {
      if (fileRef.current) fileRef.current.value = ''
    }
  }

  const remove = async (id) => {
    await client.delete(`/ioc/${id}`)
    load()
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-slate-100">Threat Intel</h1>
        <p className="text-slate-500 text-sm">Indicators of compromise (IOCs) checked against every ingested event</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <form onSubmit={submit} className="panel p-4 space-y-3">
          <h2 className="text-sm font-medium text-slate-300">Add indicator manually</h2>
          {error && <div className="text-sm text-severity-critical">{error}</div>}
          <div className="grid grid-cols-2 gap-3">
            <select className="input-field" value={form.type} onChange={(e) => setForm({ ...form, type: e.target.value })}>
              <option value="ip">IP address</option>
              <option value="domain">Domain</option>
              <option value="hash">File hash</option>
              <option value="process">Process name</option>
            </select>
            <select className="input-field" value={form.severity} onChange={(e) => setForm({ ...form, severity: e.target.value })}>
              {['low', 'medium', 'high', 'critical'].map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
          </div>
          <input required className="input-field" placeholder="Value (e.g. 1.2.3.4)" value={form.value} onChange={(e) => setForm({ ...form, value: e.target.value })} />
          <input className="input-field" placeholder="Description (optional)" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
          <button type="submit" className="btn-primary">Add indicator</button>
        </form>

        <div className="panel p-4 space-y-3">
          <h2 className="text-sm font-medium text-slate-300">Bulk import via CSV</h2>
          <p className="text-xs text-slate-500">Columns required: <code className="text-accent">type,value</code>. Optional: <code className="text-accent">severity,description</code>.</p>
          <input ref={fileRef} type="file" accept=".csv" onChange={handleImport} className="text-sm text-slate-400 file:btn-secondary file:mr-3 file:border-0 file:cursor-pointer" />
          {importMsg && <p className="text-xs text-accent">{importMsg}</p>}
        </div>
      </div>

      <div className="panel divide-y divide-base-700">
        {loading && <div className="p-6 text-slate-500 text-sm">Loading…</div>}
        {!loading && iocs.length === 0 && <div className="p-6 text-slate-500 text-sm">No indicators yet.</div>}
        {iocs.map((i) => (
          <div key={i.id} className="p-3 flex items-center justify-between gap-3">
            <div className="flex items-center gap-3 min-w-0">
              <SeverityBadge severity={i.severity} />
              <span className="text-xs text-slate-500 uppercase w-16 shrink-0">{i.type}</span>
              <span className="font-mono text-sm text-slate-200 truncate">{i.value}</span>
              <span className="text-xs text-slate-600 shrink-0">{i.source}</span>
            </div>
            <button onClick={() => remove(i.id)} className="text-xs text-slate-500 hover:text-severity-critical shrink-0">Remove</button>
          </div>
        ))}
      </div>
    </div>
  )
}
