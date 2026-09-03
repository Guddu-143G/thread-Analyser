import { useEffect, useState, useCallback } from 'react'
import client from '../api/client'

export default function Devices() {
  const [devices, setDevices] = useState([])
  const [name, setName] = useState('')
  const [platform, setPlatform] = useState('linux')
  const [newKey, setNewKey] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const load = useCallback(() => {
    setLoading(true)
    client.get('/devices').then(({ data }) => setDevices(data)).finally(() => setLoading(false))
  }, [])

  useEffect(() => {
    load()
  }, [load])

  const createDevice = async (e) => {
    e.preventDefault()
    setError('')
    try {
      const { data } = await client.post('/devices', { name, platform })
      setNewKey({ name: data.name, api_key: data.api_key, id: data.id })
      setName('')
      load()
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to create device')
    }
  }

  const rotateKey = async (id) => {
    const { data } = await client.post(`/devices/${id}/rotate-key`)
    setNewKey({ name: data.name, api_key: data.api_key, id: data.id })
    load()
  }

  const removeDevice = async (id) => {
    if (!confirm('Delete this device? Its logs and API key will stop working.')) return
    await client.delete(`/devices/${id}`)
    load()
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-slate-100">Devices</h1>
        <p className="text-slate-500 text-sm">Register endpoints that push logs via API key</p>
      </div>

      {newKey && (
        <div className="panel p-4 border-accent/40 bg-accent/5">
          <p className="text-sm text-slate-200 mb-2">
            API key for <span className="font-semibold">{newKey.name}</span> — copy it now, it won't be shown again:
          </p>
          <code className="block bg-base-950 border border-base-700 rounded-md px-3 py-2 text-accent text-sm break-all">
            {newKey.api_key}
          </code>
          <button onClick={() => setNewKey(null)} className="btn-secondary text-xs mt-2">Dismiss</button>
        </div>
      )}

      <form onSubmit={createDevice} className="panel p-4 flex gap-3 items-end flex-wrap">
        {error && <div className="w-full text-sm text-severity-critical">{error}</div>}
        <div className="flex-1 min-w-[180px]">
          <label className="block text-xs text-slate-400 mb-1">Device name</label>
          <input required className="input-field" value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. web-server-01" />
        </div>
        <div className="w-40">
          <label className="block text-xs text-slate-400 mb-1">Platform</label>
          <select className="input-field" value={platform} onChange={(e) => setPlatform(e.target.value)}>
            <option value="linux">Linux</option>
            <option value="windows">Windows</option>
            <option value="macos">macOS</option>
            <option value="network">Network device</option>
            <option value="cloud">Cloud/SaaS</option>
          </select>
        </div>
        <button type="submit" className="btn-primary">Register device</button>
      </form>

      <div className="panel divide-y divide-base-700">
        {loading && <div className="p-6 text-slate-500 text-sm">Loading…</div>}
        {!loading && devices.length === 0 && <div className="p-6 text-slate-500 text-sm">No devices registered yet.</div>}
        {devices.map((d) => (
          <div key={d.id} className="p-4 flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-slate-200">{d.name}</p>
              <p className="text-xs text-slate-500 font-mono">{d.platform} · last seen {d.last_seen ? new Date(d.last_seen).toLocaleString() : 'never'}</p>
            </div>
            <div className="flex gap-2">
              <button onClick={() => rotateKey(d.id)} className="btn-secondary text-xs px-3 py-1.5">Rotate key</button>
              <button onClick={() => removeDevice(d.id)} className="btn-secondary text-xs px-3 py-1.5 hover:bg-severity-critical/20 hover:border-severity-critical/40">Delete</button>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
