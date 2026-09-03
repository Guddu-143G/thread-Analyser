import { useEffect, useState, useCallback, useRef } from 'react'
import client from '../api/client'

const SAMPLE_LOGS = `Aug 28 10:15:30 server sshd[1122]: Failed password for invalid user admin from 203.0.113.9 port 22 ssh2
Aug 28 10:15:32 server sshd[1122]: Failed password for invalid user admin from 203.0.113.9 port 22 ssh2
Aug 28 10:15:34 server sshd[1122]: Failed password for invalid user admin from 203.0.113.9 port 22 ssh2
Aug 28 10:15:36 server sshd[1122]: Failed password for invalid user admin from 203.0.113.9 port 22 ssh2
Aug 28 10:15:38 server sshd[1122]: Failed password for invalid user admin from 203.0.113.9 port 22 ssh2
{"event_type":"auth_success","src_ip":"192.168.1.10","user":"jane"}
process=mimikatz.exe user=attacker action=credential_dump
powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA
`

export default function LogUpload() {
  const [devices, setDevices] = useState([])
  const [deviceId, setDeviceId] = useState('')
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const [uploading, setUploading] = useState(false)
  const fileRef = useRef(null)

  useEffect(() => {
    client.get('/devices').then(({ data }) => setDevices(data))
  }, [])

  const doUpload = async (blob, filename) => {
    setError('')
    setResult(null)
    setUploading(true)
    const fd = new FormData()
    fd.append('file', blob, filename)
    try {
      const params = deviceId ? { device_id: deviceId } : {}
      const { data } = await client.post('/ingest/upload', fd, {
        params,
        headers: { 'Content-Type': 'multipart/form-data' },
      })
      setResult(data)
    } catch (err) {
      setError(err.response?.data?.detail || 'Upload failed')
    } finally {
      setUploading(false)
    }
  }

  const handleFileChange = (e) => {
    const file = e.target.files[0]
    if (file) doUpload(file, file.name)
  }

  const runSampleDemo = () => {
    const blob = new Blob([SAMPLE_LOGS], { type: 'text/plain' })
    doUpload(blob, 'sample-logs.txt')
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-slate-100">Log Upload</h1>
        <p className="text-slate-500 text-sm">Upload logs for asynchronous parsing, IOC matching, and rule evaluation</p>
      </div>

      <div className="panel p-4 space-y-4">
        <div>
          <label className="block text-xs text-slate-400 mb-1">Attribute to device (optional)</label>
          <select className="input-field" value={deviceId} onChange={(e) => setDeviceId(e.target.value)}>
            <option value="">No specific device</option>
            {devices.map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}
          </select>
        </div>

        <div>
          <label className="block text-xs text-slate-400 mb-1">Log file (.txt, .log, .json — max 10MB)</label>
          <input ref={fileRef} type="file" onChange={handleFileChange} disabled={uploading}
            className="text-sm text-slate-400 file:btn-secondary file:mr-3 file:border-0 file:cursor-pointer" />
        </div>

        <div className="border-t border-base-700 pt-4">
          <p className="text-xs text-slate-500 mb-2">Or try it instantly with a bundled sample log (SSH brute force + credential dumping + encoded PowerShell):</p>
          <button onClick={runSampleDemo} disabled={uploading} className="btn-secondary">
            {uploading ? 'Processing…' : 'Run sample log demo'}
          </button>
        </div>

        {error && <div className="text-sm text-severity-critical">{error}</div>}
        {result && (
          <div className="text-sm text-accent bg-accent/10 border border-accent/30 rounded-md px-3 py-2">
            Accepted {result.accepted_events} log lines — queued for async processing. Check the Alerts and Dashboard pages in a few seconds.
          </div>
        )}
      </div>
    </div>
  )
}
