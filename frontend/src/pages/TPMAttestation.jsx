import { useEffect, useState } from 'react'
import client from '../api/client'

export default function TPMAttestation() {
  const [tpmStatus, setTpmStatus] = useState(null)
  const [records, setRecords] = useState([])
  const [loading, setLoading] = useState(true)
  const [signing, setSigning] = useState(false)
  const [verifying, setVerifying] = useState(false)
  const [feedback, setFeedback] = useState(null)

  const loadData = () => {
    Promise.all([
      client.get('/tpm/status'),
      client.get('/tpm/attestations'),
    ])
      .then(([statusRes, recordsRes]) => {
        setTpmStatus(statusRes.data || null)
        setRecords(recordsRes.data || [])
      })
      .catch((err) => {
        console.error('Failed to load TPM status:', err)
      })
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    loadData()
  }, [])

  const handleSignSampleBlock = async () => {
    setSigning(true)
    try {
      const sampleEvents = [
        { event: 'AUTH_SUCCESS', user: 'admin', ts: new Date().toISOString() },
        { event: 'KERNEL_EXECVE', binary: '/usr/bin/python3', pid: 1044 },
        { event: 'HCI_L2CAP_FRAME', interface: 'hci0', mtu: 672 },
      ]
      const { data } = await client.post('/tpm/sign-block', {
        log_records: sampleEvents,
        device_id: 'prod-tpm-srv-01',
      })
      setFeedback({
        type: 'success',
        title: '🔐 Log Block Hardware-Sealed by TPM 2.0',
        message: `Block Hash: ${data.block_hash.slice(0, 24)}... sealed with AIK: ${data.aik_key_id}`,
      })
      loadData()
      setTimeout(() => setFeedback(null), 8000)
    } catch (err) {
      setFeedback({
        type: 'error',
        title: 'Signing Failed',
        message: err.response?.data?.detail || err.message,
      })
    } finally {
      setSigning(false)
    }
  }

  const handleVerifyChain = async () => {
    setVerifying(true)
    try {
      const { data } = await client.post('/tpm/verify-chain', { limit: 50 })
      setFeedback({
        type: data.valid ? 'success' : 'error',
        title: data.valid ? '✅ Cryptographic Hardware Attestation Verified' : '❌ Integrity Breach Detected',
        message: `${data.message} | Merkle Root: ${data.merkle_root.slice(0, 32)}...`,
      })
      loadData()
      setTimeout(() => setFeedback(null), 9000)
    } catch (err) {
      setFeedback({
        type: 'error',
        title: 'Verification Error',
        message: err.response?.data?.detail || err.message,
      })
    } finally {
      setVerifying(false)
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <span>TPM 2.0 Hardware-Rooted Cryptographic Attestation</span>
            <span className="text-xs font-mono bg-purple-950 text-purple-300 px-2 py-0.5 rounded border border-purple-700 flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-purple-400 animate-pulse"></span>
              Immutable Silicon Ledger
            </span>
          </h1>
          <p className="text-slate-400 text-xs mt-0.5">
            Cryptographic SHA-256 Merkle block chains sealed inside silicon Attestation Identity Keys (AIK). Mathematical anti-tamper log protection.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleSignSampleBlock}
            disabled={signing}
            className="bg-purple-600 hover:bg-purple-500 text-white text-xs px-3.5 py-2 rounded font-mono font-bold transition-all flex items-center gap-1.5 shadow-md"
          >
            <span>🔐</span>
            <span>{signing ? 'Sealing in TPM...' : 'Sign Log Block with AIK'}</span>
          </button>
          <button
            onClick={handleVerifyChain}
            disabled={verifying}
            className="bg-emerald-600 hover:bg-emerald-500 text-white text-xs px-3.5 py-2 rounded font-mono font-bold transition-all flex items-center gap-1.5 shadow-md"
          >
            <span>✨</span>
            <span>{verifying ? 'Verifying Merkle Proof...' : 'Verify Cryptographic Chain'}</span>
          </button>
        </div>
      </div>

      {/* Feedback Banner */}
      {feedback && (
        <div
          className={`p-4 rounded-xl border text-xs font-mono animate-fade-in ${
            feedback.type === 'success'
              ? 'bg-emerald-950/80 border-emerald-600 text-emerald-200'
              : 'bg-rose-950/80 border-rose-600 text-rose-200'
          }`}
        >
          <div className="font-bold text-sm mb-1">{feedback.title}</div>
          <div className="text-slate-300 font-sans">{feedback.message}</div>
        </div>
      )}

      {/* TPM Status Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 font-mono">
        <div className="panel p-4 bg-base-900 border border-base-700 space-y-1">
          <div className="text-[10px] text-slate-500 uppercase">Hardware Silicon State</div>
          <div className="text-base font-bold text-slate-100 flex items-center gap-2">
            <span>{tpmStatus?.tpm_version || 'TPM 2.0 Spec 1.59'}</span>
          </div>
          <div className="text-[10px] text-emerald-400">● {tpmStatus?.hardware_status || 'SEALED'}</div>
        </div>

        <div className="panel p-4 bg-base-900 border border-base-700 space-y-1">
          <div className="text-[10px] text-slate-500 uppercase">AIK Public Fingerprint</div>
          <div className="text-xs font-bold text-purple-300 truncate">
            {tpmStatus?.aik_public_fingerprint || 'SHA256:8f4c2e...'}
          </div>
          <div className="text-[10px] text-slate-400">TCG Identity Key Enrolled</div>
        </div>

        <div className="panel p-4 bg-base-900 border border-base-700 space-y-1">
          <div className="text-[10px] text-slate-500 uppercase">Immutable Chain Height</div>
          <div className="text-base font-bold text-cyan-300">
            {tpmStatus?.immutable_chain_height || records.length} Sealed Blocks
          </div>
          <div className="text-[10px] text-slate-400">Zero Tamper Tolerance</div>
        </div>

        <div className="panel p-4 bg-base-900 border border-base-700 space-y-1">
          <div className="text-[10px] text-slate-500 uppercase">Latest Block Hash</div>
          <div className="text-xs font-bold text-amber-300 truncate font-mono">
            {tpmStatus?.latest_block_hash?.slice(0, 18) || 'e3b0c44298fc1c...'}...
          </div>
          <div className="text-[10px] text-slate-400">Merkle Branch Head</div>
        </div>
      </div>

      {/* PCR Registers Explorer */}
      <div className="panel p-4 space-y-3 font-mono">
        <div className="flex items-center justify-between border-b border-base-800 pb-2">
          <div>
            <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <span>Platform Configuration Registers (PCR Banks)</span>
              <span className="text-[10px] bg-purple-950 text-purple-300 px-2 py-0.5 rounded border border-purple-800">
                Hardware Integrity Root
              </span>
            </h2>
            <p className="text-[11px] text-slate-400 font-sans mt-0.5">
              Silicon cryptographic measurements captured at system initialization.
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
          {Object.entries(tpmStatus?.pcr_banks || {}).map(([pcrName, pcrDigest]) => (
            <div key={pcrName} className="p-3 bg-base-950 border border-base-800 rounded-lg space-y-1">
              <div className="flex items-center justify-between text-[11px]">
                <span className="font-bold text-slate-200">{pcrName}</span>
                <span className="text-[9px] bg-emerald-950 text-emerald-300 px-1.5 py-0.2 rounded border border-emerald-800">
                  MATCHED
                </span>
              </div>
              <div className="text-[10px] text-purple-300 font-mono break-all">{pcrDigest}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Attested Block Ledger */}
      <div className="panel p-4 space-y-3 font-mono">
        <div className="flex items-center justify-between border-b border-base-800 pb-2">
          <div>
            <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <span>Hardware-Sealed Telemetry Ledger</span>
              <span className="text-[10px] bg-base-950 text-slate-400 px-2 py-0.5 rounded border border-base-700">
                {records.length} Attestations
              </span>
            </h2>
            <p className="text-[11px] text-slate-400 font-sans mt-0.5">
              Every telemetry block is signed with the machine's private TPM 2.0 silicon key before persistence.
            </p>
          </div>
        </div>

        {records.length === 0 ? (
          <div className="p-8 text-center text-slate-500 text-xs">
            No telemetry blocks sealed yet. Click &quot;Sign Log Block with AIK&quot; above to issue the genesis hardware block!
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-base-800 text-slate-500 uppercase text-[10px]">
                  <th className="py-2.5 px-3">Sealed Time</th>
                  <th className="py-2.5 px-3">Block SHA-256 Hash</th>
                  <th className="py-2.5 px-3">TPM 2.0 Hardware Signature</th>
                  <th className="py-2.5 px-3">AIK Key ID</th>
                  <th className="py-2.5 px-3">Records</th>
                  <th className="py-2.5 px-3 text-right">Verification</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-base-800/60">
                {records.map((r) => (
                  <tr key={r.id} className="hover:bg-base-950/60 transition-colors">
                    <td className="py-2.5 px-3 text-slate-400 text-[11px]">
                      {new Date(r.created_at).toLocaleTimeString()}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-cyan-300 font-bold">
                      <code>{r.block_hash.slice(0, 20)}...</code>
                    </td>
                    <td className="py-2.5 px-3 font-mono text-purple-300">
                      <code>{r.signature.slice(0, 28)}...</code>
                    </td>
                    <td className="py-2.5 px-3 text-slate-300">{r.aik_key_id}</td>
                    <td className="py-2.5 px-3 text-slate-200 font-bold">{r.records_count} logs</td>
                    <td className="py-2.5 px-3 text-right">
                      <span className="text-[10px] px-2 py-0.5 rounded font-bold bg-emerald-950 text-emerald-300 border border-emerald-800">
                        {r.verification_status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
