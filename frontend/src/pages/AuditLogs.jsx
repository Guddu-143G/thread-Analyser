import React, { useEffect, useState, useCallback } from 'react'
import client from '../api/client'


export default function AuditLogs() {
  const [logs, setLogs] = useState([])
  const [loading, setLoading] = useState(true)
  const [actionFilter, setActionFilter] = useState('')
  const [expandedLogId, setExpandedLogId] = useState(null)
  const [verifying, setVerifying] = useState(false)
  const [verifyResult, setVerifyResult] = useState(null)
  const [zkModal, setZkModal] = useState(false)
  const [zkGenerating, setZkGenerating] = useState(false)
  const [zkProofBundle, setZkProofBundle] = useState(null)
  const [zkVerifying, setZkVerifying] = useState(false)
  const [zkVerifyResult, setZkVerifyResult] = useState(null)
  const [slaMinutes, setSlaMinutes] = useState(15)

  // V5 Searchable Symmetric Encryption (SSE) State
  const [sseQuery, setSseQuery] = useState('')
  const [sseLoading, setSseLoading] = useState(false)
  const [sseResult, setSseResult] = useState(null)

  // V6 SBOM & Binary Drift State
  const [sbomList, setSbomList] = useState([])
  const [sbomLoading, setSbomLoading] = useState(false)
  const [sbomFeedback, setSbomFeedback] = useState(null)
  const [driftResult, setDriftResult] = useState(null)

  // V7 Decentralized zk-SMPC Threat Exchange State
  const [zkThreats, setZkThreats] = useState([])
  const [zkExchangeFeedback, setZkExchangeFeedback] = useState(null)
  const [zkExchangeLoading, setZkExchangeLoading] = useState(false)

  const loadSBOMAndExchange = () => {
    client.get('/sbom').then(({ data }) => setSbomList(data.components || [])).catch(() => {})
    client.get('/exchange/certified-threats').then(({ data }) => setZkThreats(data.certified_threats || [])).catch(() => {})
  }

  const loadAuditLogs = useCallback(() => {
    setLoading(true)
    const params = { limit: 100 }
    if (actionFilter) params.action = actionFilter

    client
      .get('/audit-logs', { params })
      .then(({ data }) => setLogs(data))
      .finally(() => setLoading(false))

    loadSBOMAndExchange()
  }, [actionFilter])

  const handleProveIOC = async (iocValue) => {
    setZkExchangeLoading(true)
    try {
      const { data } = await client.post('/exchange/prove-ioc', {
        ioc_value: iocValue,
        confidence_score: 0.98
      })
      setZkExchangeFeedback(data)
      setTimeout(() => setZkExchangeFeedback(null), 8000)
    } catch (err) {
      alert('zk-SMPC Prove failed: ' + (err.response?.data?.detail || err.message))
    } finally {
      setZkExchangeLoading(false)
    }
  }


  const handleUploadSampleSBOM = async () => {
    setSbomLoading(true)
    try {
      const samplePayload = {
        bom_format: "CycloneDX",
        spec_version: "1.5",
        components: [
          { name: "openssl-crypto-lib", version: "3.1.2", sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", license: "Apache-2.0" },
          { name: "nginx-core-binary", version: "1.27.0", sha256: "8a2f4c91e0d3b6745129a8fbc34107898a2f4c91e0d3b6745129a8fbc3410789", license: "BSD-2-Clause" },
          { name: "postgres-driver", version: "42.6.0", sha256: "1f55fed36afb52af3987b65af43c69c232e428bd1f926849b55e64ae3369350d", license: "PostgreSQL" }
        ]
      }
      const { data } = await client.post('/sbom/upload', samplePayload)
      setSbomFeedback(data.message)
      loadSBOM()
      setTimeout(() => setSbomFeedback(null), 6000)
    } catch (err) {
      alert('SBOM upload failed: ' + (err.response?.data?.detail || err.message))
    } finally {
      setSbomLoading(false)
    }
  }

  const handleVerifyBinaryDrift = async (processName, binaryHash) => {
    try {
      const { data } = await client.post('/sbom/verify', {
        process_name: processName,
        binary_hash: binaryHash
      })
      setDriftResult(data)
      setTimeout(() => setDriftResult(null), 8000)
    } catch (err) {
      alert('Verification failed: ' + (err.response?.data?.detail || err.message))
    }
  }

  const runChainVerification = () => {
    setVerifying(true)
    client
      .get('/audit-logs/verify')
      .then(({ data }) => {
        setVerifyResult(data)
      })
      .catch((err) => {
        setVerifyResult({
          valid: false,
          message: err.response?.data?.detail || 'Verification request failed.',
        })
      })
      .finally(() => setVerifying(false))
  }

  const handleGenerateZKProof = async () => {
    setZkGenerating(true)
    setZkVerifyResult(null)
    try {
      const { data } = await client.post(`/compliance/zkp/generate?sla_minutes=${slaMinutes}`)
      setZkProofBundle(data)
    } catch (err) {
      alert('ZKP Generation failed: ' + (err.response?.data?.detail || err.message))
    } finally {
      setZkGenerating(false)
    }
  }

  const handleVerifyZKProof = async () => {
    if (!zkProofBundle) return
    setZkVerifying(true)
    try {
      const { data } = await client.post('/compliance/zkp/verify', { proof_bundle: zkProofBundle })
      setZkVerifyResult(data)
    } catch (err) {
      alert('ZKP Verification failed: ' + (err.response?.data?.detail || err.message))
    } finally {
      setZkVerifying(false)
    }
  }

  useEffect(() => {
    loadAuditLogs()
  }, [loadAuditLogs])

  const handleSearchSSE = async (e) => {
    e.preventDefault()
    if (!sseQuery.trim()) return
    setSseLoading(true)
    try {
      const { data } = await client.post('/archive/search', { query: sseQuery })
      setSseResult(data)
    } catch (err) {
      alert('SSE Search failed: ' + (err.response?.data?.detail || err.message))
    } finally {
      setSseLoading(false)
    }
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <span>Cryptographically Sealed Audit Ledger</span>
            <span className="text-xs font-mono bg-emerald-950/80 text-emerald-400 px-2 py-0.5 rounded border border-emerald-800 flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
              Merkle Hash-Chain &amp; zk-SNARKs
            </span>
          </h1>
          <p className="text-slate-400 text-xs mt-0.5">
            Tamper-evident append-only ledger with zero-knowledge mathematical compliance attestations.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => { setZkModal(true); if (!zkProofBundle) handleGenerateZKProof(); }}
            className="bg-gradient-to-r from-indigo-900/60 to-purple-900/60 text-purple-200 border border-purple-500/50 hover:border-purple-400 text-xs px-3 py-1.5 rounded font-mono font-bold flex items-center gap-1.5"
          >
            <span>🛡</span>
            <span>Zero-Knowledge SLA Attestation</span>
          </button>
          <button
            onClick={runChainVerification}
            disabled={verifying}
            className="btn-primary text-xs px-3 py-1.5 font-mono flex items-center gap-1.5"
          >
            {verifying ? 'Verifying Hashes...' : '🔒 Verify Chain Integrity'}
          </button>
          <button onClick={loadAuditLogs} className="btn-secondary text-xs px-3 py-1.5 font-mono">
            ⟳ Refresh Trail
          </button>
        </div>
      </div>

      {/* V5 Searchable Symmetric Encryption (SSE) Console */}
      <div className="panel p-4 space-y-3 font-mono">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-2 border-b border-base-800 pb-3">
          <div>
            <div className="flex items-center gap-2">
              <span className="text-cyan-400 text-base">🔍</span>
              <h2 className="text-sm font-bold text-slate-100">Cryptographic Searchable Archives (SSE)</h2>
              <span className="text-[10px] bg-cyan-950 text-cyan-300 border border-cyan-800 px-2 py-0.5 rounded font-bold">
                Zero-Bulk-Decryption S3 Cold Storage
              </span>
            </div>
            <p className="text-[11px] text-slate-400 font-sans mt-0.5">
              Query encrypted cold log archives (S3 / Parquet) using deterministic HMAC tokens without decrypting bulk files.
            </p>
          </div>
        </div>

        <form onSubmit={handleSearchSSE} className="flex gap-2">
          <input
            className="input-field text-xs py-1.5 flex-1 font-mono"
            placeholder="Search encrypted cold archives for IOC, IP, or command (e.g. 185.220.101.5, powershell, sshd)..."
            value={sseQuery}
            onChange={(e) => setSseQuery(e.target.value)}
          />
          <button
            type="submit"
            disabled={sseLoading}
            className="bg-cyan-600 hover:bg-cyan-500 text-white text-xs px-4 py-1.5 rounded font-bold transition-colors flex items-center gap-1"
          >
            <span>{sseLoading ? 'Tokenizing...' : '⚡ Search Encrypted Index'}</span>
          </button>
        </form>

        {sseResult && (
          <div className="p-3 bg-base-950 border border-base-800 rounded-lg text-xs space-y-2 animate-fade-in font-mono">
            <div className="flex items-center justify-between border-b border-base-800 pb-2">
              <div className="flex items-center gap-2">
                <span className="text-cyan-300 font-bold">Query: "{sseResult.query_term}"</span>
                <span className="text-[10px] bg-base-900 text-slate-400 px-2 py-0.5 rounded border border-base-700">
                  Search Token: {sseResult.deterministic_token}
                </span>
              </div>
              <span className="text-emerald-400 font-bold">
                {sseResult.matched_indices_count} Matching Records (Decrypted on-the-fly)
              </span>
            </div>

            {sseResult.matched_records?.length > 0 ? (
              <div className="space-y-1.5">
                {sseResult.matched_records.map((rec) => (
                  <div key={rec.line_index} className="p-2 bg-base-900 border border-base-800 rounded text-[11px] text-slate-200 flex items-start gap-2">
                    <span className="text-slate-500 text-[10px] shrink-0 font-bold">Line #{rec.line_index}:</span>
                    <span className="text-emerald-300 break-all">{rec.content}</span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-slate-500 text-center py-2">No matching records found in encrypted archive index.</div>
            )}
          </div>
        )}
      </div>

      {/* V6 CycloneDX SBOM Supply Chain Registry & Runtime Binary Attestor */}
      <div className="panel p-4 space-y-3 font-mono">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-2 border-b border-base-800 pb-3">
          <div>
            <div className="flex items-center gap-2">
              <span className="text-purple-400 text-base">📦</span>
              <h2 className="text-sm font-bold text-slate-100">SBOM Supply Chain Registry &amp; Binary Drift Attestor (v6.0)</h2>
              <span className="text-[10px] bg-purple-950 text-purple-300 border border-purple-800 px-2 py-0.5 rounded font-bold">
                CycloneDX / SPDX Standard
              </span>
            </div>
            <p className="text-[11px] text-slate-400 font-sans mt-0.5">
              Cross-references in-kernel eBPF executing process hashes against authorized SBOM signatures to detect supply-chain backdoors.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleUploadSampleSBOM}
              disabled={sbomLoading}
              className="bg-purple-900/60 hover:bg-purple-800/60 text-purple-200 border border-purple-600/60 text-xs px-3 py-1.5 rounded font-bold transition-all flex items-center gap-1"
            >
              <span>+ Ingest CycloneDX SBOM</span>
            </button>
            <button
              onClick={() => handleVerifyBinaryDrift("unauthorized_miner.exe", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")}
              className="bg-rose-950 hover:bg-rose-900/80 text-rose-300 border border-rose-700/60 text-xs px-3 py-1.5 rounded font-bold transition-all flex items-center gap-1"
            >
              <span>⚡ Test Supply Chain Drift</span>
            </button>
          </div>
        </div>

        {sbomFeedback && (
          <div className="p-3 rounded-lg border text-xs bg-purple-950/60 border-purple-600 text-purple-200 animate-fade-in font-sans">
            ✅ {sbomFeedback}
          </div>
        )}

        {driftResult && (
          <div className={`p-3 rounded-lg border text-xs animate-fade-in font-sans ${
            driftResult.status === 'UNAUTHORIZED_BINARY_DRIFT'
              ? 'bg-rose-950/80 border-rose-600 text-rose-200'
              : 'bg-emerald-950/60 border-emerald-600 text-emerald-200'
          }`}>
            <div className="flex items-center justify-between font-mono font-bold">
              <span>{driftResult.status === 'UNAUTHORIZED_BINARY_DRIFT' ? '❌ UNAUTHORIZED BINARY DRIFT DETECTED' : '✅ BINARY ATTESTED VALID'}</span>
              <span className="text-[10px] bg-rose-900 px-2 py-0.5 rounded text-white">{driftResult.severity || 'OK'}</span>
            </div>
            <div className="mt-1 text-[11px] font-sans">{driftResult.description}</div>
            {driftResult.remediation && (
              <div className="mt-1 font-mono text-[10px] text-amber-300">Action: {driftResult.remediation}</div>
            )}
          </div>
        )}

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-base-950/80 border-b border-base-800 text-slate-400 text-[10px] uppercase">
              <tr>
                <th className="py-2 px-3">Component Name</th>
                <th className="py-2 px-3">Version</th>
                <th className="py-2 px-3">License</th>
                <th className="py-2 px-3">Authorized SHA-256 Signature</th>
                <th className="py-2 px-3 text-right">Attestation Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-base-800/60 text-slate-300">
              {sbomList.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-4 text-center text-slate-500 font-sans">
                    No SBOM components uploaded yet. Click "+ Ingest CycloneDX SBOM" above to seed supply chain signatures.
                  </td>
                </tr>
              ) : (
                sbomList.map((c) => (
                  <tr key={c.id || c.sha256_hash} className="hover:bg-base-800/40">
                    <td className="py-2 px-3 font-bold text-slate-100">{c.name}</td>
                    <td className="py-2 px-3 text-slate-400">{c.version}</td>
                    <td className="py-2 px-3 text-slate-400">{c.license_type || 'Apache-2.0'}</td>
                    <td className="py-2 px-3">
                      <code className="text-cyan-300 text-[10px]">{c.sha256_hash?.slice(0, 24)}...</code>
                    </td>
                    <td className="py-2 px-3 text-right">
                      <span className="text-[10px] bg-emerald-950 text-emerald-300 border border-emerald-800 px-2 py-0.5 rounded font-bold">
                        WHITELISTED
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* V7 Decentralized Zero-Trust Threat Exchange (zk-SMPC) */}
      <div className="panel p-4 space-y-3 font-mono">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-2 border-b border-base-800 pb-3">
          <div>
            <div className="flex items-center gap-2">
              <span className="text-cyan-400 text-base">🌐</span>
              <h2 className="text-sm font-bold text-slate-100">Decentralized Threat Intelligence Exchange: zk-SMPC (v7.0)</h2>
              <span className="text-[10px] bg-cyan-950 text-cyan-300 border border-cyan-800 px-2 py-0.5 rounded font-bold">
                Zero-Knowledge SMPC Mesh
              </span>
            </div>
            <p className="text-[11px] text-slate-400 font-sans mt-0.5">
              Certify and correlate indicators of compromise (IOCs) collaboratively across enterprise tenant nodes with zero disclosure of internal hostnames or IP databases.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => handleProveIOC('185.220.101.5')}
              disabled={zkExchangeLoading}
              className="bg-cyan-900/60 hover:bg-cyan-800/60 text-cyan-200 border border-cyan-600/60 text-xs px-3 py-1.5 rounded font-bold transition-all flex items-center gap-1"
            >
              <span>+ Broadcast zk-Proof for Tor IOC</span>
            </button>
            <button
              onClick={() => handleProveIOC('9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08')}
              disabled={zkExchangeLoading}
              className="bg-indigo-900/60 hover:bg-indigo-800/60 text-indigo-200 border border-indigo-600/60 text-xs px-3 py-1.5 rounded font-bold transition-all flex items-center gap-1"
            >
              <span>+ Broadcast zk-Proof for Hash</span>
            </button>
          </div>
        </div>

        {zkExchangeFeedback && (
          <div className="p-3 rounded-lg border text-xs bg-cyan-950/60 border-cyan-600 text-cyan-200 animate-fade-in font-sans space-y-1">
            <div className="flex items-center justify-between font-mono font-bold">
              <span>✅ {zkExchangeFeedback.status}: {zkExchangeFeedback.message}</span>
              <span className="text-emerald-400">Confidence: {(zkExchangeFeedback.proof_bundle?.attested_confidence * 100).toFixed(0)}%</span>
            </div>
            <div className="text-[10px] text-slate-400 font-mono">
              Proof Signature: <code>{zkExchangeFeedback.proof_bundle?.zk_proof_signature?.slice(0, 32)}...</code>
            </div>
          </div>
        )}

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {zkThreats.map((t) => (
            <div key={t.proof_id} className="p-3 bg-base-950 border border-base-800 rounded-lg text-xs space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-bold text-cyan-300">{t.threat_type}</span>
                <span className="text-[10px] bg-cyan-950 text-cyan-400 px-2 py-0.5 rounded border border-cyan-800">
                  {t.proof_id}
                </span>
              </div>

              <div className="text-[11px] text-slate-400 font-mono">
                Blinded Hash: <code className="text-slate-200">{t.blinded_hash.slice(0, 24)}...</code>
              </div>

              <div className="pt-2 border-t border-base-800/80 flex items-center justify-between text-[10px]">
                <span className="text-emerald-400 font-bold">{t.anonymity_status}</span>
                <span className="text-slate-400">Witnessed by: <strong>{t.participating_nodes} Enterprise Nodes</strong></span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Verification Diagnostic Banner */}


      {verifyResult && (
        <div
          className={`p-3.5 rounded-lg border text-xs font-mono transition-all ${
            verifyResult.valid
              ? 'bg-emerald-950/60 border-emerald-700/80 text-emerald-300'
              : 'bg-rose-950/80 border-rose-600 text-rose-300'
          }`}
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 font-bold text-sm">
              <span>{verifyResult.valid ? '✅ MERKLE CHAIN VERIFIED INTACT' : '❌ TAMPERING DETECTED'}</span>
              <span className="text-xs font-normal opacity-80">
                ({verifyResult.records_verified} records validated against SHA-256 hashes)
              </span>
            </div>
            <button
              onClick={() => setVerifyResult(null)}
              className="text-slate-400 hover:text-slate-200 text-sm font-sans"
            >
              ✕
            </button>
          </div>
          <div className="mt-2 text-xs opacity-90">{verifyResult.message}</div>
          {verifyResult.latest_seal && (
            <div className="mt-1.5 flex items-center gap-2">
              <span className="text-slate-400">Latest Cumulative Seal:</span>
              <code className="bg-base-950 px-2 py-0.5 rounded border border-base-700 text-[11px] text-cyan-300">
                {verifyResult.latest_seal}
              </code>
            </div>
          )}
        </div>
      )}

      {/* Filter Bar */}
      <div className="bg-base-900 border border-base-700 rounded-lg p-3 flex items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <span className="text-xs font-mono text-slate-400">Filter Action:</span>
          <select
            className="input-field w-auto text-xs py-1 font-mono"
            value={actionFilter}
            onChange={(e) => setActionFilter(e.target.value)}
          >
            <option value="">All Actions ({logs.length})</option>
            <option value="alert_triage_transition">alert_triage_transition</option>
            <option value="soar_mitigation_triggered">soar_mitigation_triggered</option>
            <option value="device_created">device_created</option>
            <option value="device_key_rotated">device_key_rotated</option>
            <option value="device_deleted">device_deleted</option>
            <option value="rule_created">rule_created</option>
            <option value="rule_updated">rule_updated</option>
            <option value="rule_deleted">rule_deleted</option>
            <option value="ioc_created">ioc_created</option>
            <option value="ioc_csv_import">ioc_csv_import</option>
            <option value="ioc_deleted">ioc_deleted</option>
            <option value="register">register</option>
            <option value="login">login</option>
          </select>
        </div>
        <div className="text-[11px] font-mono text-slate-500">

          Showing {logs.length} cryptographically sealed audit events
        </div>
      </div>

      {/* Audit Log Table */}
      <div className="panel overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-base-950/80 border-b border-base-700 text-slate-400 uppercase text-[10px] tracking-wider">
              <tr>
                <th className="py-3 px-4 w-44">Timestamp (UTC)</th>
                <th className="py-3 px-3 w-48">Action</th>
                <th className="py-3 px-3 w-32">Actor</th>
                <th className="py-3 px-3 w-40">Target</th>
                <th className="py-3 px-3 w-44">Cryptographic Seal (SHA-256)</th>
                <th className="py-3 px-4">Audit Metadata &amp; Justification</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-base-700/60 text-slate-300">
              {loading && (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-500 font-sans text-sm">
                    Loading compliance records…
                  </td>
                </tr>
              )}
              {!loading && logs.length === 0 && (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-500 font-sans text-sm">
                    No audit records recorded yet.
                  </td>
                </tr>
              )}
              {logs.map((log) => {
                const isExpanded = expandedLogId === log.id
                return (
                  <React.Fragment key={log.id}>
                    <tr
                      onClick={() => setExpandedLogId(isExpanded ? null : log.id)}
                      className={`cursor-pointer transition-colors hover:bg-base-800/80 ${
                        isExpanded ? 'bg-base-800 border-l-2 border-l-accent' : ''
                      }`}
                    >
                      <td className="py-2.5 px-4 text-slate-400 whitespace-nowrap">
                        {new Date(log.created_at).toISOString().replace('T', ' ').slice(0, 19)}
                      </td>
                      <td className="py-2.5 px-3">
                        <span
                          className={`px-2 py-0.5 rounded text-[11px] font-semibold uppercase ${
                            log.action.includes('mitigation')
                              ? 'bg-rose-950/80 text-rose-300 border border-rose-800'
                              : log.action.includes('triage')
                              ? 'bg-indigo-950/80 text-indigo-300 border border-indigo-800'
                              : 'bg-base-950 text-accent border border-base-700'
                          }`}
                        >
                          {log.action}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-slate-300">
                        {log.actor_user_id ? log.actor_user_id.slice(0, 8) + '...' : 'System'}
                      </td>
                      <td className="py-2.5 px-3 text-cyan-400 truncate max-w-[140px]">
                        {log.target || '-'}
                      </td>
                      <td className="py-2.5 px-3">
                        {log.cryptographic_seal ? (
                          <span
                            title={log.cryptographic_seal}
                            className="bg-base-950 text-emerald-400 px-1.5 py-0.5 rounded text-[10px] border border-emerald-900/60 font-mono inline-block truncate max-w-[130px]"
                          >
                            {log.cryptographic_seal.slice(0, 12)}...
                          </span>
                        ) : (
                          <span className="text-slate-600 text-[10px]">—</span>
                        )}
                      </td>
                      <td className="py-2.5 px-4 text-slate-300 truncate max-w-md">
                        {log.meta?.comment ? (
                          <span className="text-amber-300 font-sans">"{log.meta.comment}"</span>
                        ) : (
                          <span className="text-slate-500 font-mono text-[11px]">
                            {JSON.stringify(log.meta || {})}
                          </span>
                        )}
                      </td>
                    </tr>

                    {/* Expandable JSON Detail */}
                    {isExpanded && (
                      <tr className="bg-base-950/90">
                        <td colSpan={6} className="p-4 border-t border-b border-base-700 font-mono">
                          <div className="flex items-center justify-between mb-2">
                            <div className="text-[11px] text-slate-400 font-semibold uppercase">
                              Cryptographic Audit Block Trace
                            </div>
                            {log.cryptographic_seal && (
                              <div className="text-[11px] text-emerald-400">
                                Seal: <code className="text-cyan-300">{log.cryptographic_seal}</code>
                              </div>
                            )}
                          </div>
                          <pre className="bg-base-900 border border-base-700 rounded p-3 text-xs text-emerald-400 overflow-x-auto">
                            {JSON.stringify(log, null, 2)}
                          </pre>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                )
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Zero-Knowledge Compliance Attestation Modal */}
      {zkModal && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center z-50 p-4">
          <div className="bg-base-900 border border-indigo-500/60 rounded-xl p-6 max-w-2xl w-full space-y-4 shadow-2xl font-mono animate-fade-in max-h-[90vh] flex flex-col">
            <div className="flex items-center justify-between border-b border-indigo-900/60 pb-3 shrink-0">
              <div>
                <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
                  <span className="text-indigo-400">🛡</span>
                  <span>Zero-Knowledge Compliance Attestation (zk-SNARKs)</span>
                </h3>
                <p className="text-[11px] text-slate-400 mt-0.5">
                  Prove SOC 2 Type II / ISO 27001 SLA compliance mathematically to external auditors with ZERO disclosure of private logs, IPs, or users.
                </p>
              </div>
              <button
                onClick={() => setZkModal(false)}
                className="text-slate-400 hover:text-slate-200 text-sm font-sans"
              >
                ✕
              </button>
            </div>

            <div className="space-y-4 overflow-y-auto pr-1 flex-1 text-xs">
              {/* SLA Parameter Controls */}
              <div className="p-3 bg-base-950 border border-base-800 rounded-lg space-y-2">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="text-slate-300 font-bold">Audit Statement:</span>
                  <div className="flex items-center gap-2">
                    <span className="text-slate-400 text-[11px]">Triage SLA:</span>
                    <select
                      className="bg-base-900 border border-base-700 text-slate-200 text-xs px-2 py-1 rounded"
                      value={slaMinutes}
                      onChange={(e) => setSlaMinutes(Number(e.target.value))}
                    >
                      <option value={15}>15 Minutes (Critical)</option>
                      <option value={30}>30 Minutes (High)</option>
                      <option value={60}>60 Minutes (Standard)</option>
                    </select>
                    <button
                      disabled={zkGenerating}
                      onClick={handleGenerateZKProof}
                      className="btn-primary text-xs px-3 py-1 font-bold"
                    >
                      {zkGenerating ? 'Computing Circuit...' : '⚡ Generate Proof π'}
                    </button>
                  </div>
                </div>
                <p className="text-[11px] text-slate-400 font-sans">
                  Circuit: <code className="text-indigo-300">SOC2-CC6.8-SLA-TRIAGE-CIRCUIT-v4 (Groth16 / BN254)</code>
                </p>
              </div>

              {/* Proof Bundle View */}
              {zkProofBundle && (
                <div className="space-y-3">
                  <div className="p-3 bg-base-950 border border-base-800 rounded-lg space-y-2">
                    <div className="flex items-center justify-between text-[11px]">
                      <span className="text-indigo-300 font-bold uppercase">Succinct Proof Parameters (π)</span>
                      <span className="text-emerald-400 font-bold">Curve: {zkProofBundle.curve}</span>
                    </div>

                    <div className="space-y-1 text-[11px] text-slate-300">
                      <div>π_A: <code className="text-cyan-300 truncate block">{zkProofBundle.proof?.pi_a?.[0]}</code></div>
                      <div>π_B: <code className="text-cyan-300 truncate block">{zkProofBundle.proof?.pi_b?.[0]?.[0]}</code></div>
                      <div>π_C: <code className="text-cyan-300 truncate block">{zkProofBundle.proof?.pi_c?.[0]}</code></div>
                    </div>

                    <div className="pt-2 border-t border-base-800 text-[10px] text-slate-400 space-y-0.5">
                      <div>Merkle Ledger Root Commitment: <code className="text-emerald-400">{zkProofBundle.public_inputs?.merkle_ledger_root_commitment?.slice(0, 24)}...</code></div>
                      <div>Compliance Claim: <strong className="text-slate-200">{zkProofBundle.public_inputs?.compliance_claim}</strong></div>
                      <div className="text-indigo-300">✔ {zkProofBundle.zero_knowledge_guarantee}</div>
                    </div>
                  </div>

                  {/* Auditor Verification Result */}
                  {zkVerifyResult ? (
                    <div className={`p-3.5 rounded-lg border text-xs space-y-1.5 ${
                      zkVerifyResult.verified ? 'bg-emerald-950/70 border-emerald-600 text-emerald-300' : 'bg-rose-950/70 border-rose-600 text-rose-300'
                    }`}>
                      <div className="flex items-center justify-between font-bold">
                        <span>AUDITOR VERDICT: {zkVerifyResult.auditor_verdict}</span>
                        <span className="text-[10px] bg-black/40 px-2 py-0.5 rounded">Duration: {zkVerifyResult.verification_duration_ms}ms</span>
                      </div>
                      <div className="text-[11px] font-sans text-slate-300">
                        Evaluated pairing equation over elliptic curve BN254. Confidentiality status: <strong>{zkVerifyResult.confidentiality_status}</strong>.
                      </div>
                    </div>
                  ) : (
                    <button
                      disabled={zkVerifying}
                      onClick={handleVerifyZKProof}
                      className="w-full bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-500 hover:to-purple-500 text-white text-xs py-2.5 rounded-lg font-bold transition-all shadow-md flex items-center justify-center gap-2"
                    >
                      <span>🔍</span>
                      <span>{zkVerifying ? 'Verifying Elliptic Curve Pairing...' : 'Verify Proof in Auditor Sandbox Mode (Zero Data Access)'}</span>
                    </button>
                  )}
                </div>
              )}
            </div>

            <div className="flex justify-end pt-3 border-t border-base-800 shrink-0">
              <button
                type="button"
                onClick={() => setZkModal(false)}
                className="btn-secondary text-xs px-4 py-1.5"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

