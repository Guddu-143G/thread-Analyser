import { useEffect, useState } from 'react'
import client from '../api/client'

export default function TechInventory() {
  const [inventory, setInventory] = useState([])
  const [loading, setLoading] = useState(true)
  const [deployingTech, setDeployingTech] = useState(null)
  const [feedback, setFeedback] = useState(null)

  const loadInventory = () => {
    client
      .get('/inventory')
      .then(({ data }) => setInventory(data || []))
      .catch((err) => console.error('Failed to load tech inventory:', err))
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    loadInventory()
  }, [])

  const handleDeployTargetedDecoy = async (tech, hostname) => {
    setDeployingTech(tech)
    try {
      const { data } = await client.post('/deception/targeted-deploy', {
        technology: tech,
        hostname: hostname || 'prod-app-01',
      })
      setFeedback({
        type: 'success',
        title: '🎯 Proactive Threat-Twin Decoy Deployed',
        message: data.message,
        decoy: data.decoy,
      })
      setTimeout(() => setFeedback(null), 9000)
    } catch (err) {
      setFeedback({
        type: 'error',
        title: 'Deployment Failed',
        message: err.response?.data?.detail || err.message,
      })
    } finally {
      setDeployingTech(null)
    }
  }

  return (
    <div className="space-y-6 font-mono">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <span>Real-Time Passive Tech Stack Extraction (Dynamic SBOM)</span>
            <span className="text-xs bg-cyan-950 text-cyan-300 px-2 py-0.5 rounded border border-cyan-700 flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse"></span>
              OCSF Class 5001
            </span>
          </h1>
          <p className="text-slate-400 text-xs mt-0.5 font-sans">
            Passively profiles active application layers, libraries, and listening sockets. Deploys targeted honey-token traps specifically matched to discovered technologies.
          </p>
        </div>

        <button
          onClick={loadInventory}
          className="bg-base-900 hover:bg-base-800 border border-base-700 text-slate-200 text-xs px-3 py-2 rounded transition-all flex items-center gap-1.5 self-start"
        >
          <span>🔄 Refresh Discovery</span>
        </button>
      </div>

      {/* Feedback Banner */}
      {feedback && (
        <div
          className={`p-4 rounded-xl border text-xs animate-fade-in ${
            feedback.type === 'success'
              ? 'bg-emerald-950/80 border-emerald-600 text-emerald-200'
              : 'bg-rose-950/80 border-rose-600 text-rose-200'
          }`}
        >
          <div className="font-bold text-sm mb-1">{feedback.title}</div>
          <div className="text-slate-300 font-sans">{feedback.message}</div>
          {feedback.decoy && (
            <div className="mt-2 p-2 bg-base-950 rounded border border-base-800 text-[11px] space-y-1">
              <div>Decoy Identifier: <code className="text-amber-300">{feedback.decoy.decoy_identifier}</code></div>
              <div>Type: <span className="text-cyan-300">{feedback.decoy.type}</span></div>
              {feedback.decoy.file_content_preview && (
                <div className="text-slate-400 font-mono text-[10px] bg-base-900 p-1.5 rounded mt-1 whitespace-pre">
                  {feedback.decoy.file_content_preview}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Overview Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="panel p-4 bg-base-900 border border-base-700 space-y-1">
          <div className="text-[10px] text-slate-500 uppercase">Total Discovered Technologies</div>
          <div className="text-xl font-bold text-slate-100">{inventory.length} Frameworks</div>
          <div className="text-[10px] text-emerald-400">Zero Static SBOM Delay</div>
        </div>

        <div className="panel p-4 bg-base-900 border border-base-700 space-y-1">
          <div className="text-[10px] text-slate-500 uppercase">Database &amp; Caching Services</div>
          <div className="text-xl font-bold text-cyan-300">
            {inventory.filter((i) => ['PostgreSQL', 'Redis', 'MongoDB'].includes(i.technology)).length} Monitored
          </div>
          <div className="text-[10px] text-slate-400">Socket Binds Validated</div>
        </div>

        <div className="panel p-4 bg-base-900 border border-base-700 space-y-1">
          <div className="text-[10px] text-slate-500 uppercase">Application Runtimes</div>
          <div className="text-xl font-bold text-purple-300">
            {inventory.filter((i) => ['FastAPI', 'Spring Boot', 'ExpressJS', 'Django', 'Next.js'].includes(i.technology)).length} Active
          </div>
          <div className="text-[10px] text-slate-400">Process Args Fingerprinted</div>
        </div>

        <div className="panel p-4 bg-base-900 border border-base-700 space-y-1">
          <div className="text-[10px] text-slate-500 uppercase">Discovery Confidence</div>
          <div className="text-xl font-bold text-emerald-400">High / Multi-Signal</div>
          <div className="text-[10px] text-slate-400">eBPF + Socket Cross-Checked</div>
        </div>
      </div>

      {/* Discovered Tech Stacks Cards */}
      <div className="panel p-4 space-y-3">
        <div className="flex items-center justify-between border-b border-base-800 pb-3">
          <div>
            <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <span>Discovered Workload Tech Stacks &amp; Active Deception Traps</span>
              <span className="text-[10px] bg-base-950 text-slate-400 px-2 py-0.5 rounded border border-base-700">
                {inventory.length} Stacks
              </span>
            </h2>
            <p className="text-[11px] text-slate-400 font-sans mt-0.5">
              Click &quot;Deploy Targeted Honey-Token&quot; on any discovered technology to plant customized canary traps.
            </p>
          </div>
        </div>

        {inventory.length === 0 ? (
          <div className="p-8 text-center text-slate-500 text-xs">
            No runtime technologies discovered yet. Ingest telemetry or execute sample applications to trigger real-time fingerprinting!
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-1">
            {inventory.map((item) => (
              <div
                key={item.id}
                className="p-4 bg-base-950 border border-base-800 hover:border-cyan-700/60 rounded-xl space-y-3 transition-all flex flex-col justify-between"
              >
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-slate-100 text-sm flex items-center gap-1.5">
                      <span className="text-cyan-400">
                        {item.technology === 'PostgreSQL' ? '🐘' : item.technology === 'FastAPI' ? '⚡' : item.technology === 'Spring Boot' ? '🍃' : item.technology === 'Redis' ? '🔴' : '📦'}
                      </span>
                      <span>{item.technology}</span>
                    </span>
                    <span
                      className={`text-[10px] px-2 py-0.5 rounded font-bold uppercase ${
                        item.confidence === 'very_high' || item.confidence === 'high'
                          ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                          : 'bg-amber-950 text-amber-300 border border-amber-800'
                      }`}
                    >
                      {item.confidence}
                    </span>
                  </div>

                  <div className="text-[11px] text-slate-400 space-y-1">
                    <div>Category: <span className="text-slate-200">{item.category || 'Framework'}</span></div>
                    <div>Runtime: <span className="text-purple-300">{item.runtime || 'Process Native'}</span></div>
                    <div>Port: <code className="text-amber-300">:{item.detected_port || 'Auto'}</code></div>
                    <div>Host: <span className="text-slate-300">{item.hostname || 'prod-app-01'}</span></div>
                  </div>
                </div>

                <div className="pt-2 border-t border-base-800/80 space-y-2">
                  <div className="text-[9px] text-slate-500">
                    Discovered: {new Date(item.first_seen).toLocaleString()}
                  </div>
                  <button
                    onClick={() => handleDeployTargetedDecoy(item.technology, item.hostname)}
                    disabled={deployingTech === item.technology}
                    className="w-full bg-cyan-950 hover:bg-cyan-900/80 text-cyan-200 border border-cyan-700/60 text-xs py-1.5 rounded transition-all font-bold flex items-center justify-center gap-1.5"
                  >
                    <span>🪤</span>
                    <span>
                      {deployingTech === item.technology ? 'Deploying Trap...' : `Deploy ${item.technology} Honey-Token`}
                    </span>
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
