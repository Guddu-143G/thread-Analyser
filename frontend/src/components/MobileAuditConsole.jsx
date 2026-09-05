import React, { useState, useEffect } from 'react'

export default function MobileAuditConsole({ session, onAttemptUpdated }) {
  const [deviceInfo, setDeviceInfo] = useState(null)
  const [attempts, setAttempts] = useState([])
  const [activeAttempt, setActiveAttempt] = useState(null)
  const [status, setStatus] = useState('RUNNING') // WAITING_FOR_DEVICE, RUNNING, COOLDOWN, FINISHED
  const [cooldown, setCooldown] = useState(0)
  const [speed, setSpeed] = useState(2.4)

  useEffect(() => {
    if (!session) return

    setDeviceInfo({
      manufacturer: session.device_name,
      model: session.device_model,
      serial_number: session.serial_number,
      udid: session.udid,
      os_version: session.os_version,
      passcode_type: session.passcode_type
    })

    if (session.status === 'COMPLETED') {
      setStatus('FINISHED')
    } else if (session.status === 'LOCKED_OUT') {
      setStatus('COOLDOWN')
      setCooldown(30)
    } else {
      setStatus('RUNNING')
    }

    // Connect WebSocket
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const host = window.location.host
    const wsUrl = `${protocol}//${host}/api/v21/forensics/live?session_id=${session.session_id}`
    let ws = null

    try {
      ws = new WebSocket(wsUrl)
      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data)
          if (data.type === 'DEVICE_CONNECTED') {
            setDeviceInfo(data.device)
            setStatus('RUNNING')
          } else if (data.type === 'AUDIT_TICK') {
            setActiveAttempt(data.attempt)
            setSpeed(data.guesses_per_sec || 2.4)
            setAttempts((prev) => [data.attempt, ...prev.slice(0, 9)])
            if (data.attempt.backoff_triggered_sec > 0) {
              setStatus('COOLDOWN')
              setCooldown(Math.ceil(data.attempt.backoff_triggered_sec))
            }
            if (onAttemptUpdated) onAttemptUpdated(data.attempt)
          } else if (data.type === 'AUDIT_SUCCESS') {
            setStatus('FINISHED')
            setActiveAttempt({ ...data.attempt, is_successful: true, response_code: 'SUCCESS' })
            setAttempts((prev) => [data.attempt, ...prev.slice(0, 9)])
            if (onAttemptUpdated) onAttemptUpdated(data.attempt)
          }
        } catch (e) {
          console.error('WS Parse error', e)
        }
      }
    } catch (err) {
      console.warn('WS initialization warning', err)
    }

    return () => {
      if (ws) ws.close()
    }
  }, [session])

  // Cooldown countdown timer
  useEffect(() => {
    if (cooldown <= 0) {
      if (status === 'COOLDOWN') setStatus('RUNNING')
      return
    }
    const timer = setInterval(() => {
      setCooldown((prev) => (prev > 0 ? prev - 1 : 0))
    }, 1000)
    return () => clearInterval(timer)
  }, [cooldown, status])

  // Grid coordinates helper for 3x3 pattern SVG line calculation
  const getNodeCenter = (nodeIndex) => {
    const row = Math.floor(nodeIndex / 3)
    const col = nodeIndex % 3
    // in a 192x192 box, margin=24, step=72
    const x = 24 + col * 72
    const y = 24 + row * 72
    return { x, y }
  }

  const renderPatternGrid = (activePath = []) => {
    const path = Array.isArray(activePath) && activePath.length > 0 ? activePath : [0, 1, 2, 5, 8]
    
    // Build SVG path data
    let svgPathD = ''
    if (path.length > 1) {
      const first = getNodeCenter(path[0])
      svgPathD = `M ${first.x} ${first.y}`
      for (let i = 1; i < path.length; i++) {
        const pt = getNodeCenter(path[i])
        svgPathD += ` L ${pt.x} ${pt.y}`
      }
    }

    return (
      <div className="relative w-48 h-48 mx-auto bg-slate-950 p-3 rounded-2xl border border-teal-500/30 shadow-[0_0_25px_rgba(20,184,166,0.15)] flex items-center justify-center">
        {/* SVG Connectors Line */}
        <svg className="absolute inset-0 w-full h-full pointer-events-none z-10" viewBox="0 0 192 192">
          {svgPathD && (
            <path
              d={svgPathD}
              fill="none"
              stroke="#06b6d4"
              strokeWidth="4"
              strokeLinecap="round"
              strokeLinejoin="round"
              className="animate-pulse drop-shadow-[0_0_8px_rgba(6,182,212,0.8)]"
            />
          )}
        </svg>

        {/* 3x3 Nodes Grid */}
        <div className="grid grid-cols-3 gap-6 relative z-20">
          {[0, 1, 2, 3, 4, 5, 6, 7, 8].map((node) => {
            const isSelected = path.includes(node)
            const isStartNode = path[0] === node
            const isEndNode = path[path.length - 1] === node
            return (
              <div
                key={node}
                className={`relative rounded-full flex items-center justify-center transition-all duration-200 ${
                  isSelected
                    ? isStartNode
                      ? 'bg-emerald-500 scale-110 shadow-[0_0_12px_rgba(16,185,129,0.8)] border-2 border-emerald-200'
                      : isEndNode
                      ? 'bg-amber-500 scale-110 shadow-[0_0_12px_rgba(245,158,11,0.8)] border-2 border-amber-200'
                      : 'bg-cyan-500 scale-105 shadow-[0_0_10px_rgba(6,182,212,0.7)] border border-cyan-200'
                    : 'bg-slate-900/90 border border-slate-700/80 hover:border-slate-600'
                }`}
                style={{ width: '32px', height: '32px' }}
              >
                <span className={`text-[10px] font-mono font-bold ${isSelected ? 'text-slate-950' : 'text-slate-500'}`}>
                  {node}
                </span>
                {isSelected && (
                  <div className="absolute inset-0 rounded-full border border-white/40 animate-ping opacity-40 pointer-events-none" />
                )}
              </div>
            )
          })}
        </div>
      </div>
    )
  }

  return (
    <div className="bg-base-900 border border-base-700/80 rounded-2xl p-6 text-slate-200 shadow-2xl font-sans relative overflow-hidden backdrop-blur-md">
      {/* Glow highlight */}
      <div className="absolute top-0 right-0 w-48 h-48 bg-teal-500/5 rounded-full blur-3xl pointer-events-none" />

      {/* Header Panel */}
      <div className="flex items-center justify-between border-b border-base-700/80 pb-4 mb-5">
        <div>
          <h2 className="text-base font-bold text-slate-100 flex items-center gap-2 font-mono">
            <span className="h-2.5 w-2.5 rounded-full bg-teal-400 animate-pulse shadow-[0_0_8px_rgba(45,212,191,0.8)]" />
            Hardware OTG-HID Emulation Console
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-0.5">Physical USB Subsystem &amp; Passcode Strength Auditor</p>
        </div>
        <div className="flex items-center gap-2">
          <span
            className={`px-3 py-1 rounded-full text-xs font-mono font-bold tracking-wider uppercase border transition-all ${
              status === 'RUNNING'
                ? 'bg-teal-950/80 text-teal-300 border-teal-500/50 shadow-[0_0_10px_rgba(20,184,166,0.3)] animate-pulse'
                : status === 'COOLDOWN'
                ? 'bg-rose-950/80 text-rose-300 border-rose-500/50 shadow-[0_0_10px_rgba(244,63,94,0.3)]'
                : status === 'FINISHED'
                ? 'bg-emerald-950/80 text-emerald-300 border-emerald-500/50 shadow-[0_0_10px_rgba(16,185,129,0.3)]'
                : 'bg-slate-900 text-slate-400 border-slate-700'
            }`}
          >
            ● {status}
          </span>
        </div>
      </div>

      {/* Device Info Bar */}
      {deviceInfo ? (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 bg-base-950/70 border border-base-700/60 p-3.5 rounded-xl mb-6 text-xs font-mono">
          <div>
            <span className="text-slate-500 block text-[10px] uppercase">Target Endpoint</span>
            <span className="text-slate-200 font-bold truncate block">{deviceInfo.manufacturer} {deviceInfo.model}</span>
          </div>
          <div>
            <span className="text-slate-500 block text-[10px] uppercase">Hardware Serial</span>
            <span className="text-teal-400 font-bold truncate block">{deviceInfo.serial_number}</span>
          </div>
          <div>
            <span className="text-slate-500 block text-[10px] uppercase">Attack Vector</span>
            <span className="text-amber-400 font-bold uppercase block">{deviceInfo.passcode_type}</span>
          </div>
          <div>
            <span className="text-slate-500 block text-[10px] uppercase">Throughput</span>
            <span className="text-cyan-400 font-bold block">{speed.toFixed(1)} Guesses/sec</span>
          </div>
        </div>
      ) : (
        <div className="text-center py-6 text-slate-500 text-sm font-mono border border-dashed border-base-700 rounded-xl mb-6">
          Awaiting physical USB device attachment &amp; session initiation...
        </div>
      )}

      {/* Interactive Visualizations: 3x3 Gesture Pattern Grid or PIN Meter */}
      {session && session.passcode_type === 'PATTERN' && (
        <div className="mb-6 bg-base-950/50 border border-base-800 p-5 rounded-2xl">
          <div className="flex items-center justify-between mb-3 text-xs font-mono">
            <span className="text-slate-400">Gesture Grid (3x3 Matrix Coordinates)</span>
            <span className="text-teal-400 font-bold">
              Path: [{activeAttempt?.pattern_path ? activeAttempt.pattern_path.join(' → ') : '0 → 1 → 2 → 5 → 8'}]
            </span>
          </div>
          {renderPatternGrid(activeAttempt?.pattern_path || [0, 1, 2, 5, 8])}
          <div className="flex items-center justify-center gap-6 mt-4 font-mono text-xs text-slate-400">
            <div>
              Attempt: <span className="text-slate-200 font-bold px-2 py-0.5 rounded bg-base-900 border border-base-700">#{activeAttempt?.attempt_index || 1}</span>
            </div>
            <div>
              Shannon Entropy: <span className="text-amber-400 font-bold">{activeAttempt?.entropy || session?.max_estimated_entropy || 11.83} bits</span>
            </div>
          </div>
        </div>
      )}

      {session && session.passcode_type !== 'PATTERN' && (
        <div className="mb-6 bg-base-950/50 border border-base-800 p-5 rounded-2xl text-center">
          <span className="text-xs text-slate-400 font-mono block mb-2">Simulated PIN / Alphanumeric Key Stream</span>
          <div className="text-3xl font-extrabold font-mono tracking-widest text-cyan-400 py-3 bg-base-950 rounded-xl border border-cyan-500/20 shadow-inner">
            {activeAttempt ? '•••• ••••' : '••••'}
          </div>
          <div className="flex items-center justify-center gap-6 mt-3 font-mono text-xs text-slate-400">
            <div>
              Attempt: <span className="text-slate-200 font-bold px-2 py-0.5 rounded bg-base-900 border border-base-700">#{activeAttempt?.attempt_index || 1}</span>
            </div>
            <div>
              Shannon Entropy: <span className="text-amber-400 font-bold">{activeAttempt?.entropy || session?.max_estimated_entropy || 13.29} bits</span>
            </div>
          </div>
        </div>
      )}

      {/* Cooldown Lockout Warning */}
      {status === 'COOLDOWN' && (
        <div className="bg-rose-950/40 border border-rose-700/60 rounded-xl p-5 text-center my-5 shadow-[0_0_20px_rgba(244,63,94,0.15)] animate-pulse">
          <div className="text-3xl font-extrabold text-rose-400 font-mono tracking-wider">{cooldown}s</div>
          <p className="text-xs text-rose-300 font-mono mt-1 font-semibold">
            ⚠️ Hardware Lockout Detected. Adaptive rate throttler is cooling down interface...
          </p>
        </div>
      )}

      {/* Success Banner */}
      {status === 'FINISHED' && (
        <div className="bg-emerald-950/40 border border-emerald-600/60 rounded-xl p-4 text-center my-5 shadow-[0_0_20px_rgba(16,185,129,0.2)]">
          <div className="text-emerald-400 font-mono font-bold text-sm flex items-center justify-center gap-2">
            <span>✓</span> Passcode Decrypted &amp; Verified by Forensic Engine
          </div>
          <p className="text-[11px] text-emerald-300/80 font-mono mt-1">Audit complete. Device unlock validated via OTG-HID handshake.</p>
        </div>
      )}

      {/* Real-time Session Log */}
      <div className="border-t border-base-700/80 pt-4">
        <div className="flex items-center justify-between mb-2.5">
          <h3 className="text-xs font-bold text-slate-300 uppercase font-mono tracking-wider">
            Real-Time Audit Trail (SHA-256 Hashes)
          </h3>
          <span className="text-[10px] text-slate-500 font-mono">Zero Plaintext Exposure</span>
        </div>
        <div className="space-y-1.5 max-h-40 overflow-y-auto font-mono text-[11px] pr-1">
          {attempts.length > 0 ? (
            attempts.map((att, i) => (
              <div
                key={att.attempt_id || i}
                className="flex items-center justify-between py-1.5 px-2.5 rounded bg-base-950/60 border border-base-800 text-slate-300 hover:border-base-700 transition-colors"
              >
                <span className="text-slate-500 font-semibold w-16">#{att.attempt_index}</span>
                <span className="text-slate-400 truncate max-w-[200px] font-mono text-[10px]" title={att.candidate_hash}>
                  {att.candidate_hash}
                </span>
                <span className="text-slate-500 text-[10px]">{att.latency_ms || 45}ms</span>
                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                    att.response_code === 'SUCCESS' || att.is_successful
                      ? 'bg-emerald-950 text-emerald-300 border border-emerald-700/60'
                      : att.response_code === 'LOCKED_OUT'
                      ? 'bg-rose-950 text-rose-300 border border-rose-700/60'
                      : 'bg-base-900 text-slate-400 border border-base-700'
                  }`}
                >
                  {att.response_code || (att.is_successful ? 'SUCCESS' : 'REJECTED')}
                </span>
              </div>
            ))
          ) : (
            <div className="text-center py-4 text-slate-600 text-xs font-mono">No attempts logged yet.</div>
          )}
        </div>
      </div>
    </div>
  )
}
