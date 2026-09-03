import React, { useEffect, useState, useRef, useMemo } from 'react'

const MAX_LOG_BUFFER = 2000
const ROW_HEIGHT = 28

export default function LiveConsole({ token, onNewLog, onLockEvent }) {
  const [logs, setLogs] = useState([])
  const [isStreaming, setIsStreaming] = useState(true)
  const [autoScroll, setAutoScroll] = useState(true)
  const [filterSeverity, setFilterSeverity] = useState('ALL')
  const [searchQuery, setSearchQuery] = useState('')
  const [wsStatus, setWsStatus] = useState('DISCONNECTED')
  const [activeLocks, setActiveLocks] = useState({})
  const [scrollTop, setScrollTop] = useState(0)

  const parentRef = useRef(null)
  const socketRef = useRef(null)
  const reconnectTimeoutRef = useRef(null)

  // Initialize and manage WebSocket connection
  useEffect(() => {
    if (!token) return

    let isSubscribed = true

    function connectWebSocket() {
      if (!isStreaming) return

      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
      const host = window.location.host || 'localhost:8000'
      const wsUrl = `${protocol}//${host}/api/ws/stream?token=${encodeURIComponent(token)}`

      setWsStatus('CONNECTING')
      const ws = new WebSocket(wsUrl)
      socketRef.current = ws

      ws.onopen = () => {
        if (!isSubscribed) return
        setWsStatus('CONNECTED')
      }

      ws.onmessage = (event) => {
        if (!isSubscribed) return
        try {
          const msg = JSON.parse(event.data)

          if (msg.event === 'connected') {
            if (msg.payload?.active_locks) {
              setActiveLocks(msg.payload.active_locks)
            }
          } else if (msg.event === 'raw_logs' || msg.event === 'log') {
            const newLog = msg.payload
            setLogs((prev) => {
              const updated = [...prev, newLog]
              if (updated.length > MAX_LOG_BUFFER) {
                return updated.slice(updated.length - MAX_LOG_BUFFER)
              }
              return updated
            })
            if (onNewLog) onNewLog(newLog)
          } else if (msg.event === 'alert_locked') {
            setActiveLocks((prev) => ({
              ...prev,
              [msg.payload.alert_id]: msg.payload,
            }))
            if (onLockEvent) onLockEvent(msg.payload)
          } else if (msg.event === 'alert_unlocked') {
            setActiveLocks((prev) => {
              const copy = { ...prev }
              delete copy[msg.payload.alert_id]
              return copy
            })
          }
        } catch (err) {
          console.error('Error parsing WebSocket payload:', err)
        }
      }

      ws.onclose = () => {
        if (!isSubscribed) return
        setWsStatus('DISCONNECTED')
        if (isStreaming) {
          reconnectTimeoutRef.current = setTimeout(connectWebSocket, 3000)
        }
      }

      ws.onerror = () => {
        setWsStatus('ERROR')
      }
    }

    if (isStreaming) {
      connectWebSocket()
    } else {
      if (socketRef.current) socketRef.current.close()
      setWsStatus('PAUSED')
    }

    return () => {
      isSubscribed = false
      if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current)
      if (socketRef.current) socketRef.current.close()
    }
  }, [token, isStreaming])

  // Filter logs by search query and severity
  const filteredLogs = useMemo(() => {
    return logs.filter((l) => {
      if (filterSeverity !== 'ALL') {
        const sevMap = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 }
        if (l.severity_id !== sevMap[filterSeverity]) return false
      }
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase()
        const text = `${l.message} ${l.class_name} ${l.device?.hostname || ''} ${l.actor?.user?.name || ''}`.toLowerCase()
        if (!text.includes(q)) return false
      }
      return true
    })
  }, [logs, filterSeverity, searchQuery])

  // Virtualization calculations
  const totalHeight = filteredLogs.length * ROW_HEIGHT
  const containerHeight = 460
  const overscan = 15

  const startIndex = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - overscan)
  const endIndex = Math.min(
    filteredLogs.length,
    Math.ceil((scrollTop + containerHeight) / ROW_HEIGHT) + overscan
  )

  const visibleRows = useMemo(() => {
    return filteredLogs.slice(startIndex, endIndex).map((log, idx) => ({
      index: startIndex + idx,
      top: (startIndex + idx) * ROW_HEIGHT,
      log,
    }))
  }, [filteredLogs, startIndex, endIndex])

  // Handle scroll events
  const handleScroll = (e) => {
    const el = e.currentTarget
    setScrollTop(el.scrollTop)
    const isAtBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 40
    if (isAtBottom !== autoScroll) {
      setAutoScroll(isAtBottom)
    }
  }

  // Auto-scroll when new logs arrive if user hasn't scrolled up
  useEffect(() => {
    if (autoScroll && parentRef.current) {
      parentRef.current.scrollTop = parentRef.current.scrollHeight
    }
  }, [filteredLogs.length, autoScroll])

  const severityStyles = [
    { label: 'INFO', badge: 'bg-slate-800 text-slate-300 border-slate-700', text: 'text-slate-400' },
    { label: 'LOW', badge: 'bg-sky-950 text-sky-300 border-sky-800', text: 'text-sky-400' },
    { label: 'MED', badge: 'bg-amber-950 text-amber-300 border-amber-800', text: 'text-amber-400' },
    { label: 'HIGH', badge: 'bg-orange-950 text-orange-300 border-orange-800', text: 'text-orange-400' },
    { label: 'CRIT', badge: 'bg-rose-950 text-rose-300 border-rose-800 font-bold animate-pulse', text: 'text-rose-400 font-bold' },
  ]

  return (
    <div className="bg-base-950 border border-base-700/80 rounded-xl p-4 flex flex-col h-[600px] shadow-2xl font-mono">
      {/* Header & Controls Bar */}
      <div className="flex flex-wrap justify-between items-center pb-3 border-b border-base-800 gap-3">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <span
              className={`w-2.5 h-2.5 rounded-full ${
                wsStatus === 'CONNECTED'
                  ? 'bg-emerald-400 animate-pulse shadow-sm shadow-emerald-400/50'
                  : wsStatus === 'CONNECTING'
                  ? 'bg-amber-400 animate-bounce'
                  : 'bg-rose-500'
              }`}
            />
            <span className="text-xs font-bold text-slate-100 tracking-wider">
              LIVE OCSF TAIL -F STREAM
            </span>
          </div>

          <span className="text-[10px] bg-base-900 border border-base-700 text-cyan-400 px-2 py-0.5 rounded font-semibold">
            {wsStatus}
          </span>
          <span className="text-[11px] text-slate-400">
            Buffer: <strong className="text-slate-200">{logs.length}</strong> / {MAX_LOG_BUFFER}
          </span>
        </div>

        {/* Filter & Stream Controls */}
        <div className="flex items-center gap-2 text-xs">
          <input
            type="text"
            placeholder="Filter messages..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="bg-base-900 border border-base-700 text-slate-200 px-2.5 py-1 rounded text-xs focus:outline-none focus:border-cyan-500 w-36 sm:w-48"
          />

          <select
            value={filterSeverity}
            onChange={(e) => setFilterSeverity(e.target.value)}
            className="bg-base-900 border border-base-700 text-slate-200 px-2 py-1 rounded text-xs focus:outline-none"
          >
            <option value="ALL">All Severities</option>
            <option value="INFO">Info (0)</option>
            <option value="LOW">Low (1)</option>
            <option value="MEDIUM">Medium (2)</option>
            <option value="HIGH">High (3)</option>
            <option value="CRITICAL">Critical (4)</option>
          </select>

          <button
            onClick={() => setAutoScroll(!autoScroll)}
            className={`px-2.5 py-1 rounded text-xs font-medium border transition ${
              autoScroll
                ? 'bg-cyan-950 text-cyan-300 border-cyan-800'
                : 'bg-base-900 text-slate-400 border-base-700 hover:text-slate-200'
            }`}
          >
            {autoScroll ? '⬇ Lock Bottom' : '⬆ Free Scroll'}
          </button>

          <button
            onClick={() => setIsStreaming(!isStreaming)}
            className={`px-3 py-1 rounded text-xs font-bold border transition ${
              isStreaming
                ? 'bg-rose-950/60 text-rose-300 border-rose-800 hover:bg-rose-900/80'
                : 'bg-emerald-950/60 text-emerald-300 border-emerald-800 hover:bg-emerald-900/80'
            }`}
          >
            {isStreaming ? '⏸ Pause' : '▶ Resume'}
          </button>

          <button
            onClick={() => setLogs([])}
            className="bg-base-900 hover:bg-base-800 text-slate-400 hover:text-slate-200 border border-base-700 px-2 py-1 rounded text-xs"
            title="Clear buffer"
          >
            Clear
          </button>
        </div>
      </div>

      {/* Co-Triage Active Lock Banner */}
      {Object.keys(activeLocks).length > 0 && (
        <div className="bg-indigo-950/40 border-b border-indigo-900/50 px-3 py-1.5 text-[11px] text-indigo-300 flex items-center gap-2">
          <span>🔒 Co-Triage Active:</span>
          {Object.entries(activeLocks).map(([aid, lk]) => (
            <span key={aid} className="bg-indigo-900/60 px-2 py-0.5 rounded border border-indigo-700 text-[10px]">
              {aid.slice(0, 8)} locked by <strong className="text-white">{lk.locked_by}</strong>
            </span>
          ))}
        </div>
      )}

      {/* Virtualized Terminal Window */}
      <div
        ref={parentRef}
        onScroll={handleScroll}
        className="flex-1 overflow-y-auto mt-2 relative select-text scrollbar-thin scrollbar-thumb-base-700 scrollbar-track-base-950"
      >
        {filteredLogs.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-slate-500 text-xs">
            <span className="text-2xl mb-2">⚡</span>
            <span>Awaiting telemetry stream frames over WebSocket...</span>
            <span className="text-[10px] text-slate-600 mt-1">Use the Traffic Simulator to inject live bursts</span>
          </div>
        ) : (
          <div style={{ height: `${totalHeight}px`, width: '100%', position: 'relative' }}>
            {visibleRows.map(({ top, log, index }) => {
              const sev = severityStyles[log.severity_id] || severityStyles[0]
              const timeStr = log.time ? new Date(log.time).toLocaleTimeString() : 'LIVE'

              return (
                <div
                  key={index}
                  style={{
                    position: 'absolute',
                    top: 0,
                    left: 0,
                    width: '100%',
                    height: `${ROW_HEIGHT}px`,
                    transform: `translateY(${top}px)`,
                  }}
                  className="flex gap-3 font-mono text-[11px] items-center whitespace-nowrap px-2 py-0.5 hover:bg-base-900/80 border-b border-base-900/40"
                >
                  <span className="text-slate-500 w-16 shrink-0">{timeStr}</span>
                  <span className="text-emerald-400 font-semibold w-36 shrink-0 truncate">
                    [{log.device?.hostname || 'unknown-host'}]
                  </span>
                  <span className={`px-1.5 py-0.5 rounded text-[9px] border shrink-0 ${sev.badge}`}>
                    {log.class_name || 'OCSF'}
                  </span>
                  <span className={`overflow-hidden text-ellipsis ${sev.text}`}>
                    {log.message}
                  </span>
                </div>
              )
            })}
          </div>
        )}
      </div>

      {/* Terminal Footer */}
      <div className="pt-2.5 border-t border-base-800/80 flex justify-between items-center text-[10px] text-slate-500">
        <div>
          <span>Sliding Window: </span>
          <span className="text-cyan-400 font-bold">{filteredLogs.length} events</span>
          {searchQuery && <span className="text-amber-400 ml-2">(filtered from {logs.length})</span>}
        </div>
        <div className="flex items-center gap-3">
          <span>Protocol: <strong className="text-slate-300">RFC-6455 WebSockets</strong></span>
          <span>SLA: <strong className="text-emerald-400">&lt; 1.0 ms Frame Delay</strong></span>
        </div>
      </div>
    </div>
  )
}
