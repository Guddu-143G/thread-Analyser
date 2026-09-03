import React, { useEffect, useState, useCallback } from 'react'
import client from '../api/client'


export default function LogExplorer() {
  const [events, setEvents] = useState([])
  const [loading, setLoading] = useState(true)
  const [searchQuery, setSearchQuery] = useState('')
  const [selectedEventType, setSelectedEventType] = useState('')
  const [selectedIP, setSelectedIP] = useState('')
  const [selectedUser, setSelectedUser] = useState('')
  const [expandedEventId, setExpandedEventId] = useState(null)
  const [limit] = useState(50)
  const [offset, setOffset] = useState(0)

  const loadEvents = useCallback(() => {
    setLoading(true)
    const params = { limit, offset }
    if (searchQuery) params.search = searchQuery
    if (selectedEventType) params.event_type = selectedEventType
    if (selectedIP) params.src_ip = selectedIP
    if (selectedUser) params.user = selectedUser

    client
      .get('/events', { params })
      .then(({ data }) => setEvents(data))
      .finally(() => setLoading(false))
  }, [searchQuery, selectedEventType, selectedIP, selectedUser, limit, offset])

  useEffect(() => {
    loadEvents()
  }, [loadEvents])

  const exportData = (format) => {
    if (events.length === 0) return
    if (format === 'json') {
      const blob = new Blob([JSON.stringify(events, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `threat-analyser-logs-${Date.now()}.json`
      a.click()
    } else if (format === 'csv') {
      const headers = ['id', 'ts', 'event_type', 'src_ip', 'dest_ip', 'user', 'process', 'raw']
      const csvRows = [
        headers.join(','),
        ...events.map((e) =>
          headers
            .map((h) => {
              const val = e[h] ?? ''
              return `"${String(val).replace(/"/g, '""')}"`
            })
            .join(',')
        ),
      ]
      const blob = new Blob([csvRows.join('\n')], { type: 'text/csv' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `threat-analyser-logs-${Date.now()}.csv`
      a.click()
    }
  }

  const resetFilters = () => {
    setSearchQuery('')
    setSelectedEventType('')
    setSelectedIP('')
    setSelectedUser('')
    setOffset(0)
  }

  return (
    <div className="space-y-4">
      {/* Header & Export Actions */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <span>Log Explorer &amp; Threat Hunting</span>
            <span className="text-xs font-mono bg-base-800 text-slate-300 px-2 py-0.5 rounded border border-base-700">
              Forensic Query
            </span>
          </h1>
          <p className="text-slate-400 text-xs mt-0.5">Explore, search, and analyze normalized security events across all enterprise endpoints</p>
        </div>

        <div className="flex items-center gap-2">
          <button onClick={() => exportData('json')} className="btn-secondary text-xs px-3 py-1.5 font-mono">
            Export JSON
          </button>
          <button onClick={() => exportData('csv')} className="btn-secondary text-xs px-3 py-1.5 font-mono">
            Export CSV
          </button>
        </div>
      </div>

      {/* Forensic Search & Filter Bar */}
      <div className="bg-base-900 border border-base-700 rounded-lg p-4 space-y-3">
        <div className="flex gap-3">
          <div className="flex-1 relative">
            <input
              type="text"
              className="input-field pl-8 text-xs font-mono"
              placeholder="Search raw payloads, command lines, binaries, IP addresses, or usernames..."
              value={searchQuery}
              onChange={(e) => {
                setSearchQuery(e.target.value)
                setOffset(0)
              }}
            />
            <span className="absolute left-2.5 top-2.5 text-slate-500 text-xs">🔍</span>
          </div>
          <button onClick={loadEvents} className="btn-primary text-xs px-4 py-2 font-medium">
            Search
          </button>
          {(searchQuery || selectedEventType || selectedIP || selectedUser) && (
            <button onClick={resetFilters} className="btn-secondary text-xs px-3 py-2 text-rose-400">
              Clear Filters
            </button>
          )}
        </div>

        {/* Quick Filter Selectors */}
        <div className="flex flex-wrap items-center gap-3 pt-1 border-t border-base-800 text-xs">
          <span className="text-slate-500 font-mono text-[11px] uppercase">Quick Filters:</span>
          
          <input
            className="input-field w-36 text-xs py-1 font-mono"
            placeholder="Filter Source IP"
            value={selectedIP}
            onChange={(e) => setSelectedIP(e.target.value)}
          />

          <input
            className="input-field w-36 text-xs py-1 font-mono"
            placeholder="Filter Username"
            value={selectedUser}
            onChange={(e) => setSelectedUser(e.target.value)}
          />

          <input
            className="input-field w-40 text-xs py-1 font-mono"
            placeholder="Filter Event Type"
            value={selectedEventType}
            onChange={(e) => setSelectedEventType(e.target.value)}
          />

          <span className="text-slate-500 text-[11px] font-mono ml-auto">
            Showing events {offset + 1} - {offset + events.length}
          </span>
        </div>
      </div>

      {/* Forensic Log Data Grid */}
      <div className="panel overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-base-950/80 border-b border-base-700 text-slate-400 uppercase text-[10px] tracking-wider">
              <tr>
                <th className="py-3 px-4 w-44">Timestamp (UTC)</th>
                <th className="py-3 px-3 w-32">Event Type</th>
                <th className="py-3 px-3 w-28">User</th>
                <th className="py-3 px-3 w-32">Source IP</th>
                <th className="py-3 px-3 w-32">Dest IP</th>
                <th className="py-3 px-3 w-40">Process / Target</th>
                <th className="py-3 px-4">Raw Log Payload</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-base-700/60 text-slate-300">
              {loading && (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500 font-sans text-sm">
                    Loading security events…
                  </td>
                </tr>
              )}
              {!loading && events.length === 0 && (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500 font-sans text-sm">
                    No log events found matching the search criteria.
                  </td>
                </tr>
              )}
              {events.map((e) => {
                const isExpanded = expandedEventId === e.id
                return (
                  <React.Fragment key={e.id}>
                    <tr
                      onClick={() => setExpandedEventId(isExpanded ? null : e.id)}
                      className={`cursor-pointer transition-colors hover:bg-base-800/80 ${
                        isExpanded ? 'bg-base-800 border-l-2 border-l-accent' : ''
                      }`}
                    >
                      <td className="py-2.5 px-4 text-slate-400 whitespace-nowrap">
                        {new Date(e.ts).toISOString().replace('T', ' ').slice(0, 19)}
                      </td>
                      <td className="py-2.5 px-3">
                        <span className="bg-base-950 text-accent px-1.5 py-0.5 rounded border border-base-700 text-[11px]">
                          {e.event_type || 'generic'}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 font-semibold text-slate-200">
                        {e.user || <span className="text-slate-600">-</span>}
                      </td>
                      <td className="py-2.5 px-3 text-cyan-400">
                        {e.src_ip || <span className="text-slate-600">-</span>}
                      </td>
                      <td className="py-2.5 px-3 text-indigo-400">
                        {e.dest_ip || <span className="text-slate-600">-</span>}
                      </td>
                      <td className="py-2.5 px-3 text-amber-300/90 truncate max-w-[160px]">
                        {e.process || <span className="text-slate-600">-</span>}
                      </td>
                      <td className="py-2.5 px-4 text-slate-400 truncate max-w-md font-mono text-[11px]">
                        {e.raw}
                      </td>
                    </tr>

                    {/* Expandable Forensic Deep Inspector */}
                    {isExpanded && (
                      <tr className="bg-base-950/90">
                        <td colSpan={7} className="p-4 border-t border-b border-base-700">
                          <div className="space-y-3 font-sans">
                            <div className="flex items-center justify-between text-xs font-mono text-slate-400">
                              <span className="text-accent font-semibold">◈ OCSF Normalized Event &amp; Full Raw Payload</span>
                              <span>ID: {e.id}</span>
                            </div>

                            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                              <div>
                                <span className="text-[11px] font-mono text-slate-500 uppercase block mb-1">Raw Log Record</span>
                                <pre className="bg-base-900 border border-base-700 rounded p-2.5 text-xs text-slate-300 font-mono overflow-x-auto whitespace-pre-wrap">
                                  {e.raw}
                                </pre>
                              </div>

                              <div>
                                <span className="text-[11px] font-mono text-slate-500 uppercase block mb-1">OCSF Structured Metadata</span>
                                <pre className="bg-base-900 border border-base-700 rounded p-2.5 text-xs text-emerald-400 font-mono overflow-x-auto max-h-48">
                                  {JSON.stringify(e.normalized || {}, null, 2)}
                                </pre>
                              </div>
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                )
              })}
            </tbody>
          </table>
        </div>

        {/* Pagination Bar */}
        <div className="p-3 bg-base-950/60 border-t border-base-700 flex items-center justify-between text-xs text-slate-400 font-mono">
          <div>
            Showing page {Math.floor(offset / limit) + 1}
          </div>
          <div className="flex items-center gap-2">
            <button
              disabled={offset === 0 || loading}
              onClick={() => setOffset(Math.max(0, offset - limit))}
              className="btn-secondary text-xs px-3 py-1 disabled:opacity-40"
            >
              ← Previous
            </button>
            <button
              disabled={events.length < limit || loading}
              onClick={() => setOffset(offset + limit)}
              className="btn-secondary text-xs px-3 py-1 disabled:opacity-40"
            >
              Next →
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
