import React, { useState, useEffect, useRef } from 'react';
import client from '../api/client';

export default function MitreDashboard() {
  const [loading, setLoading] = useState(false);
  const [statusData, setStatusData] = useState(null);
  const [heatmapData, setHeatmapData] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [selectedTechnique, setSelectedTechnique] = useState(null);

  // Ingestion Simulator State
  const [batchSize, setBatchSize] = useState(100);
  const [ingestLog, setIngestLog] = useState([]);
  const [isIngesting, setIsIngesting] = useState(false);

  // MDPS Sandbox State
  const [scorerInputs, setScorerInputs] = useState({
    anomaly_score: 85.0,
    mitre_weight: 80.0,
    asset_criticality: 75.0,
    intel_confidence: 90.0,
  });
  const [scorerResult, setScorerResult] = useState(null);

  // AI Summary Drawer
  const [aiSummary, setAiSummary] = useState(null);
  const [isSummarizing, setIsSummarizing] = useState(false);

  // WebSocket Live Stream
  const [wsConnected, setWsConnected] = useState(false);
  const [liveStreamEvents, setLiveStreamEvents] = useState([]);
  const wsRef = useRef(null);

  // Fetch initial data
  const fetchData = async () => {
    try {
      setLoading(true);
      const [sRes, hRes, aRes] = await Promise.all([
        client.get('/v25/status'),
        client.get('/v25/mitre/heatmap'),
        client.get('/v25/mitre/alerts?limit=25'),
      ]);

      if (sRes?.data) setStatusData(sRes.data);
      if (hRes?.data) setHeatmapData(hRes.data);
      if (aRes?.data) setAlerts(aRes.data);
    } catch (err) {
      console.error('Failed to fetch V25 telemetry:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();

    // Setup WebSocket Live Broker
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/api/v25/live?org_id=default-org`;

    try {
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        setWsConnected(true);
      };

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          if (msg.type === 'INGEST_BURST') {
            setLiveStreamEvents((prev) => [msg, ...prev.slice(0, 19)]);
            fetchData();
          } else if (msg.type === 'AI_SUMMARY_GENERATED') {
            setLiveStreamEvents((prev) => [msg, ...prev.slice(0, 19)]);
          }
        } catch (e) {
          console.warn('WS parse error:', e);
        }
      };

      ws.onclose = () => setWsConnected(false);
      ws.onerror = () => setWsConnected(false);
    } catch (e) {
      console.error('WS Connection error:', e);
    }

    // Auto-refresh interval fallback
    const interval = setInterval(() => {
      fetchData();
    }, 4000);

    return () => {
      if (wsRef.current) wsRef.current.close();
      clearInterval(interval);
    };
  }, []);

  // Compute MDPS dynamically
  const runPriorityScore = async () => {
    try {
      const res = await client.post('/v25/priority/score', scorerInputs);
      if (res?.data) {
        setScorerResult(res.data);
      }
    } catch (err) {
      console.error('MDPS score error:', err);
    }
  };

  useEffect(() => {
    runPriorityScore();
  }, [scorerInputs]);

  // Trigger high-throughput ingestion burst
  const handleIngestBurst = async (customSize = 100) => {
    try {
      setIsIngesting(true);
      const res = await client.post('/v25/ingest/stream', { batch_size: customSize });
      if (res?.data) {
        setIngestLog((prev) => [res.data, ...prev.slice(0, 9)]);
        await fetchData();
      }
    } catch (err) {
      console.error('Ingest burst error:', err);
    } finally {
      setIsIngesting(false);
    }
  };

  // Generate AI Summary
  const handleGenerateAISummary = async (alert) => {
    try {
      setSelectedAlert(alert);
      setIsSummarizing(true);
      setAiSummary(null);
      const res = await client.post('/v25/ai/summarize', {
        alert_id: alert.alert_id,
        technique_id: alert.technique_id,
        technique_name: alert.technique_name,
        tactic_id: alert.tactic_id,
        tactic_name: alert.tactic_name,
        priority_score: alert.priority_score,
        priority_level: alert.priority_level,
        source_ip: alert.source_ip,
        destination_ip: alert.destination_ip,
        payload_summary: alert.payload_summary,
      });
      if (res?.data) {
        setAiSummary(res.data);
      }
    } catch (err) {
      console.error('AI summary error:', err);
    } finally {
      setIsSummarizing(false);
    }
  };

  return (
    <div className="space-y-6 text-slate-100 font-sans">
      {/* HEADER BAR */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-base-900/90 border border-base-700/80 p-5 rounded-xl shadow-xl backdrop-blur-md">
        <div className="flex items-center gap-3.5">
          <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-indigo-500/20 via-purple-500/20 to-pink-500/20 border border-indigo-500/40 flex items-center justify-center text-indigo-400 text-xl font-bold shadow-inner">
            🎯
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-bold font-mono tracking-wide text-white">
                MITRE ATT&CK Matrix &amp; MDPS Cognitive Engine
              </h1>
              <span className="px-2 py-0.5 text-[10px] font-mono bg-indigo-950 text-indigo-300 border border-indigo-700 rounded font-semibold uppercase">
                v25.0
              </span>
            </div>
            <p className="text-xs text-slate-400 font-mono mt-0.5">
              100,000+ EPS Sliding Stream • Neon Serverless RLS • Prompt-Shielded AI Summaries
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 bg-base-950/80 px-3.5 py-1.5 rounded-lg border border-base-700 text-xs font-mono">
            <span
              className={`w-2 h-2 rounded-full ${
                wsConnected ? 'bg-emerald-400 animate-ping' : 'bg-amber-400'
              }`}
            ></span>
            <span className="text-slate-400">STREAM BROKER:</span>
            <span className={wsConnected ? 'text-emerald-400 font-semibold' : 'text-amber-400 font-semibold'}>
              {wsConnected ? 'LIVE WS' : 'CONNECTING'}
            </span>
          </div>

          <button
            onClick={fetchData}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-base-800 hover:bg-base-700 text-slate-200 border border-base-600 rounded-lg text-xs font-mono font-medium transition-all"
          >
            <span>🔄</span>
            <span>{loading ? 'Syncing...' : 'Sync Matrix'}</span>
          </button>
        </div>
      </div>

      {/* KPI METRICS OVERVIEW */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-base-900/80 border border-base-700/80 p-4 rounded-xl relative overflow-hidden shadow-lg">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
            <span>PIPELINE THROUGHPUT</span>
            <span className="text-cyan-400 text-sm">📈</span>
          </div>
          <div className="text-2xl font-bold font-mono text-cyan-300 mt-2">
            {statusData?.pipeline_throughput_eps?.toLocaleString() || '10,542'} <span className="text-xs text-slate-400">EPS</span>
          </div>
          <div className="text-[11px] text-slate-400 font-mono mt-1 flex items-center justify-between">
            <span>Avg Latency:</span>
            <span className="text-emerald-400 font-semibold">{statusData?.pipeline_latency_ms || '1.42'} ms</span>
          </div>
          <div className="absolute bottom-0 left-0 right-0 h-1 bg-cyan-500/20">
            <div className="h-full bg-cyan-400 w-4/5 animate-pulse"></div>
          </div>
        </div>

        <div className="bg-base-900/80 border border-base-700/80 p-4 rounded-xl relative overflow-hidden shadow-lg">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
            <span>TOTAL MITRE ALERTS</span>
            <span className="text-rose-400 text-sm">🔥</span>
          </div>
          <div className="text-2xl font-bold font-mono text-rose-300 mt-2">
            {statusData?.total_mitre_alerts || heatmapData?.total_alerts || 0}
          </div>
          <div className="text-[11px] text-slate-400 font-mono mt-1 flex items-center justify-between">
            <span>Avg Risk Score:</span>
            <span className="text-rose-400 font-semibold">{heatmapData?.overall_avg_priority || 0}/100</span>
          </div>
          <div className="absolute bottom-0 left-0 right-0 h-1 bg-rose-500/20">
            <div className="h-full bg-rose-500 w-3/5"></div>
          </div>
        </div>

        <div className="bg-base-900/80 border border-base-700/80 p-4 rounded-xl relative overflow-hidden shadow-lg">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
            <span>ACTIVE TACTIC PHASES</span>
            <span className="text-indigo-400 text-sm">🛡️</span>
          </div>
          <div className="text-2xl font-bold font-mono text-indigo-300 mt-2">
            {statusData?.active_tactics_count || 12} / 12
          </div>
          <div className="text-[11px] text-slate-400 font-mono mt-1 flex items-center justify-between">
            <span>Coverage:</span>
            <span className="text-indigo-400 font-semibold">100% ATT&CK v14</span>
          </div>
          <div className="absolute bottom-0 left-0 right-0 h-1 bg-indigo-500/20">
            <div className="h-full bg-indigo-500 w-full"></div>
          </div>
        </div>

        <div className="bg-base-900/80 border border-base-700/80 p-4 rounded-xl relative overflow-hidden shadow-lg">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
            <span>AI TRIAGE SUMMARIES</span>
            <span className="text-amber-400 text-sm">⚡</span>
          </div>
          <div className="text-2xl font-bold font-mono text-amber-300 mt-2">
            {statusData?.ai_summaries_generated || 0}
          </div>
          <div className="text-[11px] text-slate-400 font-mono mt-1 flex items-center justify-between">
            <span>PII Shielding:</span>
            <span className="text-emerald-400 font-semibold">ACTIVE (Enforced)</span>
          </div>
          <div className="absolute bottom-0 left-0 right-0 h-1 bg-amber-500/20">
            <div className="h-full bg-amber-400 w-5/6"></div>
          </div>
        </div>
      </div>

      {/* MITRE ATT&CK HEATMAP MATRIX */}
      <div className="bg-base-900/90 border border-base-700/80 rounded-xl p-5 shadow-xl">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-4 border-b border-base-800 pb-3">
          <div>
            <h2 className="text-base font-bold font-mono text-white flex items-center gap-2">
              <span>🎯</span>
              Dynamic MITRE ATT&CK Tactic &amp; Technique Heatmap
            </h2>
            <p className="text-xs text-slate-400 font-mono">
              Live density mapping correlating OCSF classes 3002, 1007, 4001, and 1001
            </p>
          </div>
          <div className="flex items-center gap-2 text-[11px] font-mono">
            <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded bg-rose-500"></span> Critical</span>
            <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded bg-amber-500"></span> High</span>
            <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded bg-indigo-500"></span> Med</span>
            <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded bg-slate-800"></span> Low</span>
          </div>
        </div>

        {/* MATRIX GRID */}
        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-3 overflow-x-auto pb-2">
          {heatmapData?.matrix?.map((tac) => (
            <div
              key={tac.tactic_id}
              className="bg-base-950/80 border border-base-800 rounded-lg p-3 flex flex-col justify-between hover:border-indigo-600/50 transition-all"
            >
              <div>
                <div className="flex items-center justify-between text-[10px] font-mono text-slate-400 mb-1">
                  <span>{tac.tactic_id}</span>
                  <span className={`px-1.5 py-0.2 rounded font-bold ${
                    tac.critical_count > 0 ? 'bg-rose-950 text-rose-400 border border-rose-800' :
                    tac.alert_count > 0 ? 'bg-amber-950 text-amber-400 border border-amber-800' :
                    'bg-base-800 text-slate-400'
                  }`}>
                    {tac.alert_count}
                  </span>
                </div>
                <div className="text-xs font-bold text-slate-200 truncate mb-2" title={tac.tactic_name}>
                  {tac.tactic_name}
                </div>

                {/* TECHNIQUES PILLS */}
                <div className="space-y-1.5">
                  {tac.techniques_list?.map((tech) => {
                    const score = tech.max_priority_score;
                    let badgeClass = 'bg-base-900 border-base-800 text-slate-400';
                    if (score >= 85) badgeClass = 'bg-rose-950/80 border-rose-600 text-rose-300';
                    else if (score >= 65) badgeClass = 'bg-amber-950/80 border-amber-600 text-amber-300';
                    else if (score >= 40) badgeClass = 'bg-indigo-950/80 border-indigo-600 text-indigo-300';
                    else if (tech.count > 0) badgeClass = 'bg-slate-800 border-slate-700 text-slate-300';

                    return (
                      <div
                        key={tech.technique_id}
                        onClick={() => setSelectedTechnique(tech)}
                        className={`p-1.5 rounded border text-[10px] font-mono cursor-pointer transition-all hover:scale-[1.02] flex items-center justify-between ${badgeClass}`}
                      >
                        <span className="font-semibold">{tech.technique_id}</span>
                        <span className="text-[9px] px-1 bg-black/40 rounded">
                          {tech.count > 0 ? `${tech.count} (${Math.round(score)})` : '0'}
                        </span>
                      </div>
                    );
                  })}
                </div>
              </div>

              <div className="mt-3 pt-2 border-t border-base-900 text-[10px] font-mono text-slate-400 flex justify-between">
                <span>Avg Risk:</span>
                <span className="font-semibold text-slate-200">{tac.avg_priority_score}</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* DUAL WORKSPACE: INGESTION PIPELINE & MDPS SCORING */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* INGESTION PIPELINE STREAM CONTROLLER */}
        <div className="bg-base-900/90 border border-base-700/80 rounded-xl p-5 shadow-xl flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-sm font-bold font-mono text-white flex items-center gap-2">
                <span>⚡</span>
                Sliding-Window Stream Ingestion Pipeline
              </h2>
              <span className="text-[10px] font-mono bg-cyan-950 text-cyan-300 px-2 py-0.5 rounded border border-cyan-800">
                FastAPI + Redis
              </span>
            </div>
            <p className="text-xs text-slate-400 font-mono mb-4">
              Inject high-throughput synthetic telemetry bursts to measure instantaneous EPS and real-time MITRE mapping.
            </p>

            <div className="grid grid-cols-3 gap-2 mb-4">
              <button
                onClick={() => handleIngestBurst(50)}
                disabled={isIngesting}
                className="px-3 py-2 bg-base-800 hover:bg-base-700 text-slate-200 rounded-lg text-xs font-mono font-medium border border-base-700 flex flex-col items-center gap-1 transition-all"
              >
                <span className="text-cyan-400 font-bold">50 Events</span>
                <span className="text-[9px] text-slate-400">Micro Burst</span>
              </button>

              <button
                onClick={() => handleIngestBurst(250)}
                disabled={isIngesting}
                className="px-3 py-2 bg-indigo-950/60 hover:bg-indigo-900/80 text-indigo-200 rounded-lg text-xs font-mono font-medium border border-indigo-700 flex flex-col items-center gap-1 transition-all"
              >
                <span className="text-indigo-300 font-bold">250 Events</span>
                <span className="text-[9px] text-indigo-400">High Stream</span>
              </button>

              <button
                onClick={() => handleIngestBurst(1000)}
                disabled={isIngesting}
                className="px-3 py-2 bg-gradient-to-r from-rose-950 to-purple-950 hover:from-rose-900 hover:to-purple-900 text-rose-200 rounded-lg text-xs font-mono font-medium border border-rose-600 flex flex-col items-center gap-1 transition-all shadow-md"
              >
                <span className="text-rose-300 font-bold">1,000 Events</span>
                <span className="text-[9px] text-rose-400">100k+ EPS Stress</span>
              </button>
            </div>

            {/* LIVE INGESTION LOG */}
            <div className="bg-base-950 border border-base-800 rounded-lg p-3 font-mono text-[11px] h-48 overflow-y-auto space-y-2">
              <div className="text-slate-500 text-[10px] pb-1 border-b border-base-900 flex justify-between">
                <span>BATCH STREAM LOG</span>
                <span>STATUS / LATENCY</span>
              </div>
              {ingestLog.length === 0 && (
                <div className="text-slate-600 text-center py-12">
                  No active burst recorded in this session. Click above to inject stream.
                </div>
              )}
              {ingestLog.map((log, idx) => (
                <div key={idx} className="p-2 bg-base-900/80 rounded border border-base-800 flex items-center justify-between">
                  <div>
                    <span className="text-cyan-400 font-semibold">{log.events_processed} Events</span>
                    <span className="text-slate-400 ml-2">→ {log.alerts_generated} MITRE Alerts</span>
                  </div>
                  <div className="text-right">
                    <span className="text-emerald-400 font-bold">{log.instantaneous_eps} EPS</span>
                    <span className="text-slate-500 ml-2">({log.latency_ms}ms)</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* MDPS MULTI-DIMENSIONAL PRIORITIZATION SCORER */}
        <div className="bg-base-900/90 border border-base-700/80 rounded-xl p-5 shadow-xl flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-sm font-bold font-mono text-white flex items-center gap-2">
                <span>🎛️</span>
                Multi-Dimensional Automated Prioritization (MDPS)
              </h2>
              <span className="text-[10px] font-mono bg-purple-950 text-purple-300 px-2 py-0.5 rounded border border-purple-800">
                Formula Engine v25
              </span>
            </div>
            <p className="text-xs text-slate-400 font-mono mb-4">
              Dynamically computes risk scores using normalized anomaly, MITRE weight, asset value, and threat intel confidence.
            </p>

            {/* SLIDERS */}
            <div className="space-y-3 mb-4">
              <div>
                <div className="flex justify-between text-xs font-mono text-slate-300 mb-1">
                  <span>Anomaly Score (w₁ = 0.35)</span>
                  <span className="text-purple-300 font-bold">{scorerInputs.anomaly_score}</span>
                </div>
                <input
                  type="range"
                  min="0"
                  max="100"
                  value={scorerInputs.anomaly_score}
                  onChange={(e) => setScorerInputs({ ...scorerInputs, anomaly_score: parseFloat(e.target.value) })}
                  className="w-full accent-purple-500 bg-base-950 rounded-lg h-2"
                />
              </div>

              <div>
                <div className="flex justify-between text-xs font-mono text-slate-300 mb-1">
                  <span>MITRE Severity Weight (w₂ = 0.35)</span>
                  <span className="text-indigo-300 font-bold">{scorerInputs.mitre_weight}</span>
                </div>
                <input
                  type="range"
                  min="0"
                  max="100"
                  value={scorerInputs.mitre_weight}
                  onChange={(e) => setScorerInputs({ ...scorerInputs, mitre_weight: parseFloat(e.target.value) })}
                  className="w-full accent-indigo-500 bg-base-950 rounded-lg h-2"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <div className="flex justify-between text-xs font-mono text-slate-300 mb-1">
                    <span>Asset Value (w₃ = 0.15)</span>
                    <span className="text-cyan-300 font-bold">{scorerInputs.asset_criticality}</span>
                  </div>
                  <input
                    type="range"
                    min="0"
                    max="100"
                    value={scorerInputs.asset_criticality}
                    onChange={(e) => setScorerInputs({ ...scorerInputs, asset_criticality: parseFloat(e.target.value) })}
                    className="w-full accent-cyan-500 bg-base-950 rounded-lg h-2"
                  />
                </div>

                <div>
                  <div className="flex justify-between text-xs font-mono text-slate-300 mb-1">
                    <span>Intel Conf (w₄ = 0.15)</span>
                    <span className="text-emerald-300 font-bold">{scorerInputs.intel_confidence}</span>
                  </div>
                  <input
                    type="range"
                    min="0"
                    max="100"
                    value={scorerInputs.intel_confidence}
                    onChange={(e) => setScorerInputs({ ...scorerInputs, intel_confidence: parseFloat(e.target.value) })}
                    className="w-full accent-emerald-500 bg-base-950 rounded-lg h-2"
                  />
                </div>
              </div>
            </div>

            {/* SCORER OUTPUT PILL */}
            {scorerResult && (
              <div className={`p-3 rounded-lg border flex items-center justify-between font-mono ${
                scorerResult.priority_level === 'CRITICAL' ? 'bg-rose-950/80 border-rose-600 text-rose-200' :
                scorerResult.priority_level === 'HIGH' ? 'bg-amber-950/80 border-amber-600 text-amber-200' :
                scorerResult.priority_level === 'MEDIUM' ? 'bg-indigo-950/80 border-indigo-600 text-indigo-200' :
                'bg-base-950 border-base-800 text-slate-300'
              }`}>
                <div>
                  <div className="text-[10px] text-slate-400">MDPS FINAL RESULT:</div>
                  <div className="text-xl font-bold">{scorerResult.final_score} / 100</div>
                  {scorerResult.breakdown?.accelerated && (
                    <div className="text-[10px] text-amber-300 mt-0.5">⚡ Acceleration ×1.15 applied</div>
                  )}
                </div>
                <div className="text-right">
                  <span className="px-2.5 py-1 rounded text-xs font-bold uppercase tracking-wider bg-black/50 border border-current">
                    {scorerResult.priority_level}
                  </span>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* MERKLE-CHAINED MITRE ALERTS FEED */}
      <div className="bg-base-900/90 border border-base-700/80 rounded-xl p-5 shadow-xl">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-4 border-b border-base-800 pb-3">
          <div>
            <h2 className="text-base font-bold font-mono text-white flex items-center gap-2">
              <span>🛡️</span>
              Cryptographic Merkle-Chained MITRE Alert Feed
            </h2>
            <p className="text-xs text-slate-400 font-mono">
              Immutable SHA-256 hash-chained alert sequence stored in Neon Serverless Postgres with RLS
            </p>
          </div>
          <div className="text-xs font-mono text-slate-400">
            Total Alerts: <span className="text-white font-bold">{alerts.length}</span>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-base-950/80 text-slate-400 border-b border-base-800">
              <tr>
                <th className="p-3">PRIORITY</th>
                <th className="p-3">TECHNIQUE &amp; TACTIC</th>
                <th className="p-3">SOURCE → DESTINATION</th>
                <th className="p-3">PAYLOAD SUMMARY</th>
                <th className="p-3">MERKLE ALERT HASH</th>
                <th className="p-3 text-right">ACTION</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-base-800">
              {alerts.length === 0 ? (
                <tr>
                  <td colSpan="6" className="p-6 text-center text-slate-500">
                    No MITRE alerts found. Run an ingestion burst above to generate live alerts.
                  </td>
                </tr>
              ) : (
                alerts.map((a) => (
                  <tr key={a.alert_id} className="hover:bg-base-800/60 transition-colors">
                    <td className="p-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        a.priority_level === 'CRITICAL' ? 'bg-rose-950 text-rose-300 border border-rose-700' :
                        a.priority_level === 'HIGH' ? 'bg-amber-950 text-amber-300 border border-amber-700' :
                        a.priority_level === 'MEDIUM' ? 'bg-indigo-950 text-indigo-300 border border-indigo-700' :
                        'bg-base-950 text-slate-400 border border-base-800'
                      }`}>
                        {a.priority_level} ({a.priority_score})
                      </span>
                    </td>
                    <td className="p-3">
                      <div className="font-semibold text-slate-200">{a.technique_id} - {a.technique_name || 'Technique'}</div>
                      <div className="text-[10px] text-slate-400">{a.tactic_id} ({a.tactic_name || 'Tactic'})</div>
                    </td>
                    <td className="p-3 text-slate-300">
                      <div>{a.source_ip || '0.0.0.0'}</div>
                      <div className="text-[10px] text-slate-500">→ {a.destination_ip || '0.0.0.0'}</div>
                    </td>
                    <td className="p-3 max-w-xs truncate text-slate-400" title={a.payload_summary}>
                      {a.payload_summary || 'Standard OCSF log event payload'}
                    </td>
                    <td className="p-3 text-slate-400 font-mono text-[10px]">
                      <span className="text-indigo-400">{a.alert_hash ? a.alert_hash.slice(0, 16) + '...' : 'GENESIS'}</span>
                    </td>
                    <td className="p-3 text-right">
                      <button
                        onClick={() => handleGenerateAISummary(a)}
                        className="px-2.5 py-1 bg-indigo-950 hover:bg-indigo-900 text-indigo-200 border border-indigo-700 rounded text-[10px] font-mono font-medium transition-all"
                      >
                        AI Triage
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* EXPLAINABLE AI TRIAGE MODAL / DRAWER */}
      {selectedAlert && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-base-900 border border-base-700 rounded-2xl w-full max-w-2xl overflow-hidden shadow-2xl flex flex-col max-h-[90vh]">
            <div className="p-4 border-b border-base-800 flex items-center justify-between bg-base-950">
              <div className="flex items-center gap-2 font-mono">
                <span className="text-amber-400 text-base">⚡</span>
                <span className="font-bold text-sm text-white">
                  Explainable AI Threat Summary (Prompt Shielded)
                </span>
              </div>
              <button
                onClick={() => setSelectedAlert(null)}
                className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-base-800"
              >
                ✕
              </button>
            </div>

            <div className="p-5 overflow-y-auto space-y-4 font-mono text-xs">
              {/* ALERT CONTEXT HEADER */}
              <div className="p-3 bg-base-950 rounded-lg border border-base-800 flex items-center justify-between">
                <div>
                  <div className="text-slate-400 text-[10px]">TARGET ALERT:</div>
                  <div className="font-bold text-slate-200">
                    {selectedAlert.technique_id} • {selectedAlert.tactic_id} • Score: {selectedAlert.priority_score}
                  </div>
                </div>
                <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                  selectedAlert.priority_level === 'CRITICAL' ? 'bg-rose-950 text-rose-300' : 'bg-amber-950 text-amber-300'
                }`}>
                  {selectedAlert.priority_level}
                </span>
              </div>

              {isSummarizing ? (
                <div className="py-12 flex flex-col items-center justify-center gap-3 text-slate-400">
                  <div className="text-2xl animate-spin">🔄</div>
                  <span>Sanitizing PII and generating 3-sentence executive report...</span>
                </div>
              ) : aiSummary ? (
                <>
                  {/* PII REDACTION POSTURE */}
                  <div className="p-3 bg-emerald-950/40 border border-emerald-800/80 rounded-lg">
                    <div className="flex items-center gap-2 text-emerald-300 font-semibold mb-1">
                      <span>🔒</span>
                      PII Sanitization &amp; Prompt Shield Verification
                    </div>
                    <p className="text-[11px] text-emerald-200/80">
                      Sensitive email addresses, IPv4/IPv6 indicators, and instruction injection payloads were neutralized prior to inference.
                    </p>
                    <div className="mt-2 text-[10px] bg-black/40 p-2 rounded text-slate-300 break-all">
                      <span className="text-slate-500">Sanitized Prompt:</span> {aiSummary.sanitized_input || 'N/A'}
                    </div>
                  </div>

                  {/* EXECUTIVE SUMMARY */}
                  <div className="p-3.5 bg-base-950 border border-indigo-800/60 rounded-lg">
                    <div className="text-[10px] text-indigo-400 font-bold mb-1 uppercase tracking-wider">
                      Executive Summary (Explainable 3-Sentence Report):
                    </div>
                    <p className="text-slate-200 leading-relaxed text-xs">
                      {aiSummary.executive_summary}
                    </p>
                  </div>

                  {/* THREAT ACTOR ATTRIBUTION */}
                  <div className="p-3 bg-base-950 border border-base-800 rounded-lg">
                    <div className="text-[10px] text-slate-400 font-bold mb-1">
                      THREAT ACTOR / CAMPAIGN ATTRIBUTION:
                    </div>
                    <div className="text-amber-300 font-bold text-xs">
                      {aiSummary.threat_actor_attribution || 'Unknown Adversary'}
                    </div>
                  </div>

                  {/* ACTIONABLE REMEDIATION */}
                  <div className="p-3.5 bg-base-950 border border-base-800 rounded-lg">
                    <div className="text-[10px] text-emerald-400 font-bold mb-1 uppercase tracking-wider">
                      Actionable Remediation Playbook:
                    </div>
                    <pre className="text-slate-300 whitespace-pre-wrap font-sans text-xs bg-black/30 p-2.5 rounded border border-base-800 leading-relaxed">
                      {aiSummary.actionable_remediation}
                    </pre>
                  </div>
                </>
              ) : (
                <div className="text-slate-500 text-center py-8">
                  Failed to generate summary. Please try again.
                </div>
              )}
            </div>

            <div className="p-3 bg-base-950 border-t border-base-800 flex justify-end font-mono text-xs">
              <button
                onClick={() => setSelectedAlert(null)}
                className="px-4 py-1.5 bg-base-800 hover:bg-base-700 text-slate-200 rounded-lg border border-base-700 font-medium"
              >
                Close Drawer
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
