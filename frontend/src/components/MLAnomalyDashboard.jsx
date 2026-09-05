import React, { useState, useEffect, useRef } from 'react';

export default function MLAnomalyDashboard({ modelDetails, onRetrain, onSimulate, isActionLoading }) {
  const [activeTab, setActiveTab] = useState('evaluator'); // 'evaluator' | 'baselines' | 'runs' | 'stream'
  const [wsConnected, setWsConnected] = useState(false);
  const [streamEvents, setStreamEvents] = useState([]);
  const wsRef = useRef(null);

  // Live Evaluator Form State
  const [telemetryInput, setTelemetryInput] = useState({
    request_rate_1m: 24.5,
    request_rate_5m: 110.0,
    failed_auth_count: 0,
    payload_entropy: 3.1,
    unusual_port_flag: 0,
    geo_distance_km: 85.0,
    packet_size_variance: 160.0,
    token_anomaly_score: 0.08,
    session_duration_sec: 320.0,
    concurrent_sessions: 1
  });

  const [evaluationResult, setEvaluationResult] = useState(null);
  const [evalLoading, setEvalLoading] = useState(false);

  // Setup WebSocket connection
  useEffect(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host;
    const orgId = modelDetails?.org_id || 'default_org';
    const wsUrl = `${protocol}//${host}/api/v27/live-telemetry?org_id=${orgId}`;

    try {
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        setWsConnected(true);
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.type === 'EVALUATION_RESULT' || data.type === 'SIMULATION_TICK') {
            setStreamEvents((prev) => [data, ...prev.slice(0, 39)]);
          }
        } catch (e) {
          console.debug('WS parse error:', e);
        }
      };

      ws.onclose = () => {
        setWsConnected(false);
      };

      ws.onerror = () => {
        setWsConnected(false);
      };
    } catch (e) {
      console.debug('WS connection error:', e);
    }

    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, [modelDetails?.org_id]);

  const handleInputChange = (field, value) => {
    setTelemetryInput((prev) => ({
      ...prev,
      [field]: parseFloat(value) || 0
    }));
  };

  const handleEvaluate = async () => {
    setEvalLoading(true);
    try {
      const token = localStorage.getItem('ta_token') || localStorage.getItem('token');
      const res = await fetch('/api/v27/score', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { 'Authorization': `Bearer ${token}` } : {})
        },
        body: JSON.stringify(telemetryInput)
      });

      if (res.ok) {
        const data = await res.json();
        setEvaluationResult(data);
        // Also send through ws if connected
        if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
          wsRef.current.send(JSON.stringify({ type: 'EVALUATE', event: telemetryInput }));
        }
      }
    } catch (err) {
      console.error('Failed to score telemetry:', err);
    } finally {
      setEvalLoading(false);
    }
  };

  const loadPreset = (presetType) => {
    if (presetType === 'BENIGN_API_BURST') {
      setTelemetryInput({
        request_rate_1m: 45.0,
        request_rate_5m: 180.0,
        failed_auth_count: 0,
        payload_entropy: 3.2,
        unusual_port_flag: 0,
        geo_distance_km: 15.0,
        packet_size_variance: 220.0,
        token_anomaly_score: 0.04,
        session_duration_sec: 450.0,
        concurrent_sessions: 2
      });
    } else if (presetType === 'BRUTE_FORCE_EXFIL') {
      setTelemetryInput({
        request_rate_1m: 180.0,
        request_rate_5m: 750.0,
        failed_auth_count: 18,
        payload_entropy: 7.2,
        unusual_port_flag: 1,
        geo_distance_km: 8400.0,
        packet_size_variance: 1450.0,
        token_anomaly_score: 0.94,
        session_duration_sec: 12.0,
        concurrent_sessions: 14
      });
    } else if (presetType === 'CREDENTIAL_STUFFING') {
      setTelemetryInput({
        request_rate_1m: 95.0,
        request_rate_5m: 420.0,
        failed_auth_count: 24,
        payload_entropy: 4.8,
        unusual_port_flag: 0,
        geo_distance_km: 4200.0,
        packet_size_variance: 510.0,
        token_anomaly_score: 0.82,
        session_duration_sec: 45.0,
        concurrent_sessions: 8
      });
    } else {
      // Normal Enterprise Baseline
      setTelemetryInput({
        request_rate_1m: 20.0,
        request_rate_5m: 95.0,
        failed_auth_count: 0,
        payload_entropy: 2.8,
        unusual_port_flag: 0,
        geo_distance_km: 40.0,
        packet_size_variance: 140.0,
        token_anomaly_score: 0.05,
        session_duration_sec: 300.0,
        concurrent_sessions: 1
      });
    }
  };

  const getSeverityBadgeClass = (severity) => {
    switch (severity) {
      case 'CRITICAL':
        return 'bg-rose-950/80 text-rose-300 border-rose-600/60 animate-pulse';
      case 'HIGH':
        return 'bg-amber-950/80 text-amber-300 border-amber-600/60';
      case 'MEDIUM':
        return 'bg-yellow-950/80 text-yellow-300 border-yellow-600/60';
      default:
        return 'bg-emerald-950/80 text-emerald-300 border-emerald-600/60';
    }
  };

  return (
    <div className="space-y-6 text-slate-200">
      {/* Top Banner: Pipeline Health & Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-base-900/90 border border-base-700/80 shadow-lg backdrop-blur flex items-center justify-between">
          <div>
            <div className="text-[11px] font-mono uppercase tracking-wider text-slate-400">ML Engine Status</div>
            <div className="text-xl font-bold font-mono text-cyan-400 flex items-center gap-2 mt-1">
              <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-ping"></span>
              {modelDetails?.status || 'ACTIVE'}
            </div>
            <div className="text-[10px] text-slate-500 font-mono mt-0.5">{modelDetails?.algorithm || 'IsolationForest'}</div>
          </div>
          <div className="text-2xl p-2.5 rounded-lg bg-cyan-950/60 border border-cyan-700/50 text-cyan-300">🤖</div>
        </div>

        <div className="p-4 rounded-xl bg-base-900/90 border border-base-700/80 shadow-lg backdrop-blur flex items-center justify-between">
          <div>
            <div className="text-[11px] font-mono uppercase tracking-wider text-slate-400">Trained Telemetry</div>
            <div className="text-xl font-bold font-mono text-indigo-300 mt-1">
              {modelDetails?.training_samples_count?.toLocaleString() || '150'} <span className="text-xs text-slate-400 font-normal">samples</span>
            </div>
            <div className="text-[10px] text-slate-500 font-mono mt-0.5">Neon Postgres + Realtime</div>
          </div>
          <div className="text-2xl p-2.5 rounded-lg bg-indigo-950/60 border border-indigo-700/50 text-indigo-300">📊</div>
        </div>

        <div className="p-4 rounded-xl bg-base-900/90 border border-base-700/80 shadow-lg backdrop-blur flex items-center justify-between">
          <div>
            <div className="text-[11px] font-mono uppercase tracking-wider text-slate-400">Contamination Rate</div>
            <div className="text-xl font-bold font-mono text-emerald-400 mt-1">
              {((modelDetails?.contamination || 0.05) * 100).toFixed(1)}%
            </div>
            <div className="text-[10px] text-slate-500 font-mono mt-0.5">Decision Boundary: [ -0.5, 0.5 ]</div>
          </div>
          <div className="text-2xl p-2.5 rounded-lg bg-emerald-950/60 border border-emerald-700/50 text-emerald-300">🎯</div>
        </div>

        <div className="p-4 rounded-xl bg-base-900/90 border border-base-700/80 shadow-lg backdrop-blur flex items-center justify-between">
          <div>
            <div className="text-[11px] font-mono uppercase tracking-wider text-slate-400">Live Telemetry Stream</div>
            <div className="text-xl font-bold font-mono text-teal-300 flex items-center gap-2 mt-1">
              <span className={`w-2.5 h-2.5 rounded-full ${wsConnected ? 'bg-teal-400 animate-pulse' : 'bg-rose-400'}`}></span>
              {wsConnected ? 'CONNECTED' : 'STANDBY'}
            </div>
            <div className="text-[10px] text-slate-500 font-mono mt-0.5">WebSocket v27.0</div>
          </div>
          <div className="text-2xl p-2.5 rounded-lg bg-teal-950/60 border border-teal-700/50 text-teal-300">⚡</div>
        </div>
      </div>

      {/* Action Bar */}
      <div className="p-4 rounded-xl bg-gradient-to-r from-base-900 via-base-900/95 to-base-900 border border-cyan-500/20 shadow-xl flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <span className="text-xl font-mono text-cyan-400">🧠</span>
          <div>
            <h3 className="text-sm font-semibold text-slate-100 font-mono">Self-Training Multi-Tenant ML Engine</h3>
            <p className="text-xs text-slate-400">Tenant-isolated Isolation Forest with RobustScaler and real-time PCA dimensionality reduction</p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={onSimulate}
            disabled={isActionLoading}
            className="px-3.5 py-1.5 rounded-lg bg-base-800 hover:bg-base-700 text-cyan-300 text-xs font-mono font-medium border border-cyan-600/40 transition-all flex items-center gap-1.5 shadow-sm hover:shadow-cyan-900/20"
          >
            <span>⚡</span>
            <span>Simulate Telemetry Burst</span>
          </button>

          <button
            onClick={onRetrain}
            disabled={isActionLoading}
            className="px-4 py-1.5 rounded-lg bg-gradient-to-r from-cyan-600 to-indigo-600 hover:from-cyan-500 hover:to-indigo-500 text-white text-xs font-mono font-bold shadow-lg shadow-cyan-950/50 transition-all flex items-center gap-1.5 disabled:opacity-50"
          >
            {isActionLoading ? (
              <>
                <span className="w-3 h-3 border-2 border-white border-t-transparent rounded-full animate-spin"></span>
                <span>Retraining Model...</span>
              </>
            ) : (
              <>
                <span>🔄</span>
                <span>Retrain Tenant Model</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Tabs Navigation */}
      <div className="flex border-b border-base-700/80 gap-2">
        <button
          onClick={() => setActiveTab('evaluator')}
          className={`px-4 py-2.5 text-xs font-mono font-semibold transition-all border-b-2 flex items-center gap-2 ${
            activeTab === 'evaluator'
              ? 'border-cyan-400 text-cyan-300 bg-cyan-950/30'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <span>🔬</span> Live Telemetry Evaluator
        </button>

        <button
          onClick={() => setActiveTab('baselines')}
          className={`px-4 py-2.5 text-xs font-mono font-semibold transition-all border-b-2 flex items-center gap-2 ${
            activeTab === 'baselines'
              ? 'border-indigo-400 text-indigo-300 bg-indigo-950/30'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <span>📐</span> Feature Baselines &amp; Weights ({modelDetails?.baselines?.length || 10})
        </button>

        <button
          onClick={() => setActiveTab('runs')}
          className={`px-4 py-2.5 text-xs font-mono font-semibold transition-all border-b-2 flex items-center gap-2 ${
            activeTab === 'runs'
              ? 'border-emerald-400 text-emerald-300 bg-emerald-950/30'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <span>📜</span> Model Training Runs ({modelDetails?.recent_runs?.length || 0})
        </button>

        <button
          onClick={() => setActiveTab('stream')}
          className={`px-4 py-2.5 text-xs font-mono font-semibold transition-all border-b-2 flex items-center gap-2 ${
            activeTab === 'stream'
              ? 'border-teal-400 text-teal-300 bg-teal-950/30'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <span>📡</span> Live Scored Stream Feed ({streamEvents.length})
        </button>
      </div>

      {/* Tab 1: Live Telemetry Evaluator & Decision Matrix */}
      {activeTab === 'evaluator' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Feature Inputs & Presets */}
          <div className="lg:col-span-7 space-y-4 p-5 rounded-xl bg-base-900/80 border border-base-700/80">
            <div className="flex items-center justify-between pb-3 border-b border-base-700/70">
              <div className="flex items-center gap-2">
                <span className="text-cyan-400 font-mono font-bold text-sm">Telemetry Vector Parameters</span>
                <span className="text-[10px] px-2 py-0.5 rounded bg-base-800 text-slate-400 font-mono">10 tracked dimensions</span>
              </div>

              {/* Presets */}
              <div className="flex gap-1.5">
                <button
                  onClick={() => loadPreset('BENIGN')}
                  className="px-2 py-1 text-[10px] font-mono rounded bg-base-800 hover:bg-base-700 text-emerald-300 border border-emerald-800/40"
                >
                  Baseline Normal
                </button>
                <button
                  onClick={() => loadPreset('BENIGN_API_BURST')}
                  className="px-2 py-1 text-[10px] font-mono rounded bg-base-800 hover:bg-base-700 text-cyan-300 border border-cyan-800/40"
                >
                  API Spike
                </button>
                <button
                  onClick={() => loadPreset('BRUTE_FORCE_EXFIL')}
                  className="px-2 py-1 text-[10px] font-mono rounded bg-base-800 hover:bg-base-700 text-rose-300 border border-rose-800/40"
                >
                  Exfil Attack
                </button>
                <button
                  onClick={() => loadPreset('CREDENTIAL_STUFFING')}
                  className="px-2 py-1 text-[10px] font-mono rounded bg-base-800 hover:bg-base-700 text-amber-300 border border-amber-800/40"
                >
                  Brute Force
                </button>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs font-mono">
              <div>
                <label className="text-slate-400 block mb-1">Request Rate (1 min): <span className="text-cyan-300 font-bold">{telemetryInput.request_rate_1m} req/s</span></label>
                <input
                  type="range"
                  min="0"
                  max="300"
                  step="1"
                  value={telemetryInput.request_rate_1m}
                  onChange={(e) => handleInputChange('request_rate_1m', e.target.value)}
                  className="w-full accent-cyan-400"
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Request Rate (5 min): <span className="text-cyan-300 font-bold">{telemetryInput.request_rate_5m} req/s</span></label>
                <input
                  type="range"
                  min="0"
                  max="1200"
                  step="5"
                  value={telemetryInput.request_rate_5m}
                  onChange={(e) => handleInputChange('request_rate_5m', e.target.value)}
                  className="w-full accent-cyan-400"
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Failed Auth Count: <span className="text-rose-300 font-bold">{telemetryInput.failed_auth_count}</span></label>
                <input
                  type="range"
                  min="0"
                  max="50"
                  step="1"
                  value={telemetryInput.failed_auth_count}
                  onChange={(e) => handleInputChange('failed_auth_count', e.target.value)}
                  className="w-full accent-rose-400"
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Payload Entropy (Shannon): <span className="text-amber-300 font-bold">{telemetryInput.payload_entropy}</span></label>
                <input
                  type="range"
                  min="0"
                  max="8.0"
                  step="0.1"
                  value={telemetryInput.payload_entropy}
                  onChange={(e) => handleInputChange('payload_entropy', e.target.value)}
                  className="w-full accent-amber-400"
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Unusual Port Flag: <span className="text-indigo-300 font-bold">{telemetryInput.unusual_port_flag ? 'YES (1)' : 'NO (0)'}</span></label>
                <select
                  value={telemetryInput.unusual_port_flag}
                  onChange={(e) => handleInputChange('unusual_port_flag', e.target.value)}
                  className="w-full p-1.5 rounded bg-base-950 border border-base-700 text-slate-200"
                >
                  <option value={0}>0 - Standard Ports (80, 443, 22)</option>
                  <option value={1}>1 - Unusual High Port (4444, 1337, etc.)</option>
                </select>
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Geo Distance (km): <span className="text-teal-300 font-bold">{telemetryInput.geo_distance_km} km</span></label>
                <input
                  type="range"
                  min="0"
                  max="12000"
                  step="50"
                  value={telemetryInput.geo_distance_km}
                  onChange={(e) => handleInputChange('geo_distance_km', e.target.value)}
                  className="w-full accent-teal-400"
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Packet Size Variance: <span className="text-purple-300 font-bold">{telemetryInput.packet_size_variance}</span></label>
                <input
                  type="range"
                  min="0"
                  max="3000"
                  step="20"
                  value={telemetryInput.packet_size_variance}
                  onChange={(e) => handleInputChange('packet_size_variance', e.target.value)}
                  className="w-full accent-purple-400"
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Token Anomaly Score: <span className="text-rose-300 font-bold">{telemetryInput.token_anomaly_score}</span></label>
                <input
                  type="range"
                  min="0"
                  max="1.0"
                  step="0.01"
                  value={telemetryInput.token_anomaly_score}
                  onChange={(e) => handleInputChange('token_anomaly_score', e.target.value)}
                  className="w-full accent-rose-400"
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Session Duration (sec): <span className="text-slate-300 font-bold">{telemetryInput.session_duration_sec}s</span></label>
                <input
                  type="range"
                  min="1"
                  max="3600"
                  step="10"
                  value={telemetryInput.session_duration_sec}
                  onChange={(e) => handleInputChange('session_duration_sec', e.target.value)}
                  className="w-full accent-slate-400"
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Concurrent Sessions: <span className="text-slate-300 font-bold">{telemetryInput.concurrent_sessions}</span></label>
                <input
                  type="range"
                  min="1"
                  max="30"
                  step="1"
                  value={telemetryInput.concurrent_sessions}
                  onChange={(e) => handleInputChange('concurrent_sessions', e.target.value)}
                  className="w-full accent-slate-400"
                />
              </div>
            </div>

            <div className="pt-3 border-t border-base-700 flex justify-end">
              <button
                onClick={handleEvaluate}
                disabled={evalLoading}
                className="px-6 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-mono font-bold text-xs shadow-lg shadow-cyan-900/30 transition-all flex items-center gap-2"
              >
                {evalLoading ? (
                  <>
                    <span className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin"></span>
                    <span>Scoring Telemetry...</span>
                  </>
                ) : (
                  <>
                    <span>⚡</span>
                    <span>Run ML Anomaly Inference</span>
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Inference Output & PCA Space */}
          <div className="lg:col-span-5 space-y-4">
            {/* Score Card */}
            <div className="p-5 rounded-xl bg-base-900/80 border border-base-700/80 shadow-xl">
              <h4 className="text-xs uppercase font-mono tracking-wider text-slate-400 mb-3 flex items-center justify-between">
                <span>Inference Diagnosis</span>
                {evaluationResult && (
                  <span className={`px-2.5 py-0.5 rounded text-[10px] font-mono font-bold border ${getSeverityBadgeClass(evaluationResult.severity)}`}>
                    {evaluationResult.severity}
                  </span>
                )}
              </h4>

              {evaluationResult ? (
                <div className="space-y-4">
                  {/* Gauge */}
                  <div className="p-4 rounded-lg bg-base-950/70 border border-base-700 text-center">
                    <div className="text-[11px] font-mono text-slate-400">ANOMALY CONFIDENCE SCORE</div>
                    <div className={`text-4xl font-black font-mono my-1 ${
                      evaluationResult.anomaly_score >= 0.65 ? 'text-rose-400' : 'text-emerald-400'
                    }`}>
                      {(evaluationResult.anomaly_score * 100).toFixed(1)}%
                    </div>
                    <div className="text-xs font-mono text-slate-400">
                      Classification: {evaluationResult.is_anomaly ? (
                        <span className="text-rose-400 font-bold">⚠️ MALICIOUS ANOMALY DETECTED</span>
                      ) : (
                        <span className="text-emerald-400 font-bold">✓ BENIGN NORMAL TELEMETRY</span>
                      )}
                    </div>
                  </div>

                  {/* Top Features */}
                  <div>
                    <div className="text-[11px] font-mono uppercase text-slate-400 mb-2">Highest Deviating Feature Drivers</div>
                    <div className="space-y-1.5">
                      {evaluationResult.top_contributing_features?.map((fc, i) => (
                        <div key={i} className="p-2 rounded bg-base-950/50 border border-base-800 text-xs font-mono flex items-center justify-between">
                          <div>
                            <span className="text-slate-200 font-semibold">{fc.feature}</span>
                            <span className="text-slate-500 text-[10px] ml-2">val: {fc.value}</span>
                          </div>
                          <div className="flex items-center gap-2">
                            <span className="text-[10px] text-amber-400">Z: +{fc.z_score}σ</span>
                            <span className={`text-[9px] px-1.5 py-0.2 rounded border font-bold ${
                              fc.deviation_level === 'CRITICAL' ? 'bg-rose-950 text-rose-300 border-rose-700' :
                              fc.deviation_level === 'HIGH' ? 'bg-amber-950 text-amber-300 border-amber-700' :
                              'bg-slate-800 text-slate-400 border-slate-700'
                            }`}>
                              {fc.deviation_level}
                            </span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* 2D PCA Decision Space */}
                  <div className="p-3 rounded-lg bg-base-950 border border-base-800">
                    <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 mb-2">
                      <span>PCA 2D Decision Space</span>
                      <span className="text-cyan-400 text-[10px]">
                        [{evaluationResult.pca_coordinates?.[0]?.toFixed(2)}, {evaluationResult.pca_coordinates?.[1]?.toFixed(2)}]
                      </span>
                    </div>
                    <div className="h-28 w-full relative bg-base-900 rounded border border-base-800 flex items-center justify-center overflow-hidden">
                      {/* Grid Lines */}
                      <div className="absolute inset-0 grid grid-cols-4 grid-rows-2 opacity-20 pointer-events-none">
                        <div className="border-r border-b border-cyan-400"></div>
                        <div className="border-r border-b border-cyan-400"></div>
                        <div className="border-r border-b border-cyan-400"></div>
                        <div className="border-b border-cyan-400"></div>
                        <div className="border-r border-cyan-400"></div>
                        <div className="border-r border-cyan-400"></div>
                        <div className="border-r border-cyan-400"></div>
                        <div></div>
                      </div>
                      {/* Normal Baseline Cluster ellipse */}
                      <div className="w-24 h-16 rounded-full border border-emerald-500/40 bg-emerald-500/10 absolute"></div>
                      {/* Anomaly contour */}
                      <div className="w-48 h-24 rounded-full border border-dashed border-rose-500/30 absolute"></div>

                      {/* Current Point */}
                      <div
                        className={`w-3.5 h-3.5 rounded-full border-2 shadow-lg absolute transition-all ${
                          evaluationResult.is_anomaly
                            ? 'bg-rose-500 border-white shadow-rose-500/80 animate-ping'
                            : 'bg-emerald-400 border-white shadow-emerald-400/80'
                        }`}
                        style={{
                          transform: `translate(${Math.max(-80, Math.min(80, (evaluationResult.pca_coordinates?.[0] || 0) * 15))}px, ${Math.max(-40, Math.min(40, -(evaluationResult.pca_coordinates?.[1] || 0) * 15))}px)`
                        }}
                      ></div>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="py-12 text-center text-slate-500 font-mono text-xs">
                  <div className="text-2xl mb-2">⚡</div>
                  Click "Run ML Anomaly Inference" or select a preset to evaluate telemetry in real-time.
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Tab 2: Feature Baselines & Importance Weights */}
      {activeTab === 'baselines' && (
        <div className="p-5 rounded-xl bg-base-900/80 border border-base-700/80 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-base-700">
            <h3 className="text-sm font-mono font-bold text-indigo-300">Feature Baseline Distributions &amp; Statistical Weights</h3>
            <span className="text-xs text-slate-400 font-mono">Calculated on Neon Postgres Historical Telemetry</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {modelDetails?.baselines?.map((b) => (
              <div key={b.id} className="p-3.5 rounded-lg bg-base-950/70 border border-base-800 space-y-2">
                <div className="flex items-center justify-between text-xs font-mono">
                  <span className="text-slate-100 font-bold">{b.feature_name}</span>
                  <span className="text-indigo-400 font-semibold">Weight: {(b.importance_weight * 100).toFixed(1)}%</span>
                </div>

                {/* Progress bar for importance */}
                <div className="w-full h-1.5 bg-base-800 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-gradient-to-r from-indigo-500 to-cyan-400 rounded-full"
                    style={{ width: `${Math.min(100, b.importance_weight * 300)}%` }}
                  ></div>
                </div>

                <div className="grid grid-cols-3 gap-2 text-[10px] font-mono text-slate-400 pt-1 border-t border-base-800/80">
                  <div>Mean (μ): <span className="text-slate-200 font-semibold">{b.mean_value}</span></div>
                  <div>StdDev (σ): <span className="text-slate-200 font-semibold">{b.std_value}</span></div>
                  <div>Status: <span className="text-emerald-400 font-semibold">CALIBRATED</span></div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tab 3: Model Training Runs Audit */}
      {activeTab === 'runs' && (
        <div className="p-5 rounded-xl bg-base-900/80 border border-base-700/80 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-base-700">
            <h3 className="text-sm font-mono font-bold text-emerald-300">Historical Self-Training Pipeline Runs</h3>
            <span className="text-xs text-slate-400 font-mono">Celery &amp; Async Task Execution History</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-base-950 text-slate-400 uppercase text-[10px] tracking-wider border-b border-base-800">
                <tr>
                  <th className="p-3">Run ID</th>
                  <th className="p-3">Type</th>
                  <th className="p-3">Status</th>
                  <th className="p-3">Samples Used</th>
                  <th className="p-3">Duration</th>
                  <th className="p-3">Started At</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-base-800">
                {modelDetails?.recent_runs?.map((r) => (
                  <tr key={r.id} className="hover:bg-base-800/40">
                    <td className="p-3 text-cyan-300 font-mono">{r.id.slice(0, 8)}...</td>
                    <td className="p-3 text-slate-300">{r.run_type}</td>
                    <td className="p-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        r.status === 'SUCCESS' ? 'bg-emerald-950 text-emerald-300 border border-emerald-700' : 'bg-rose-950 text-rose-300 border border-rose-700'
                      }`}>
                        {r.status}
                      </span>
                    </td>
                    <td className="p-3 text-slate-200">{r.samples_used}</td>
                    <td className="p-3 text-amber-300">{r.training_duration_sec}s</td>
                    <td className="p-3 text-slate-400">{r.started_at ? new Date(r.started_at).toLocaleString() : 'N/A'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Tab 4: Live WebSocket Stream Feed */}
      {activeTab === 'stream' && (
        <div className="p-5 rounded-xl bg-base-900/80 border border-base-700/80 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-base-700">
            <div className="flex items-center gap-2">
              <span className={`w-2.5 h-2.5 rounded-full ${wsConnected ? 'bg-teal-400 animate-pulse' : 'bg-rose-400'}`}></span>
              <h3 className="text-sm font-mono font-bold text-teal-300">Live Telemetry Ingestion &amp; Score Feed</h3>
            </div>
            <button
              onClick={() => setStreamEvents([])}
              className="px-2.5 py-1 text-[10px] font-mono rounded bg-base-800 hover:bg-base-700 text-slate-300"
            >
              Clear Buffer
            </button>
          </div>

          <div className="space-y-2 max-h-96 overflow-y-auto pr-1">
            {streamEvents.length === 0 ? (
              <div className="py-12 text-center text-slate-500 font-mono text-xs">
                No streamed telemetry events received yet. Click "Simulate Telemetry Burst" or run tests in the evaluator.
              </div>
            ) : (
              streamEvents.map((evt, idx) => {
                const evalData = evt.evaluation || {};
                const isAnom = evalData.is_anomaly;
                return (
                  <div
                    key={idx}
                    className={`p-3 rounded-lg border text-xs font-mono transition-all flex items-center justify-between ${
                      isAnom
                        ? 'bg-rose-950/40 border-rose-700/70 text-rose-200'
                        : 'bg-base-950/70 border-base-800 text-slate-300'
                    }`}
                  >
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          isAnom ? 'bg-rose-900 text-rose-200' : 'bg-emerald-950 text-emerald-300'
                        }`}>
                          {isAnom ? 'ANOMALY' : 'BENIGN'}
                        </span>
                        <span className="font-bold text-slate-100">
                          Score: {((evalData.anomaly_score || 0) * 100).toFixed(1)}%
                        </span>
                        <span className="text-[10px] text-slate-400">
                          Boundary: {evalData.decision_boundary}
                        </span>
                      </div>
                      <div className="text-[10px] text-slate-400 truncate max-w-lg">
                        req_1m: {evt.raw_event?.request_rate_1m} | failed_auth: {evt.raw_event?.failed_auth_count} | entropy: {evt.raw_event?.payload_entropy} | geo: {evt.raw_event?.geo_distance_km}km
                      </div>
                    </div>

                    <div className="text-right">
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${getSeverityBadgeClass(evalData.severity)}`}>
                        {evalData.severity || 'LOW'}
                      </span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>
      )}
    </div>
  );
}
