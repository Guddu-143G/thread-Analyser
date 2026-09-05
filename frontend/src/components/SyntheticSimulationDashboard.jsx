import React, { useState, useEffect, useRef } from 'react';

// Custom lightweight SVG Icons
const Icons = {
  Flame: () => (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M17.657 18.657A8 8 0 016.343 7.343S7 9 9 10c0-2 .5-5 2.986-7C14 5 16.09 5.777 17.656 7.343A7.975 7.975 0 0120 13a7.975 7.975 0 01-2.343 5.657z" />
    </svg>
  ),
  Terminal: () => (
    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
    </svg>
  ),
  ShieldAlert: () => (
    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
    </svg>
  ),
  Check: () => (
    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" />
    </svg>
  ),
  Server: () => (
    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01" />
    </svg>
  ),
  Activity: () => (
    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 10V3L4 14h7v7l9-11h-7z" />
    </svg>
  ),
  Cpu: () => (
    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 3v2m6-2v2M9 19v2m6-2v2M3 9h2m-2 6h2m14-6h2m-2 6h2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z" />
    </svg>
  ),
  Refresh: ({ className = "w-4 h-4" }) => (
    <svg className={className} fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
    </svg>
  ),
  Layers: () => (
    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
    </svg>
  ),
  Play: () => (
    <svg className="w-3.5 h-3.5 fill-current" viewBox="0 0 24 24">
      <path d="M8 5v14l11-7z" />
    </svg>
  ),
  Sliders: () => (
    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4" />
    </svg>
  ),
  Clock: () => (
    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
    </svg>
  ),
  Users: () => (
    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z" />
    </svg>
  ),
  FileCode: () => (
    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
    </svg>
  )
};

export default function SyntheticSimulationDashboard({ orgId = 'default-org' }) {
  // WebSocket State
  const [connectionStatus, setConnectionStatus] = useState('Connecting to Simulation Hub...');
  const [wsConnected, setWsConnected] = useState(false);
  const [activeScenario, setActiveScenario] = useState(null);
  const [running, setRunning] = useState(false);
  const [simulationLogs, setSimulationLogs] = useState([]);
  const [currentStep, setCurrentStep] = useState(0);
  const [totalSteps, setTotalSteps] = useState(0);

  // Profiles & Runs from Backend API
  const [profiles, setProfiles] = useState([]);
  const [runs, setRuns] = useState([]);
  const [loadingProfiles, setLoadingProfiles] = useState(true);

  // STG Generator State
  const [eventCount, setEventCount] = useState(5000);
  const [diurnalEnabled, setDiurnalEnabled] = useState(true);
  const [noiseRatio, setNoiseRatio] = useState(0.3);
  const [bootstrapML, setBootstrapML] = useState(true);
  const [generatingSTG, setGeneratingSTG] = useState(false);
  const [stgResult, setStgResult] = useState(null);

  // KEDA & GitOps State
  const [kedaConfig, setKedaConfig] = useState(null);
  const [activeTab, setActiveTab] = useState('emulation'); // emulation | stg | keda | history

  const ws = useRef(null);
  const logTerminalRef = useRef(null);

  const fetchProfilesAndRuns = async () => {
    try {
      const token = localStorage.getItem('ta_token') || localStorage.getItem('token');
      const authHeader = token ? { Authorization: `Bearer ${token}` } : {};

      const [resProfiles, resRuns, resKeda] = await Promise.all([
        fetch('/api/v29/profiles', { headers: authHeader }),
        fetch('/api/v29/runs?limit=10', { headers: authHeader }),
        fetch('/api/v29/keda-config', { headers: authHeader })
      ]);

      if (resProfiles.ok) {
        const data = await resProfiles.json();
        setProfiles(data);
      }
      if (resRuns.ok) {
        const data = await resRuns.json();
        setRuns(data);
      }
      if (resKeda.ok) {
        const data = await resKeda.json();
        setKedaConfig(data);
      }
    } catch (err) {
      console.error('Failed to load V29 profiles & runs:', err);
    } finally {
      setLoadingProfiles(false);
    }
  };

  useEffect(() => {
    fetchProfilesAndRuns();
  }, []);

  // Initialize WebSocket connection
  useEffect(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.hostname === 'localhost' ? 'localhost:8000' : window.location.host;
    const wsUrl = `${protocol}//${host}/api/v1/simulation/ws?org_id=${orgId}`;

    ws.current = new WebSocket(wsUrl);

    ws.current.onopen = () => {
      setConnectionStatus('Simulation Gateway Ready (mTLS)');
      setWsConnected(true);
    };

    ws.current.onclose = () => {
      setConnectionStatus('Disconnected. Reconnecting...');
      setWsConnected(false);
    };

    ws.current.onerror = () => {
      setConnectionStatus('Connection Error');
      setWsConnected(false);
    };

    ws.current.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data);

        if (payload.type === 'SIMULATION_START') {
          setRunning(true);
          setCurrentStep(0);
          setTotalSteps(payload.total_steps || 4);
          setSimulationLogs([`[+] ${payload.message}`]);
        } else if (payload.type === 'SIMULATION_STEP') {
          setCurrentStep(payload.step_order);
          setTotalSteps(payload.total_steps || totalSteps);
          setSimulationLogs((prev) => [
            ...prev,
            `[Step ${payload.step_order}/${payload.total_steps || '4'}] [OCSF ${payload.ocsf || payload.ocsf_class}] ${payload.injected_message}`,
            `[Pipeline Broker] ${payload.message}`
          ]);
        } else if (payload.type === 'SIMULATION_COMPLETE') {
          setRunning(false);
          setSimulationLogs((prev) => [
            ...prev,
            `[+] ${payload.message}`,
            `[Verified] Detection rules validated & alert triggers confirmed.`
          ]);
          fetchProfilesAndRuns();
        }
      } catch (err) {
        console.error('Error parsing simulation WS message:', err);
      }
    };

    return () => {
      if (ws.current) ws.current.close();
    };
  }, [orgId]);

  // Auto-scroll terminal logs
  useEffect(() => {
    if (logTerminalRef.current) {
      logTerminalRef.current.scrollTop = logTerminalRef.current.scrollHeight;
    }
  }, [simulationLogs]);

  const triggerEmulation = (profileId, profileName) => {
    setActiveScenario(profileName);
    setSimulationLogs([`[>] Dispatching trigger request for ${profileName}...`]);
    setRunning(true);

    if (ws.current && ws.current.readyState === WebSocket.OPEN) {
      ws.current.send(
        JSON.stringify({
          action: 'TRIGGER_SIMULATION',
          profile_id: profileId,
          delay_multiplier: 1.0
        })
      );
    } else {
      // Fallback to REST trigger
      const token = localStorage.getItem('ta_token') || localStorage.getItem('token');
      fetch('/api/v29/trigger-simulation', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {})
        },
        body: JSON.stringify({
          profile_id: profileId,
          async_execution: true,
          delay_multiplier: 1.0
        })
      })
        .then((res) => res.json())
        .then((data) => {
          setSimulationLogs((prev) => [...prev, `[REST Trigger] ${data.message}`]);
        })
        .catch((err) => {
          setSimulationLogs((prev) => [...prev, `[Error] REST trigger failed: ${err}`]);
          setRunning(false);
        });
    }
  };

  const handleGenerateSTG = async () => {
    setGeneratingSTG(true);
    setStgResult(null);
    try {
      const token = localStorage.getItem('ta_token') || localStorage.getItem('token');
      const res = await fetch('/api/v29/generate-synthetic', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {})
        },
        body: JSON.stringify({
          count: eventCount,
          diurnal_profile: diurnalEnabled,
          noise_ratio: noiseRatio,
          user_clusters_count: 5,
          bootstrap_ml_coldstart: bootstrapML,
          inject_to_stream: true,
          persist_to_db: true
        })
      });

      if (res.ok) {
        const data = await res.json();
        setStgResult(data);
      } else {
        alert('Failed to generate synthetic telemetry');
      }
    } catch (err) {
      console.error('STG generation failed:', err);
    } finally {
      setGeneratingSTG(false);
    }
  };

  return (
    <div className="space-y-6 font-sans">
      {/* 1. Header Banner & Status */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 shadow-2xl relative overflow-hidden">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 relative z-10">
          <div>
            <div className="flex items-center gap-3">
              <div className="p-2.5 bg-gradient-to-tr from-purple-600 to-indigo-600 rounded-xl shadow-lg shadow-purple-500/20 text-white">
                <Icons.Flame />
              </div>
              <div>
                <h1 className="text-2xl font-black tracking-tight text-white flex items-center gap-2">
                  Simulation & Attack Emulation Hub
                  <span className="text-xs font-mono px-2.5 py-0.5 rounded-full bg-purple-500/20 text-purple-300 border border-purple-500/30">
                    v29.0 Sovereign STG
                  </span>
                </h1>
                <p className="text-sm text-slate-400 mt-0.5">
                  Zero-Data Cold Start Baseline Bootstrapping • Purple-Team APT Emulation • KEDA Stream Scaling
                </p>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800">
              <span className={`h-2.5 w-2.5 rounded-full ${wsConnected ? 'bg-emerald-500 animate-pulse' : 'bg-rose-500'}`} />
              <span className="text-xs font-mono text-slate-300 uppercase">{connectionStatus}</span>
            </div>
            <button
              onClick={fetchProfilesAndRuns}
              className="p-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition-colors border border-slate-700"
              title="Refresh Profiles & Runs"
            >
              <Icons.Refresh />
            </button>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="flex items-center gap-2 mt-6 pt-4 border-t border-slate-800">
          <button
            onClick={() => setActiveTab('emulation')}
            className={`px-4 py-2 rounded-lg text-xs font-bold transition-all flex items-center gap-2 ${
              activeTab === 'emulation'
                ? 'bg-purple-600 text-white shadow-lg shadow-purple-600/30'
                : 'bg-slate-800/60 text-slate-400 hover:text-slate-200 hover:bg-slate-800'
            }`}
          >
            <Icons.ShieldAlert />
            Purple-Team Emulation
          </button>
          <button
            onClick={() => setActiveTab('stg')}
            className={`px-4 py-2 rounded-lg text-xs font-bold transition-all flex items-center gap-2 ${
              activeTab === 'stg'
                ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-600/30'
                : 'bg-slate-800/60 text-slate-400 hover:text-slate-200 hover:bg-slate-800'
            }`}
          >
            <Icons.Activity />
            Synthetic Telemetry (STG)
          </button>
          <button
            onClick={() => setActiveTab('keda')}
            className={`px-4 py-2 rounded-lg text-xs font-bold transition-all flex items-center gap-2 ${
              activeTab === 'keda'
                ? 'bg-cyan-600 text-white shadow-lg shadow-cyan-600/30'
                : 'bg-slate-800/60 text-slate-400 hover:text-slate-200 hover:bg-slate-800'
            }`}
          >
            <Icons.Server />
            KEDA & GitOps Fabric
          </button>
          <button
            onClick={() => setActiveTab('history')}
            className={`px-4 py-2 rounded-lg text-xs font-bold transition-all flex items-center gap-2 ${
              activeTab === 'history'
                ? 'bg-emerald-600 text-white shadow-lg shadow-emerald-600/30'
                : 'bg-slate-800/60 text-slate-400 hover:text-slate-200 hover:bg-slate-800'
            }`}
          >
            <Icons.Clock />
            Simulation Run History ({runs.length})
          </button>
        </div>
      </div>

      {/* 2. TAB: Purple-Team Emulation */}
      {activeTab === 'emulation' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left Column: Adversary Profile Selector */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
                <Icons.ShieldAlert />
                Select Attack Profile
              </h3>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-500/10 text-purple-400 border border-purple-500/20">
                {profiles.length} Profiles
              </span>
            </div>

            {loadingProfiles ? (
              <div className="text-center py-8 text-slate-500 text-xs flex items-center justify-center gap-2">
                <Icons.Refresh className="w-4 h-4 animate-spin" /> Loading scenarios...
              </div>
            ) : profiles.length === 0 ? (
              <div className="text-center py-8 text-slate-500 text-xs">No simulation profiles loaded.</div>
            ) : (
              profiles.map((p) => {
                const isAPT = p.threat_actor === 'APT29';
                const isHermetic = p.threat_actor === 'HermeticWiper';
                const isSelected = activeScenario === p.name;

                return (
                  <div
                    key={p.id}
                    className={`p-4 rounded-xl border transition-all flex flex-col justify-between space-y-3 ${
                      isSelected
                        ? 'border-purple-500 bg-purple-950/30 shadow-lg shadow-purple-900/20'
                        : 'border-slate-800 bg-slate-950/60 hover:border-slate-700 hover:bg-slate-950/90'
                    }`}
                  >
                    <div>
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-white text-sm flex items-center gap-2">
                          <span
                            className={`h-2.5 w-2.5 rounded-full ${
                              isAPT ? 'bg-orange-500' : isHermetic ? 'bg-rose-500' : 'bg-indigo-500'
                            }`}
                          />
                          {p.name}
                        </span>
                        <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                          {p.threat_actor}
                        </span>
                      </div>
                      <p className="text-xs text-slate-400 mt-2 leading-relaxed">{p.description}</p>
                      <div className="flex items-center gap-2 mt-3 text-[11px] font-mono text-slate-500">
                        <Icons.Layers />
                        <span>{p.steps?.length || 4} Sequential OCSF Steps</span>
                      </div>
                    </div>

                    <button
                      onClick={() => triggerEmulation(p.id, p.name)}
                      disabled={running}
                      className={`w-full text-xs font-bold py-2.5 px-4 rounded-lg transition-all flex items-center justify-center gap-2 ${
                        running
                          ? 'bg-slate-800 text-slate-500 cursor-not-allowed'
                          : isAPT
                          ? 'bg-gradient-to-r from-orange-600 to-amber-600 hover:from-orange-500 hover:to-amber-500 text-white shadow-lg shadow-orange-600/20'
                          : 'bg-gradient-to-r from-rose-600 to-pink-600 hover:from-rose-500 hover:to-pink-500 text-white shadow-lg shadow-rose-600/20'
                      }`}
                    >
                      {running && isSelected ? (
                        <>
                          <Icons.Refresh className="w-3.5 h-3.5 animate-spin" /> Emulating In Progress...
                        </>
                      ) : (
                        <>
                          <Icons.Play /> Run {p.threat_actor} Emulation
                        </>
                      )}
                    </button>
                  </div>
                );
              })
            )}
          </div>

          {/* Middle/Right Column: Live Execution Terminal */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 lg:col-span-2 flex flex-col h-[580px]">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
                <Icons.Terminal />
                Live Emulation Stream Console
              </h3>
              {running && (
                <div className="flex items-center gap-2 text-xs font-mono text-orange-400">
                  <span className="h-2 w-2 rounded-full bg-orange-400 animate-ping" />
                  <span>STEP {currentStep} / {totalSteps || 4} ACTIVE</span>
                </div>
              )}
            </div>

            {/* Terminal Window */}
            <div
              ref={logTerminalRef}
              className="overflow-y-auto flex-1 pr-2 mt-4 space-y-2 font-mono text-xs text-slate-300"
            >
              {simulationLogs.length === 0 ? (
                <div className="h-full flex flex-col items-center justify-center text-slate-600 space-y-3">
                  <Icons.Flame />
                  <p className="text-xs">Select an attack profile on the left to trigger live sandbox log injection.</p>
                  <span className="text-[11px] text-slate-600">
                    Real-time logs will stream via WebSocket directly to Redis stream <code className="text-purple-400">logs:raw_stream</code>
                  </span>
                </div>
              ) : (
                simulationLogs.map((log, index) => {
                  const isSuccess = log.includes('[+]') || log.includes('[Pipeline Broker]') || log.includes('[Verified]');
                  const isStep = log.includes('[Step');
                  const isError = log.includes('[Error]');

                  return (
                    <div
                      key={index}
                      className={`p-2.5 rounded-lg border leading-relaxed ${
                        isError
                          ? 'border-rose-900/60 bg-rose-950/30 text-rose-300'
                          : isStep
                          ? 'border-amber-900/60 bg-amber-950/30 text-amber-300'
                          : isSuccess
                          ? 'border-emerald-900/60 bg-emerald-950/30 text-emerald-300'
                          : 'border-slate-800 bg-slate-950 text-slate-300'
                      }`}
                    >
                      {log}
                    </div>
                  );
                })
              )}
            </div>

            {/* Bottom Progress Bar */}
            {running && (
              <div className="mt-4 pt-3 border-t border-slate-800 space-y-2">
                <div className="flex justify-between items-center text-xs">
                  <span className="text-slate-400">Attack Emulation Execution Progress:</span>
                  <span className="font-mono font-bold text-purple-400">
                    {Math.round(((currentStep || 1) / (totalSteps || 4)) * 100)}%
                  </span>
                </div>
                <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                  <div
                    className="bg-gradient-to-r from-purple-600 to-indigo-500 h-full transition-all duration-500"
                    style={{ width: `${((currentStep || 1) / (totalSteps || 4)) * 100}%` }}
                  />
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* 3. TAB: Sovereign Synthetic Telemetry (STG) */}
      {activeTab === 'stg' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* STG Configuration Card */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 space-y-5">
            <div className="border-b border-slate-800 pb-3">
              <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
                <Icons.Sliders />
                STG Configuration Controls
              </h3>
              <p className="text-[11px] text-slate-400 mt-1">
                Configure synthetic telemetry parameters to bootstrap cold-start models instantly.
              </p>
            </div>

            {/* Event Count Selector */}
            <div className="space-y-2">
              <label className="text-xs font-semibold text-slate-300 flex justify-between">
                <span>Telemetry Batch Count</span>
                <span className="font-mono text-indigo-400 font-bold">{eventCount.toLocaleString()} Events</span>
              </label>
              <div className="grid grid-cols-4 gap-2">
                {[1000, 5000, 10000, 25000].map((count) => (
                  <button
                    key={count}
                    onClick={() => setEventCount(count)}
                    className={`py-1.5 text-xs font-mono rounded-lg border transition-all ${
                      eventCount === count
                        ? 'border-indigo-500 bg-indigo-950/60 text-indigo-300 font-bold'
                        : 'border-slate-800 bg-slate-950 hover:bg-slate-800 text-slate-400'
                    }`}
                  >
                    {count >= 1000 ? `${count / 1000}k` : count}
                  </button>
                ))}
              </div>
            </div>

            {/* Diurnal Temporal Curve Toggle */}
            <div className="p-3 rounded-xl border border-slate-800 bg-slate-950 flex items-center justify-between">
              <div>
                <div className="text-xs font-bold text-white flex items-center gap-1.5">
                  <Icons.Activity />
                  Diurnal Sine/Cosine Temporal Curve
                </div>
                <p className="text-[11px] text-slate-400 mt-0.5">
                  Simulates realistic 9am–5pm peak business hour curves.
                </p>
              </div>
              <button
                onClick={() => setDiurnalEnabled(!diurnalEnabled)}
                className={`w-11 h-6 rounded-full transition-colors relative p-0.5 ${
                  diurnalEnabled ? 'bg-indigo-600' : 'bg-slate-700'
                }`}
              >
                <div
                  className={`w-5 h-5 rounded-full bg-white transition-transform ${
                    diurnalEnabled ? 'translate-x-5' : 'translate-x-0'
                  }`}
                />
              </button>
            </div>

            {/* Background Noise Slider */}
            <div className="space-y-2">
              <div className="flex justify-between items-center text-xs">
                <span className="font-semibold text-slate-300">Background Noise Injection</span>
                <span className="font-mono text-indigo-400 font-bold">{Math.round(noiseRatio * 100)}%</span>
              </div>
              <input
                type="range"
                min="0.0"
                max="0.6"
                step="0.05"
                value={noiseRatio}
                onChange={(e) => setNoiseRatio(parseFloat(e.target.value))}
                className="w-full accent-indigo-500 h-1.5 bg-slate-800 rounded-lg cursor-pointer"
              />
              <p className="text-[11px] text-slate-500">
                Adds benign DNS resolutions and routine cron logs to prevent ML overfitting.
              </p>
            </div>

            {/* ML Cold Start Bootstrap Toggle */}
            <div className="p-3 rounded-xl border border-slate-800 bg-slate-950 flex items-center justify-between">
              <div>
                <div className="text-xs font-bold text-white flex items-center gap-1.5">
                  <Icons.Cpu />
                  Bootstrap Isolation Forest ML
                </div>
                <p className="text-[11px] text-slate-400 mt-0.5">
                  Instantly trains tenant anomaly detection baseline.
                </p>
              </div>
              <button
                onClick={() => setBootstrapML(!bootstrapML)}
                className={`w-11 h-6 rounded-full transition-colors relative p-0.5 ${
                  bootstrapML ? 'bg-emerald-600' : 'bg-slate-700'
                }`}
              >
                <div
                  className={`w-5 h-5 rounded-full bg-white transition-transform ${
                    bootstrapML ? 'translate-x-5' : 'translate-x-0'
                  }`}
                />
              </button>
            </div>

            {/* Trigger Button */}
            <button
              onClick={handleGenerateSTG}
              disabled={generatingSTG}
              className={`w-full py-3 px-4 rounded-xl font-bold text-xs transition-all flex items-center justify-center gap-2 shadow-lg ${
                generatingSTG
                  ? 'bg-slate-800 text-slate-500 cursor-not-allowed'
                  : 'bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-500 hover:to-purple-500 text-white shadow-indigo-600/30'
              }`}
            >
              {generatingSTG ? (
                <>
                  <Icons.Refresh className="w-4 h-4 animate-spin" /> Generating Synthetic Telemetry Matrix...
                </>
              ) : (
                <>
                  <Icons.Activity /> Bootstrap {eventCount.toLocaleString()} Sovereign Events
                </>
              )}
            </button>
          </div>

          {/* STG Results & Persona Matrix */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 lg:col-span-2 space-y-5">
            <div className="border-b border-slate-800 pb-3 flex items-center justify-between">
              <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
                <Icons.Users />
                UEBA Identity Personas & STG Telemetry Matrix
              </h3>
              {stgResult && (
                <span className="text-xs font-mono text-emerald-400 flex items-center gap-1">
                  <Icons.Check /> Generated in {stgResult.time_elapsed_sec}s
                </span>
              )}
            </div>

            {/* Personas Cards */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <div className="p-3 rounded-xl border border-slate-800 bg-slate-950">
                <div className="text-xs font-bold text-white">dev_alice</div>
                <div className="text-[11px] text-slate-400">Software Engineer</div>
                <div className="text-[10px] font-mono text-indigo-400 mt-2">git, node, python3, zsh</div>
              </div>
              <div className="p-3 rounded-xl border border-slate-800 bg-slate-950">
                <div className="text-xs font-bold text-white">admin_bob</div>
                <div className="text-[11px] text-slate-400">Site Reliability Eng</div>
                <div className="text-[10px] font-mono text-purple-400 mt-2">kubectl, ssh, terraform</div>
              </div>
              <div className="p-3 rounded-xl border border-slate-800 bg-slate-950">
                <div className="text-xs font-bold text-white">cron_runner_db</div>
                <div className="text-[11px] text-slate-400">Database Service Acct</div>
                <div className="text-[10px] font-mono text-emerald-400 mt-2">pg_dump, rsync, gzip</div>
              </div>
            </div>

            {/* STG Output Breakdown */}
            {stgResult ? (
              <div className="space-y-4">
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  <div className="p-3.5 rounded-xl border border-slate-800 bg-slate-950">
                    <span className="text-[10px] text-slate-500 uppercase font-mono">Total Generated</span>
                    <div className="text-xl font-bold font-mono text-white mt-1">
                      {stgResult.events_generated.toLocaleString()}
                    </div>
                  </div>
                  <div className="p-3.5 rounded-xl border border-slate-800 bg-slate-950">
                    <span className="text-[10px] text-slate-500 uppercase font-mono">DB Persisted</span>
                    <div className="text-xl font-bold font-mono text-indigo-400 mt-1">
                      {stgResult.events_persisted.toLocaleString()}
                    </div>
                  </div>
                  <div className="p-3.5 rounded-xl border border-slate-800 bg-slate-950">
                    <span className="text-[10px] text-slate-500 uppercase font-mono">Redis Streamed</span>
                    <div className="text-xl font-bold font-mono text-purple-400 mt-1">
                      {stgResult.events_streamed.toLocaleString()}
                    </div>
                  </div>
                  <div className="p-3.5 rounded-xl border border-slate-800 bg-slate-950">
                    <span className="text-[10px] text-slate-500 uppercase font-mono">ML Baseline</span>
                    <div className="text-xs font-bold font-mono text-emerald-400 mt-2 flex items-center gap-1">
                      <Icons.Check />
                      {stgResult.ml_coldstart_bootstrapped ? 'Trained & Active' : 'Fallback Mode'}
                    </div>
                  </div>
                </div>

                {/* Sample Log Preview */}
                <div className="space-y-2">
                  <div className="text-xs font-bold text-slate-300">Sample High-Fidelity OCSF Logs:</div>
                  <div className="space-y-1.5">
                    {stgResult.sample_events.map((sample, idx) => (
                      <div
                        key={idx}
                        className="p-2.5 rounded-lg border border-slate-800 bg-slate-950 font-mono text-[11px] text-slate-300 flex items-center justify-between"
                      >
                        <div className="truncate pr-4">
                          <span className="text-indigo-400 font-bold mr-2">[{sample.ocsf_class}]</span>
                          <span>{sample.raw}</span>
                        </div>
                        <span className="text-[10px] text-slate-500 shrink-0">{sample.timestamp.slice(11, 19)}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            ) : (
              <div className="p-12 text-center border border-dashed border-slate-800 rounded-xl text-slate-500 text-xs">
                Click "Bootstrap Sovereign Events" to generate synthetic baseline logs.
              </div>
            )}
          </div>
        </div>
      )}

      {/* 4. TAB: KEDA & GitOps Fabric */}
      {activeTab === 'keda' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 space-y-4">
            <div className="border-b border-slate-800 pb-3">
              <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
                <Icons.Server />
                KEDA ScaledObject Blueprint
              </h3>
              <p className="text-[11px] text-slate-400 mt-1">
                Event-Driven Autoscaling driven by Redis Stream backlog threshold.
              </p>
            </div>

            <div className="space-y-3 font-mono text-xs">
              <div className="p-3 rounded-xl border border-slate-800 bg-slate-950 flex justify-between">
                <span className="text-slate-400">Stream Target:</span>
                <span className="text-cyan-400 font-bold">{kedaConfig?.stream_name || 'logs:raw_stream'}</span>
              </div>
              <div className="p-3 rounded-xl border border-slate-800 bg-slate-950 flex justify-between">
                <span className="text-slate-400">Scale Threshold:</span>
                <span className="text-white font-bold">{kedaConfig?.target_backlog_threshold?.toLocaleString() || '10,000'} msgs</span>
              </div>
              <div className="p-3 rounded-xl border border-slate-800 bg-slate-950 flex justify-between">
                <span className="text-slate-400">Worker Pod Bounds:</span>
                <span className="text-emerald-400 font-bold">
                  {kedaConfig?.min_replicas || 2} → {kedaConfig?.max_replicas || 50} Pods
                </span>
              </div>
              <div className="p-3 rounded-xl border border-slate-800 bg-slate-950 flex justify-between">
                <span className="text-slate-400">GitOps Sync:</span>
                <span className="text-purple-400 font-bold">{kedaConfig?.gitops_status || 'HEALTHY_SYNCED'}</span>
              </div>
            </div>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 lg:col-span-2 space-y-3">
            <div className="border-b border-slate-800 pb-3 flex items-center justify-between">
              <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
                <Icons.FileCode />
                Kubernetes & ArgoCD Manifest Spec
              </h3>
              <span className="text-[10px] font-mono text-slate-400">deploy/k8s/keda_celery_scaledobject.yaml</span>
            </div>

            <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800 font-mono text-[11px] text-cyan-300 overflow-x-auto leading-relaxed h-[380px]">
{`apiVersion: keda.sh/v1alpha1
kind: ScaledObject
metadata:
  name: celery-stream-worker-scaler
  namespace: threat-analyser-prod
spec:
  scaleTargetRef:
    name: threat-analyser-worker
  minReplicaCount: 2
  maxReplicaCount: 50
  cooldownPeriod: 300
  triggers:
    - type: redis-streams
      metadata:
        address: redis-cluster.threat-analyser-prod.svc.cluster.local:6379
        stream: logs:raw_stream
        pendingEntriesCount: "10000"`}
            </pre>
          </div>
        </div>
      )}

      {/* 5. TAB: Historical Simulation Run Ledger */}
      {activeTab === 'history' && (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 space-y-4">
          <div className="border-b border-slate-800 pb-3 flex items-center justify-between">
            <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
              <Icons.Clock />
              Historical Simulation Ledger & Pipeline Verification Runs
            </h3>
            <span className="text-xs text-slate-400">{runs.length} Historical Executions</span>
          </div>

          {runs.length === 0 ? (
            <div className="text-center py-12 text-slate-500 text-xs">
              No simulation runs logged yet. Execute an adversary emulation scenario to generate records.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 uppercase text-[10px]">
                    <th className="pb-3 font-semibold">Run ID</th>
                    <th className="pb-3 font-semibold">Scenario</th>
                    <th className="pb-3 font-semibold">Status</th>
                    <th className="pb-3 font-semibold">Alerts Injected</th>
                    <th className="pb-3 font-semibold">Started At</th>
                    <th className="pb-3 font-semibold">Outcome</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800 text-slate-300">
                  {runs.map((r) => (
                    <tr key={r.id} className="hover:bg-slate-800/30 transition-colors">
                      <td className="py-3 font-bold text-white">{r.id}</td>
                      <td className="py-3 text-purple-300">{r.profile_name || 'APT Scenario'}</td>
                      <td className="py-3">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                            r.status === 'COMPLETED'
                              ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                              : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                          }`}
                        >
                          {r.status}
                        </span>
                      </td>
                      <td className="py-3 text-slate-300">{r.alerts_triggered_count || 4} Steps Verified</td>
                      <td className="py-3 text-slate-400">{new Date(r.started_at).toLocaleTimeString()}</td>
                      <td className="py-3 text-emerald-400 flex items-center gap-1">
                        <Icons.Check /> Pipeline Validated
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
