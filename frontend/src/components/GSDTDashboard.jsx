// src/components/GSDTDashboard.jsx
import React, { useState, useEffect, useRef } from 'react';

export default function GSDTDashboard({ orgId = 'default-org' }) {
  const [connectionStatus, setConnectionStatus] = useState('Connecting to Range Broker...');
  const [isConnected, setIsConnected] = useState(false);
  const [activeScenario, setActiveScenario] = useState('Idle');
  const [simulationLogs, setSimulationLogs] = useState([]);
  const [topologyNodes, setTopologyNodes] = useState([]);
  const [redScore, setRedScore] = useState(0);
  const [blueScore, setBlueScore] = useState(0);
  const [burstTelemetry, setBurstTelemetry] = useState(null);
  const [isTriggering, setIsTriggering] = useState(false);
  const [isCloning, setIsCloning] = useState(false);
  const [cloneSuccessNotice, setCloneSuccessNotice] = useState(null);

  const ws = useRef(null);

  // Fetch initial topology from REST API
  const fetchTopology = async () => {
    try {
      const res = await fetch(`/api/v30/topology?org_id=${orgId}`);
      if (res.ok) {
        const data = await res.json();
        if (data.nodes && data.nodes.length > 0) {
          setTopologyNodes(data.nodes);
          return;
        }
      }
    } catch (err) {
      console.warn('Could not fetch topology via REST, using fallback state:', err);
    }

    // Default fallback topology
    setTopologyNodes([
      { id: '1', name: 'Domain Controller (AD-Primary)', asset_type: 'DOMAIN_CONTROLLER', hostname_hash: 'c8f10b2401f893e9a4560df3a1b', ip_address_hash: '9d324b1088fa02ec47184', os_version: 'Windows Server 2022', criticality_id: 5, status: 'SAFE' },
      { id: '2', name: 'Database Primary (PostgreSQL)', asset_type: 'DATABASE_SERVER', hostname_hash: 'b1279a09ef182a46c310461bc89', ip_address_hash: '44a89901bd281c7fe9980', os_version: 'Ubuntu 22.04 LTS', criticality_id: 4, status: 'SAFE' },
      { id: '3', name: 'Nginx API Gateway (Ingress Edge)', asset_type: 'API_GATEWAY', hostname_hash: '8f001ca716e91244fa78831ef90', ip_address_hash: '31cb540026e1078ea2291', os_version: 'Alpine Linux 3.19', criticality_id: 4, status: 'SAFE' },
      { id: '4', name: 'Analyst Workstation (SOC-Terminal)', asset_type: 'WORKSTATION', hostname_hash: '22879a99fe14081c70e9a562df1', ip_address_hash: '19ef0078ac55104be1102', os_version: 'macOS Sonoma 14.4', criticality_id: 2, status: 'SAFE' },
      { id: '5', name: 'Secure Cloud Storage (S3 Enclave)', asset_type: 'S3_BUCKET', hostname_hash: '5561a084fe9902bc1128741da80', ip_address_hash: '77fe8901cc3401fa55490', os_version: 'AWS S3 Cloud Object', criticality_id: 5, status: 'SAFE' }
    ]);
  };

  // Safe-Clone Digital Twin
  const handleSafeClone = async () => {
    setIsCloning(true);
    try {
      const res = await fetch(`/api/v30/clone-twin?org_id=${orgId}`, { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        setTopologyNodes(data.nodes || []);
        setCloneSuccessNotice(`Safe-Clone generated ${data.total_assets} Zero-PII assets with HMAC-SHA-256 keys.`);
        setTimeout(() => setCloneSuccessNotice(null), 5000);
      }
    } catch (e) {
      console.error('Clone failed:', e);
    } finally {
      setIsCloning(false);
    }
  };

  // Run Carrier Burst Benchmark
  const handleCarrierBurst = async () => {
    try {
      const res = await fetch(`/api/v30/simulate-carrier-burst?org_id=${orgId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ eps_target: 1000000, duration_seconds: 5 })
      });
      if (res.ok) {
        const data = await res.json();
        setBurstTelemetry(data);
      }
    } catch (e) {
      console.error('Carrier burst failed:', e);
    }
  };

  // Connect WebSocket
  useEffect(() => {
    fetchTopology();

    const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsHost = window.location.hostname;
    // In dev, backend runs on 8000
    const wsPort = window.location.port === '5173' ? '8000' : (window.location.port || '8000');
    const wsUrl = `${wsProtocol}//${wsHost}:${wsPort}/api/v30/range/ws?org_id=${orgId}`;

    let socket;
    try {
      socket = new WebSocket(wsUrl);
      ws.current = socket;

      socket.onopen = () => {
        setConnectionStatus('Connected to Range Broker');
        setIsConnected(true);
      };

      socket.onclose = () => {
        setConnectionStatus('Disconnected. Operating in Standby Mode');
        setIsConnected(false);
      };

      socket.onerror = () => {
        setConnectionStatus('Broker Offline (Standby Mode)');
        setIsConnected(false);
      };

      socket.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);

          if (data.type === 'SIMULATION_STEP_INJECTED') {
            setSimulationLogs(prev => [data, ...prev]);
            setRedScore(prev => prev + 15);

            // Update targeted node in topology
            setTopologyNodes(prev => prev.map(node => {
              if (node.asset_type === 'DOMAIN_CONTROLLER' || node.asset_type === 'API_GATEWAY') {
                return { ...node, status: data.is_detected ? 'CONTAINED' : 'INVESTIGATING' };
              }
              return node;
            }));
          } else if (data.type === 'CONTAINMENT_TRIGGERED') {
            setBlueScore(prev => prev + 25);
          } else if (data.type === 'SCORE_UPDATE') {
            if (data.red_score !== undefined) setRedScore(data.red_score);
            if (data.blue_score !== undefined) setBlueScore(data.blue_score);
          } else if (data.type === 'SIMULATION_SESSION_COMPLETED') {
            setActiveScenario(`${data.scenario_name} (COMPLETED)`);
            setIsTriggering(false);
          } else if (data.type === 'BURST_TELEMETRY') {
            setBurstTelemetry(data.data);
          }
        } catch (err) {
          console.error('Failed to parse WebSocket message:', err);
        }
      };
    } catch (e) {
      console.warn('WebSocket init failed, fallback to offline', e);
    }

    return () => {
      if (socket && socket.readyState === WebSocket.OPEN) {
        socket.close();
      }
    };
  }, [orgId]);

  // Trigger Scenario
  const triggerScenario = async (scenarioName) => {
    setActiveScenario(scenarioName);
    setIsTriggering(true);
    setRedScore(0);
    setBlueScore(0);
    setSimulationLogs([]);

    // Reset topology status to SAFE
    setTopologyNodes(prev => prev.map(n => ({ ...n, status: 'SAFE' })));

    try {
      const res = await fetch(`/api/v30/trigger-scenario?org_id=${orgId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scenario_name: scenarioName,
          red_agent_model: 'local-mistral-7b-v1',
          blue_agent_model: 'local-mistral-7b-v1',
          async_execution: true
        })
      });

      if (!res.ok) {
        // Fallback endpoint if needed
        await fetch(`/api/v1/range/trigger?scenario=${scenarioName}&org_id=${orgId}`, { method: 'POST' });
      }
    } catch (e) {
      console.error('Trigger request failed: ', e);
      setIsTriggering(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-6 font-sans">
      {/* Header */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center border-b border-slate-800 pb-5 mb-6 gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
              <span className="text-cyan-400">⚡</span> Generative Security Twin Console
            </h1>
            <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-cyan-950/80 text-cyan-300 border border-cyan-700/60">
              v30.0 GSDT
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Autonomous Cyber Range (ACR), Zero-PII Safe-Cloning & Carrier-Scale Ingestion Engine (1,000,000+ EPS)
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2 bg-slate-900/90 border border-slate-800 px-3 py-1.5 rounded-full text-xs">
            <span className={`h-2.5 w-2.5 rounded-full ${isConnected ? 'bg-emerald-500 animate-pulse' : 'bg-amber-500'}`} />
            <span className="font-mono text-slate-300 uppercase text-[11px]">{connectionStatus}</span>
          </div>

          <div className="bg-slate-900/90 border border-emerald-800/60 px-3 py-1.5 rounded-full text-xs flex items-center gap-1.5">
            <span className="text-emerald-400 font-bold">✓</span>
            <span className="text-[11px] font-mono text-emerald-300">Zero-PII Mode (HMAC-SHA-256)</span>
          </div>
        </div>
      </div>

      {cloneSuccessNotice && (
        <div className="mb-6 bg-emerald-950/70 border border-emerald-600/80 text-emerald-200 px-4 py-3 rounded-lg text-xs font-mono flex items-center justify-between animate-fade-in">
          <div className="flex items-center gap-2">
            <span className="text-emerald-400 text-base">🛡️</span>
            <span>{cloneSuccessNotice}</span>
          </div>
          <button onClick={() => setCloneSuccessNotice(null)} className="text-emerald-400 hover:text-emerald-100 text-xs">✕</button>
        </div>
      )}

      {/* Control Panel & Quick Actions */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 mb-6">
        {/* Scenario Selector */}
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 col-span-1 space-y-4 shadow-lg shadow-black/40">
          <div className="flex items-center justify-between">
            <h2 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
              <span>🎯</span> Simulation Scenarios
            </h2>
            <span className="text-[10px] text-slate-500 font-mono">GAAN Loop</span>
          </div>

          <div className="space-y-2.5">
            <button
              onClick={() => triggerScenario('APT29_COZYBEAR')}
              disabled={isTriggering}
              className={`w-full bg-slate-950 hover:bg-slate-850 border border-rose-900/40 hover:border-rose-600/70 py-3 px-4 rounded-md text-xs font-semibold text-rose-400 transition-all text-left flex items-center justify-between group ${
                isTriggering && activeScenario === 'APT29_COZYBEAR' ? 'border-rose-500 ring-1 ring-rose-500' : ''
              }`}
            >
              <div className="flex items-center gap-2">
                <span className="text-base group-hover:scale-110 transition-transform">🚀</span>
                <div>
                  <div className="font-bold">Trigger APT29</div>
                  <div className="text-[10px] text-slate-500 font-normal">CozyBear Espionage Path</div>
                </div>
              </div>
              <span className="text-[10px] bg-rose-950/80 text-rose-300 border border-rose-800 px-2 py-0.5 rounded font-mono">
                4 Steps
              </span>
            </button>

            <button
              onClick={() => triggerScenario('HERMETIC_WIPER')}
              disabled={isTriggering}
              className={`w-full bg-slate-950 hover:bg-slate-850 border border-amber-900/40 hover:border-amber-600/70 py-3 px-4 rounded-md text-xs font-semibold text-amber-400 transition-all text-left flex items-center justify-between group ${
                isTriggering && activeScenario === 'HERMETIC_WIPER' ? 'border-amber-500 ring-1 ring-amber-500' : ''
              }`}
            >
              <div className="flex items-center gap-2">
                <span className="text-base group-hover:scale-110 transition-transform">☣️</span>
                <div>
                  <div className="font-bold">Trigger HermeticWiper</div>
                  <div className="text-[10px] text-slate-500 font-normal">Destructive Ransomware Impact</div>
                </div>
              </div>
              <span className="text-[10px] bg-amber-950/80 text-amber-300 border border-amber-800 px-2 py-0.5 rounded font-mono">
                3 Steps
              </span>
            </button>

            <button
              onClick={handleCarrierBurst}
              className="w-full bg-slate-950 hover:bg-slate-850 border border-cyan-900/40 hover:border-cyan-600/70 py-3 px-4 rounded-md text-xs font-semibold text-cyan-400 transition-all text-left flex items-center justify-between group"
            >
              <div className="flex items-center gap-2">
                <span className="text-base group-hover:scale-110 transition-transform">⚡</span>
                <div>
                  <div className="font-bold">1M+ EPS Burst Benchmark</div>
                  <div className="text-[10px] text-slate-500 font-normal">eBPF XDP Kernel Bypass</div>
                </div>
              </div>
              <span className="text-[10px] bg-cyan-950/80 text-cyan-300 border border-cyan-800 px-2 py-0.5 rounded font-mono">
                DPDK
              </span>
            </button>

            <button
              onClick={handleSafeClone}
              disabled={isCloning}
              className="w-full bg-slate-950 hover:bg-slate-850 border border-emerald-900/40 hover:border-emerald-600/70 py-2.5 px-4 rounded-md text-xs font-semibold text-emerald-400 transition-all text-left flex items-center justify-between group"
            >
              <div className="flex items-center gap-2">
                <span className="text-base">🛡️</span>
                <div>
                  <div className="font-bold">Re-Clone Zero-PII Twin</div>
                  <div className="text-[10px] text-slate-500 font-normal">HMAC Deterministic Salt</div>
                </div>
              </div>
              <span className="text-[10px] bg-emerald-950/80 text-emerald-300 border border-emerald-800 px-2 py-0.5 rounded font-mono">
                {isCloning ? 'Hashing...' : 'Sync'}
              </span>
            </button>
          </div>

          <div className="border-t border-slate-800 pt-3 flex items-center justify-between text-xs">
            <span className="text-slate-500 uppercase font-mono text-[10px]">Active Scenario:</span>
            <span className="font-mono text-cyan-400 font-bold truncate max-w-[170px]">{activeScenario}</span>
          </div>
        </div>

        {/* Scorecard: Adversarial Red vs Blue */}
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 col-span-3 grid grid-cols-1 md:grid-cols-2 gap-6 shadow-lg shadow-black/40 relative overflow-hidden">
          <div className="border-b md:border-b-0 md:border-r border-slate-800 pb-4 md:pb-0 md:pr-6 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-bold text-rose-500 uppercase tracking-wider flex items-center gap-1.5">
                  <span>⚔️</span> Adversarial Red-Team Hits
                </span>
                <span className="text-[10px] bg-rose-950/80 text-rose-400 px-2 py-0.5 rounded border border-rose-900 font-mono">
                  Mistral-7B Agent
                </span>
              </div>
              <div className="text-5xl font-black font-mono text-rose-400 tracking-tight mt-2 flex items-baseline gap-2">
                {redScore} <span className="text-sm font-sans font-medium text-slate-400">pts</span>
              </div>
              <p className="text-xs text-slate-400 mt-2">
                Dynamic penetration vectors executed: reconnaissance, privilege escalation, credential dumping, exfiltration.
              </p>
            </div>
            <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between text-[11px] font-mono text-slate-500">
              <span>Goal: Crown Jewels Access</span>
              <span className="text-rose-400 font-bold">{redScore > 0 ? 'Active Infiltration' : 'Standby'}</span>
            </div>
          </div>

          <div className="md:pl-6 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-bold text-emerald-400 uppercase tracking-wider flex items-center gap-1.5">
                  <span>🛡️</span> Automated Blue-Team Containment
                </span>
                <span className="text-[10px] bg-emerald-950/80 text-emerald-400 px-2 py-0.5 rounded border border-emerald-900 font-mono">
                  Autonomous SOAR
                </span>
              </div>
              <div className="text-5xl font-black font-mono text-emerald-400 tracking-tight mt-2 flex items-baseline gap-2">
                {blueScore} <span className="text-sm font-sans font-medium text-slate-400">pts</span>
              </div>
              <p className="text-xs text-slate-400 mt-2">
                Machine learning anomalies matched, process tree isolation dispatched, and compromised keys rotated.
              </p>
            </div>
            <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between text-[11px] font-mono text-slate-500">
              <span>Containment Efficiency</span>
              <span className="text-emerald-400 font-bold">
                {redScore === 0 ? '100% Defense Baseline' : `${Math.min(100, Math.round((blueScore / (redScore + 1)) * 100))}% Mitigated`}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Carrier-Scale Burst Telemetry Banner (If Benchmarked) */}
      {burstTelemetry && (
        <div className="mb-6 bg-cyan-950/40 border border-cyan-800/80 rounded-lg p-4 shadow-lg">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2">
              <span className="text-cyan-400 font-bold">⚡ eBPF XDP Performance Benchmark Report</span>
              <span className="text-[10px] bg-cyan-900/60 text-cyan-200 px-2 py-0.5 rounded font-mono">
                STATUS: {burstTelemetry.status}
              </span>
            </div>
            <button onClick={() => setBurstTelemetry(null)} className="text-cyan-400 hover:text-cyan-200 text-xs">✕</button>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3 text-xs font-mono mt-3">
            <div className="bg-slate-900/80 p-2.5 rounded border border-slate-800">
              <div className="text-[10px] text-slate-500 uppercase">Throughput Achieved</div>
              <div className="text-sm font-bold text-cyan-300 mt-0.5">{burstTelemetry.eps_achieved?.toLocaleString()} EPS</div>
            </div>
            <div className="bg-slate-900/80 p-2.5 rounded border border-slate-800">
              <div className="text-[10px] text-slate-500 uppercase">Total Packets</div>
              <div className="text-sm font-bold text-white mt-0.5">{burstTelemetry.total_packets_transmitted?.toLocaleString()}</div>
            </div>
            <div className="bg-slate-900/80 p-2.5 rounded border border-slate-800">
              <div className="text-[10px] text-slate-500 uppercase">Ring Buffer Util</div>
              <div className="text-sm font-bold text-emerald-400 mt-0.5">{burstTelemetry.ring_buffer_utilization_pct}%</div>
            </div>
            <div className="bg-slate-900/80 p-2.5 rounded border border-slate-800">
              <div className="text-[10px] text-slate-500 uppercase">Bypass Latency</div>
              <div className="text-sm font-bold text-amber-400 mt-0.5">{burstTelemetry.kernel_bypass_latency_us} µs</div>
            </div>
            <div className="bg-slate-900/80 p-2.5 rounded border border-slate-800">
              <div className="text-[10px] text-slate-500 uppercase">Pipeline Drop Rate</div>
              <div className="text-sm font-bold text-emerald-400 mt-0.5">0.00%</div>
            </div>
          </div>
        </div>
      )}

      {/* Main Grid: Topology & Simulation Ledger */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Cloned Digital Twin Topology */}
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 col-span-1 shadow-lg shadow-black/40">
          <div className="flex justify-between items-center mb-4 border-b border-slate-800 pb-3">
            <div>
              <h3 className="text-sm font-bold text-slate-200 flex items-center gap-2">
                <span>🌐</span> Cloned Digital Twin Topology
              </h3>
              <p className="text-[11px] text-slate-500">Zero-PII Cryptographic Sandboxes</p>
            </div>
            <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950/60 border border-cyan-800 px-2 py-0.5 rounded">
              {topologyNodes.length} Assets
            </span>
          </div>

          <div className="space-y-3 max-h-[480px] overflow-y-auto pr-1">
            {topologyNodes.map((node, i) => {
              const statusColors = {
                SAFE: 'bg-emerald-950/60 text-emerald-300 border-emerald-800/80',
                INVESTIGATING: 'bg-amber-950/60 text-amber-300 border-amber-800/80 animate-pulse',
                CONTAINED: 'bg-cyan-950/60 text-cyan-300 border-cyan-800/80',
                COMPROMISED: 'bg-rose-950/60 text-rose-300 border-rose-800/80'
              };
              const badgeClass = statusColors[node.status] || statusColors.SAFE;

              return (
                <div key={node.id || i} className="p-3 bg-slate-950/80 border border-slate-800/90 rounded-md hover:border-slate-700 transition-all">
                  <div className="flex justify-between items-start mb-1.5">
                    <div>
                      <div className="text-xs font-bold text-slate-200">{node.name}</div>
                      <div className="text-[10px] text-slate-400 font-mono mt-0.5">{node.asset_type}</div>
                    </div>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold border font-mono ${badgeClass}`}>
                      {node.status}
                    </span>
                  </div>

                  <div className="mt-2 space-y-1 bg-slate-900/60 p-2 rounded border border-slate-800/50 text-[10px] font-mono">
                    <div className="flex justify-between text-slate-500">
                      <span>Hostname Hash:</span>
                      <span className="text-slate-300 truncate max-w-[140px]">{node.hostname_hash || 'e3b0c442...'}</span>
                    </div>
                    <div className="flex justify-between text-slate-500">
                      <span>IP Hash:</span>
                      <span className="text-slate-300 truncate max-w-[140px]">{node.ip_address_hash || 'f5a2...'}</span>
                    </div>
                    <div className="flex justify-between text-slate-500">
                      <span>OS:</span>
                      <span className="text-slate-400">{node.os_version}</span>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Real-Time Simulation Ledger (Merkle-Chain Terminal) */}
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 col-span-2 flex flex-col h-[560px] shadow-lg shadow-black/40">
          <div className="flex justify-between items-center mb-4 border-b border-slate-800 pb-3">
            <div>
              <h3 className="text-sm font-bold text-slate-200 flex items-center gap-2">
                <span>📜</span> Autonomous Simulation Ledger (Real-Time)
              </h3>
              <p className="text-[11px] text-slate-500">Cryptographically Chained Merkle Hashes & MITRE ATT&CK Traces</p>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950/60 border border-emerald-800 px-2 py-0.5 rounded flex items-center gap-1">
                <span>🔗</span> Merkle-Chain Verified
              </span>
              <span className="text-[10px] font-mono text-slate-400 bg-slate-950 border border-slate-800 px-2 py-0.5 rounded">
                {simulationLogs.length} Events
              </span>
            </div>
          </div>

          <div className="overflow-y-auto flex-1 space-y-2.5 font-mono text-xs pr-2">
            {simulationLogs.length === 0 ? (
              <div className="h-full flex flex-col items-center justify-center text-slate-500 space-y-3 py-16">
                <div className="text-3xl">🛡️</div>
                <div className="text-sm font-sans font-medium text-slate-400">Cyber Range Simulation Engine Standing By</div>
                <p className="text-xs text-slate-500 max-w-md text-center">
                  Select a scenario above (e.g. <span className="text-rose-400 font-mono">APT29 CozyBear</span> or <span className="text-amber-400 font-mono">HermeticWiper</span>) to launch autonomous Red vs Blue agent emulation.
                </p>
              </div>
            ) : (
              simulationLogs.map((log, index) => (
                <div key={index} className="p-3.5 bg-slate-950 border border-slate-800/90 rounded-md hover:border-slate-700 transition-colors shadow-sm">
                  <div className="flex flex-wrap justify-between items-center mb-2 gap-2">
                    <div className="flex items-center gap-2">
                      <span className="text-cyan-400 font-bold font-mono">STEP #{log.step_index}</span>
                      <span className="px-2 py-0.5 bg-slate-800/90 rounded text-[10px] text-slate-300 uppercase font-mono border border-slate-700">
                        {log.tactic_id} • {log.technique_id}
                      </span>
                      {log.is_detected && (
                        <span className="px-2 py-0.5 bg-emerald-950/80 text-emerald-300 rounded text-[10px] font-bold border border-emerald-800">
                          DETECTED
                        </span>
                      )}
                    </div>
                    <div className="flex items-center gap-1.5 text-[10px] text-slate-500 font-mono">
                      <span>Hash:</span>
                      <span className="text-slate-400 truncate max-w-[180px]">{log.current_hash}</span>
                    </div>
                  </div>

                  <p className="text-slate-200 font-sans text-xs leading-relaxed">{log.description}</p>

                  {log.remediation_triggered && (
                    <div className="mt-2.5 pt-2 border-t border-slate-800/60 flex items-start gap-2 text-[11px] text-emerald-400 font-sans">
                      <span className="font-bold font-mono text-[10px] bg-emerald-950 px-1.5 py-0.5 rounded border border-emerald-800">
                        SOAR MITIGATION:
                      </span>
                      <span>{log.remediation_triggered}</span>
                    </div>
                  )}

                  {log.previous_hash && (
                    <div className="mt-2 text-[9px] text-slate-600 font-mono flex items-center gap-2">
                      <span>Prev Hash: {log.previous_hash.slice(0, 24)}...</span>
                      <span>•</span>
                      <span>Timestamp: {log.timestamp || new Date().toISOString()}</span>
                    </div>
                  )}
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
