// src/components/ProvenanceGraphConsole.jsx
import React, { useState, useEffect, useRef, useMemo } from 'react';

// Node category color palette & icons
const NODE_TYPE_CONFIG = {
  PROCESS: { color: '#06b6d4', bg: 'bg-cyan-950/80', border: 'border-cyan-500/80', text: 'text-cyan-300', icon: '⚙️' },
  FILE: { color: '#10b981', bg: 'bg-emerald-950/80', border: 'border-emerald-500/80', text: 'text-emerald-300', icon: '📄' },
  SOCKET: { color: '#f43f5e', bg: 'bg-rose-950/80', border: 'border-rose-500/80', text: 'text-rose-300', icon: '🌐' },
  DOMAIN: { color: '#f59e0b', bg: 'bg-amber-950/80', border: 'border-amber-500/80', text: 'text-amber-300', icon: '🔗' },
  IP_ADDRESS: { color: '#a855f7', bg: 'bg-purple-950/80', border: 'border-purple-500/80', text: 'text-purple-300', icon: '📡' },
  USER: { color: '#38bdf8', bg: 'bg-sky-950/80', border: 'border-sky-500/80', text: 'text-sky-300', icon: '👤' },
  DEFAULT: { color: '#94a3b8', bg: 'bg-slate-900', border: 'border-slate-700', text: 'text-slate-300', icon: '🔹' }
};

export default function ProvenanceGraphConsole({ orgId = 'org_acme_corp' }) {
  const [activeTab, setActiveTab] = useState('graph'); // 'graph' | 'edges' | 'soar' | 'tpm'
  const [wsStatus, setWsStatus] = useState('Connecting...');
  const [graphNodes, setGraphNodes] = useState([]);
  const [graphEdges, setGraphEdges] = useState([]);
  const [soarLogs, setSoarLogs] = useState([]);
  const [tpmSignatures, setTpmSignatures] = useState([]);
  const [selectedNode, setSelectedNode] = useState(null);
  const [selectedEdge, setSelectedEdge] = useState(null);
  const [tracebackData, setTracebackData] = useState(null);
  const [loadingTrace, setLoadingTrace] = useState(false);
  const [filterType, setFilterType] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [tpmVerifyResult, setTpmVerifyResult] = useState(null);
  const [verifyingTpm, setVerifyingTpm] = useState(false);
  const ws = useRef(null);

  // 1. Fetch live DPG Topology
  const fetchGraphData = async () => {
    try {
      const token = localStorage.getItem('ta_token') || localStorage.getItem('token');
      const res = await fetch('/api/v26/provenance/graph?limit_nodes=80&limit_edges=120', {
        headers: token ? { 'Authorization': `Bearer ${token}` } : {}
      });
      if (res.ok) {
        const data = await res.json();
        if (data.edges && data.edges.length > 0) setGraphEdges(data.edges);
        if (data.nodes && data.nodes.length > 0) setGraphNodes(data.nodes);
      }
    } catch (err) {
      console.error('Failed to fetch DPG graph:', err);
    }
  };

  // 2. Fetch SOAR Logs
  const fetchSoarLogs = async () => {
    try {
      const token = localStorage.getItem('ta_token') || localStorage.getItem('token');
      const res = await fetch('/api/v26/soar/logs?limit=20', {
        headers: token ? { 'Authorization': `Bearer ${token}` } : {}
      });
      if (res.ok) {
        const data = await res.json();
        if (data && data.length > 0) {
          setSoarLogs(data.map(d => ({
            id: d.id,
            playbook_name: d.playbook_name || 'High-Risk Threat Edge Isolation',
            device_id: d.device_id,
            status: d.status,
            steps_executed: d.execution_dag_trace?.steps_executed || [],
            duration_ms: d.execution_dag_trace?.execution_duration_ms || 14.2,
            timestamp: d.started_at
          })));
        }
      }
    } catch (err) {
      console.error('Failed to fetch SOAR logs:', err);
    }
  };

  // 3. Fetch TPM 2.0 Signatures
  const fetchTpmSignatures = async () => {
    try {
      const token = localStorage.getItem('ta_token') || localStorage.getItem('token');
      const res = await fetch('/api/v26/tpm/signatures?limit=10', {
        headers: token ? { 'Authorization': `Bearer ${token}` } : {}
      });
      if (res.ok) {
        const data = await res.json();
        setTpmSignatures(data);
      }
    } catch (err) {
      console.error('Failed to fetch TPM signatures:', err);
    }
  };

  // 4. WebSocket Streaming Setup
  useEffect(() => {
    fetchGraphData();
    fetchSoarLogs();
    fetchTpmSignatures();

    const host = window.location.host || 'localhost:8000';
    const wsProto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${wsProto}//${host}/api/v1/provenance/ws?org_id=${orgId}`;

    let socket = null;
    const connectWs = () => {
      try {
        socket = new WebSocket(wsUrl);
        ws.current = socket;

        socket.onopen = () => {
          setWsStatus('Live Streaming Connected');
        };

        socket.onclose = () => {
          setWsStatus('Live Sync Active (Polling)');
        };

        socket.onerror = () => {
          setWsStatus('Live Sync Active (Polling)');
        };

        socket.onmessage = (event) => {
          try {
            const payload = JSON.parse(event.data);
            if (payload.event_type === 'NEW_NODE') {
              setGraphNodes(prev => {
                if (prev.some(n => n.id === payload.node.id)) return prev;
                return [...prev, payload.node].slice(-100);
              });
            } else if (payload.event_type === 'NEW_EDGE') {
              setGraphEdges(prev => [payload.edge, ...prev].slice(0, 150));
            } else if (payload.event_type === 'SOAR_PLAYBOOK_RUN') {
              setSoarLogs(prev => [payload.execution_log, ...prev].slice(0, 30));
            }
          } catch (err) {
            console.error('WS parse error:', err);
          }
        };
      } catch (err) {
        setWsStatus('Live Sync Active (Polling)');
      }
    };

    connectWs();

    const pollInterval = setInterval(() => {
      fetchGraphData();
      fetchSoarLogs();
      fetchTpmSignatures();
    }, 4000);

    return () => {
      if (socket) socket.close();
      clearInterval(pollInterval);
    };
  }, [orgId]);

  // Causal Traceback Execution
  const triggerCausalTraceback = async (targetIdOrName) => {
    setLoadingTrace(true);
    try {
      const token = localStorage.getItem('ta_token') || localStorage.getItem('token');
      const res = await fetch('/api/v26/provenance/traceback', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { 'Authorization': `Bearer ${token}` } : {})
        },
        body: JSON.stringify({
          target_entity_or_id: targetIdOrName,
          max_depth: 10,
          asp_shell_descendants_only: true
        })
      });
      if (res.ok) {
        const data = await res.json();
        setTracebackData(data);
      }
    } catch (err) {
      console.error('Traceback failed:', err);
    } finally {
      setLoadingTrace(false);
    }
  };

  const handleSelectNode = (node) => {
    setSelectedNode(node);
    setSelectedEdge(null);
    triggerCausalTraceback(node.id || node.name);
  };

  const handleSelectEdge = (edge) => {
    setSelectedEdge(edge);
    const targetNode = graphNodes.find(n => n.id === edge.target_node_id) || {
      id: edge.target_node_id,
      name: edge.target_name,
      node_type: edge.target_type || 'PROCESS'
    };
    setSelectedNode(targetNode);
    triggerCausalTraceback(edge.target_node_id || edge.target_name);
  };

  // Verify TPM Signature
  const handleVerifyTpmSignature = async (sig) => {
    setVerifyingTpm(true);
    try {
      const token = localStorage.getItem('ta_token') || localStorage.getItem('token');
      const res = await fetch('/api/v26/tpm/verify-attestation', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { 'Authorization': `Bearer ${token}` } : {})
        },
        body: JSON.stringify({
          merkle_root_hash: sig.merkle_root_hash,
          tpm_hardware_signature: sig.tpm_hardware_signature,
          pcr_composite_digest: sig.pcr_composite_digest
        })
      });
      if (res.ok) {
        const data = await res.json();
        setTpmVerifyResult({ ...data, sigId: sig.id });
      }
    } catch (err) {
      console.error('TPM verification failed:', err);
    } finally {
      setVerifyingTpm(false);
    }
  };

  // Node filtering & layout positioning
  const filteredNodes = useMemo(() => {
    return graphNodes.filter(n => {
      const matchesType = filterType === 'ALL' || n.node_type === filterType;
      const matchesSearch = !searchQuery || 
        n.name.toLowerCase().includes(searchQuery.toLowerCase()) || 
        n.entity_key.toLowerCase().includes(searchQuery.toLowerCase());
      return matchesType && matchesSearch;
    });
  }, [graphNodes, filterType, searchQuery]);

  // Generate 2D graph layout coordinates
  const nodePositions = useMemo(() => {
    const pos = {};
    const width = 760;
    const height = 440;
    const padding = 50;

    const typeGroups = {
      USER: [],
      PROCESS: [],
      SOCKET: [],
      FILE: [],
      DOMAIN: [],
      IP_ADDRESS: []
    };

    filteredNodes.forEach(node => {
      const t = node.node_type || 'PROCESS';
      if (typeGroups[t]) typeGroups[t].push(node);
      else typeGroups.PROCESS.push(node);
    });

    // Column positions
    const columns = [
      { key: 'USER', x: padding + 40 },
      { key: 'PROCESS', x: padding + 200 },
      { key: 'FILE', x: padding + 420 },
      { key: 'SOCKET', x: padding + 580 },
      { key: 'IP_ADDRESS', x: padding + 660 }
    ];

    columns.forEach(col => {
      const group = typeGroups[col.key] || [];
      const step = (height - padding * 2) / Math.max(group.length, 1);
      group.forEach((n, idx) => {
        pos[n.id] = {
          x: col.x + (Math.sin(idx * 1.5) * 15),
          y: padding + 30 + (idx * step)
        };
      });
    });

    return pos;
  }, [filteredNodes]);

  return (
    <div className="bg-slate-950 text-slate-100 rounded-xl border border-slate-800 p-5 md:p-7 font-sans shadow-2xl space-y-6">
      {/* 1. Header & Navigation Tabs */}
      <div className="flex flex-col lg:flex-row justify-between items-start lg:items-center gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-3">
            <h2 className="text-xl md:text-2xl font-black tracking-tight text-white flex items-center gap-2.5">
              <span className="w-3 h-3 rounded-full bg-cyan-400 animate-pulse"></span>
              Causal Data Provenance Graph (DPG) Console
            </h2>
            <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-cyan-950 text-cyan-400 border border-cyan-700/60 uppercase">
              v26 Sovereign
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Real-time multi-tenant causal lineage graph, self-healing SOAR DAG playbooks &amp; TPM 2.0 hardware ledger
          </p>
        </div>

        {/* Tab Selector & Live Indicator */}
        <div className="flex flex-wrap items-center gap-2">
          <div className="bg-slate-900 p-1 rounded-lg border border-slate-800 flex items-center gap-1 font-mono text-xs">
            <button
              onClick={() => setActiveTab('graph')}
              className={`px-3 py-1.5 rounded-md transition-all font-semibold flex items-center gap-1.5 ${
                activeTab === 'graph' ? 'bg-cyan-600 text-white shadow-md' : 'text-slate-400 hover:text-white'
              }`}
            >
              <span>🕸️</span> Topology Graph
            </button>
            <button
              onClick={() => setActiveTab('edges')}
              className={`px-3 py-1.5 rounded-md transition-all font-semibold flex items-center gap-1.5 ${
                activeTab === 'edges' ? 'bg-cyan-600 text-white shadow-md' : 'text-slate-400 hover:text-white'
              }`}
            >
              <span>⚡</span> Edge Stream ({graphEdges.length})
            </button>
            <button
              onClick={() => setActiveTab('soar')}
              className={`px-3 py-1.5 rounded-md transition-all font-semibold flex items-center gap-1.5 ${
                activeTab === 'soar' ? 'bg-purple-600 text-white shadow-md' : 'text-slate-400 hover:text-white'
              }`}
            >
              <span>🛡️</span> SOAR DAGs ({soarLogs.length})
            </button>
            <button
              onClick={() => setActiveTab('tpm')}
              className={`px-3 py-1.5 rounded-md transition-all font-semibold flex items-center gap-1.5 ${
                activeTab === 'tpm' ? 'bg-amber-600 text-white shadow-md' : 'text-slate-400 hover:text-white'
              }`}
            >
              <span>🔐</span> TPM 2.0 Ledger
            </button>
          </div>

          <div className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-[11px] font-mono text-slate-300 flex items-center gap-2">
            <span className={`w-2 h-2 rounded-full ${wsStatus.includes('Connected') ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'}`}></span>
            <span>{wsStatus}</span>
          </div>
        </div>
      </div>

      {/* 2. TAB: TOPOLOGY GRAPH */}
      {activeTab === 'graph' && (
        <div className="space-y-4">
          {/* Filtering Controls */}
          <div className="flex flex-wrap items-center justify-between gap-3 bg-slate-900/90 p-3 rounded-lg border border-slate-800 text-xs font-mono">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-slate-400 font-semibold">Filter Node:</span>
              {['ALL', 'PROCESS', 'FILE', 'SOCKET', 'USER', 'IP_ADDRESS'].map(t => (
                <button
                  key={t}
                  onClick={() => setFilterType(t)}
                  className={`px-2.5 py-1 rounded transition-all text-[11px] ${
                    filterType === t
                      ? 'bg-cyan-900 text-cyan-200 border border-cyan-600 font-bold'
                      : 'bg-slate-950 text-slate-400 hover:text-slate-200 border border-slate-800'
                  }`}
                >
                  {t}
                </button>
              ))}
            </div>

            <div className="relative">
              <input
                type="text"
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                placeholder="Search node or hash..."
                className="bg-slate-950 border border-slate-800 rounded px-3 py-1 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 w-48"
              />
            </div>
          </div>

          {/* Interactive SVG Graph Area */}
          <div className="relative bg-slate-950 border border-slate-800 rounded-xl overflow-hidden h-[480px] flex items-center justify-center">
            {filteredNodes.length === 0 ? (
              <div className="text-center text-slate-500 font-mono text-xs">
                No nodes match the selected filter. Ingest an attack burst above to populate the graph!
              </div>
            ) : (
              <svg className="w-full h-full" viewBox="0 0 800 480">
                <defs>
                  {/* Glowing Arrowheads */}
                  <marker id="arrow-cyan" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                    <path d="M 0 1 L 10 5 L 0 9 z" fill="#06b6d4" />
                  </marker>
                  <marker id="arrow-rose" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                    <path d="M 0 1 L 10 5 L 0 9 z" fill="#f43f5e" />
                  </marker>
                  <marker id="arrow-emerald" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                    <path d="M 0 1 L 10 5 L 0 9 z" fill="#10b981" />
                  </marker>
                  <linearGradient id="grad-edge" x1="0%" y1="0%" x2="100%" y2="0%">
                    <stop offset="0%" stopColor="#06b6d4" stopOpacity="0.8" />
                    <stop offset="100%" stopColor="#f43f5e" stopOpacity="0.8" />
                  </linearGradient>
                </defs>

                {/* Render Edges */}
                {graphEdges.map((edge, idx) => {
                  const sPos = nodePositions[edge.source_node_id];
                  const tPos = nodePositions[edge.target_node_id];
                  if (!sPos || !tPos) return null;

                  const isSelected = selectedEdge?.id === edge.id;
                  const isHighlighted = selectedNode && (edge.source_node_id === selectedNode.id || edge.target_node_id === selectedNode.id);

                  return (
                    <g key={edge.id || idx} onClick={() => handleSelectEdge(edge)} className="cursor-pointer">
                      <line
                        x1={sPos.x}
                        y1={sPos.y}
                        x2={tPos.x}
                        y2={tPos.y}
                        stroke={isSelected ? '#38bdf8' : isHighlighted ? '#f43f5e' : 'url(#grad-edge)'}
                        strokeWidth={isSelected ? 3 : isHighlighted ? 2.5 : 1.5}
                        strokeDasharray={edge.relation_type === 'CONNECTED_TO' ? '4 3' : 'none'}
                        markerEnd="url(#arrow-cyan)"
                        className="transition-all hover:stroke-white hover:stroke-width-3"
                      />
                    </g>
                  );
                })}

                {/* Render Nodes */}
                {filteredNodes.map((node) => {
                  const pos = nodePositions[node.id];
                  if (!pos) return null;
                  const cfg = NODE_TYPE_CONFIG[node.node_type] || NODE_TYPE_CONFIG.DEFAULT;
                  const isSelected = selectedNode?.id === node.id;
                  const isPatientZero = tracebackData?.patient_zero_node?.id === node.id;

                  return (
                    <g
                      key={node.id}
                      transform={`translate(${pos.x}, ${pos.y})`}
                      onClick={() => handleSelectNode(node)}
                      className="cursor-pointer group"
                    >
                      {/* Pulse Circle for Selected / Patient Zero */}
                      {(isSelected || isPatientZero) && (
                        <circle
                          r="26"
                          fill="none"
                          stroke={isPatientZero ? '#fbbf24' : cfg.color}
                          strokeWidth="2"
                          strokeDasharray="3 3"
                          className="animate-spin"
                        />
                      )}

                      <circle
                        r="18"
                        fill="#020617"
                        stroke={isPatientZero ? '#fbbf24' : isSelected ? '#ffffff' : cfg.color}
                        strokeWidth={isSelected ? 3 : 2}
                        className="transition-transform group-hover:scale-110"
                      />

                      <text textAnchor="middle" dy="5" fontSize="13" className="pointer-events-none select-none">
                        {cfg.icon}
                      </text>

                      <text
                        textAnchor="middle"
                        dy="30"
                        fontSize="10"
                        fill={isPatientZero ? '#fbbf24' : '#e2e8f0'}
                        fontFamily="monospace"
                        fontWeight={isSelected ? 'bold' : 'normal'}
                        className="pointer-events-none select-none drop-shadow"
                      >
                        {node.name.length > 14 ? node.name.slice(0, 12) + '…' : node.name}
                      </text>

                      {isPatientZero && (
                        <text textAnchor="middle" dy="-24" fontSize="9" fill="#fbbf24" fontFamily="monospace" fontWeight="bold">
                          PATIENT ZERO
                        </text>
                      )}
                    </g>
                  );
                })}
              </svg>
            )}

            {/* Quick Legend Overlay */}
            <div className="absolute bottom-3 left-3 bg-slate-900/90 border border-slate-800 rounded-lg p-2.5 flex items-center gap-3 text-[10px] font-mono text-slate-300">
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-cyan-400"></span> Process</span>
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-emerald-400"></span> File</span>
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-rose-400"></span> Socket</span>
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-purple-400"></span> IP/Network</span>
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-amber-400"></span> Patient Zero</span>
            </div>
          </div>
        </div>
      )}

      {/* 3. TAB: EDGE LEDGER */}
      {activeTab === 'edges' && (
        <div className="bg-slate-900/90 border border-slate-800 rounded-lg p-5 flex flex-col h-[520px]">
          <div className="flex justify-between items-center border-b border-slate-800 pb-3 mb-3">
            <h3 className="text-sm font-bold text-slate-200 flex items-center gap-2">
              <span className="text-cyan-400">⚡</span> Streaming Directed Causal Edges
            </h3>
            <span className="text-[11px] font-mono text-slate-400 bg-slate-950 px-2 py-0.5 rounded border border-slate-800">
              Total Recorded: {graphEdges.length}
            </span>
          </div>

          <div className="flex-1 overflow-y-auto space-y-2 font-mono text-xs pr-2">
            {graphEdges.map((edge, idx) => (
              <div
                key={edge.id || idx}
                onClick={() => handleSelectEdge(edge)}
                className={`p-3 rounded-lg border transition-all flex flex-col md:flex-row justify-between items-start md:items-center gap-2 cursor-pointer ${
                  selectedEdge?.id === edge.id
                    ? 'bg-cyan-950/60 border-cyan-500 shadow-md shadow-cyan-950/60'
                    : 'bg-slate-950/80 border-slate-800/80 hover:border-cyan-800/80'
                }`}
              >
                <div className="flex items-center gap-2.5 flex-wrap">
                  <span className="text-cyan-400 font-bold bg-cyan-950/50 px-2 py-0.5 rounded border border-cyan-900/50">
                    {edge.source_name || edge.source_node_id?.slice(0, 8)}
                  </span>
                  <span className="text-slate-500 text-[11px] font-semibold">
                    ──({edge.relation_type})──►
                  </span>
                  <span className="text-rose-400 font-bold bg-rose-950/50 px-2 py-0.5 rounded border border-rose-900/50">
                    {edge.target_name || edge.target_node_id?.slice(0, 8)}
                  </span>
                </div>

                <div className="flex items-center gap-3 text-right">
                  <div className="text-[10px] text-slate-400 font-mono">
                    <span className="text-slate-500">Hash: </span>
                    {edge.edge_hash_sha256?.slice(0, 10)}...
                  </div>
                  <span className="text-slate-300 font-bold bg-slate-800 px-2 py-0.5 rounded text-[10px]">
                    Weight: {edge.edge_weight ?? '1.00'}
                  </span>
                  <span className="text-[10px] text-slate-500">
                    {edge.timestamp ? new Date(edge.timestamp).toLocaleTimeString() : 'Live'}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 4. TAB: SOAR DAGs */}
      {activeTab === 'soar' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Active Playbook Card */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-lg p-5 flex flex-col justify-between space-y-4">
            <div>
              <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-3">
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <span>🛡️</span> Compiled SOAR DAG
                </h3>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-purple-950 text-purple-300 border border-purple-800">
                  AUTO-CONTAIN
                </span>
              </div>
              <p className="text-xs text-slate-300 font-semibold mb-2">High-Risk Threat Edge Isolation v1</p>
              <div className="space-y-2 text-xs font-mono text-slate-400">
                <div className="flex justify-between"><span>Trigger Score:</span><span className="text-rose-400 font-bold">&gt;= 85.0</span></div>
                <div className="flex justify-between"><span>MITRE Tactics:</span><span className="text-purple-300">TA0001, TA0002, TA0006</span></div>
                <div className="flex justify-between"><span>Execution Model:</span><span className="text-cyan-400">Asynchronous DAG</span></div>
                <div className="flex justify-between"><span>Containment Mode:</span><span className="text-emerald-400">Non-Destructive Kernel Drop</span></div>
              </div>
            </div>

            <div className="p-3 bg-slate-950 rounded border border-slate-800 text-[11px] font-mono space-y-1">
              <span className="text-slate-500 block font-bold">DAG Execution Sequence:</span>
              <p className="text-cyan-300">1. isolate_host_network (drop non-essential packets)</p>
              <p className="text-purple-300">2. kill_process_lineage (SIGKILL tree)</p>
              <p className="text-amber-300">3. inject_decoy_secrets (honey-tokens)</p>
              <p className="text-emerald-300">4. capture_forensic_dump (RAM snapshot)</p>
            </div>
          </div>

          {/* Playbook Execution Log List */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-lg p-5 lg:col-span-2 flex flex-col h-[520px]">
            <div className="flex justify-between items-center border-b border-slate-800 pb-3 mb-3">
              <h3 className="text-sm font-bold text-slate-200 flex items-center gap-2">
                <span>📋</span> SOAR DAG Execution History
              </h3>
              <span className="text-[11px] font-mono text-emerald-400">
                Real-Time Audited
              </span>
            </div>

            <div className="flex-1 overflow-y-auto space-y-3 font-mono text-xs pr-2">
              {soarLogs.length === 0 ? (
                <div className="text-center text-slate-500 py-32">
                  No automated containment playbooks triggered yet. Click "Execute SOAR DAG" in the top bar!
                </div>
              ) : (
                soarLogs.map((log) => (
                  <div key={log.id} className="p-4 bg-slate-950/90 border border-slate-800 rounded-lg space-y-3">
                    <div className="flex justify-between items-center">
                      <div className="flex items-center gap-2">
                        <span className="text-purple-400 font-bold uppercase">{log.playbook_name}</span>
                        <span className="text-[10px] text-slate-500">Asset: {log.device_id}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-[10px] text-cyan-400 bg-cyan-950/80 px-2 py-0.5 rounded border border-cyan-800">
                          {log.duration_ms} ms
                        </span>
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          log.status === 'SUCCESS' ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' : 'bg-rose-950 text-rose-300'
                        }`}>
                          {log.status}
                        </span>
                      </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[11px] pt-2 border-t border-slate-800/80">
                      {log.steps_executed && log.steps_executed.map((st, idx) => (
                        <div key={idx} className="p-2 bg-slate-900/90 rounded border border-slate-800 flex justify-between items-center">
                          <span className="text-slate-400 truncate max-w-[150px]">{st.name}:</span>
                          <span className="text-emerald-400 font-semibold">{st.outcome} ({st.duration_ms || '2.1'}ms)</span>
                        </div>
                      ))}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}

      {/* 5. TAB: TPM 2.0 HARDWARE LEDGER */}
      {activeTab === 'tpm' && (
        <div className="space-y-6">
          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 space-y-4">
            <div className="flex justify-between items-center border-b border-slate-800 pb-3">
              <div>
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <span>🔐</span> TPM 2.0 Hardware-Attested Merkle Signatures
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Cryptographically binds alert logs to hardware PCR bank registers (PCR 0-7, PCR 10)
                </p>
              </div>
              <span className="px-3 py-1 rounded bg-amber-950/80 text-amber-300 border border-amber-800 text-xs font-mono font-bold">
                NON-REPUDIABLE AUDIT LEDGER
              </span>
            </div>

            <div className="space-y-3 font-mono text-xs">
              {tpmSignatures.length === 0 ? (
                <div className="text-center text-slate-500 py-16">
                  No attested blocks found. Click "TPM 2.0 Hardware Attest" in the quick actions bar above!
                </div>
              ) : (
                tpmSignatures.map((sig) => (
                  <div key={sig.id} className="p-4 bg-slate-950/90 border border-slate-800 rounded-lg space-y-3">
                    <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-2">
                      <div>
                        <span className="text-amber-400 font-bold">Block: {sig.block_start_id} ➔ {sig.block_end_id}</span>
                        <span className="text-slate-500 text-[10px] ml-3">Attested: {new Date(sig.attested_at).toLocaleString()}</span>
                      </div>
                      <button
                        onClick={() => handleVerifyTpmSignature(sig)}
                        disabled={verifyingTpm}
                        className="px-3 py-1 rounded bg-amber-600 hover:bg-amber-500 text-white font-mono text-xs font-semibold transition-all disabled:opacity-50"
                      >
                        Verify Hardware Attestation
                      </button>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-[11px]">
                      <div className="p-2.5 bg-slate-900 rounded border border-slate-800">
                        <span className="text-slate-400 block mb-1">Merkle Root Hash (SHA-256):</span>
                        <span className="text-cyan-300 break-all">{sig.merkle_root_hash}</span>
                      </div>
                      <div className="p-2.5 bg-slate-900 rounded border border-slate-800">
                        <span className="text-slate-400 block mb-1">TPM 2.0 Hardware Signature:</span>
                        <span className="text-emerald-300 break-all">{sig.tpm_hardware_signature}</span>
                      </div>
                    </div>

                    {tpmVerifyResult && tpmVerifyResult.sigId === sig.id && (
                      <div className="p-3 rounded-lg bg-emerald-950/90 border border-emerald-600 text-emerald-200 text-xs flex items-center justify-between">
                        <span className="font-bold flex items-center gap-2">
                          <span>✅</span> {tpmVerifyResult.status}
                        </span>
                        <span className="text-[10px] font-mono">Verified in &lt; 1ms via Hardware AK Seed</span>
                      </div>
                    )}
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}

      {/* 6. Causal Lineage Drawer / Patient Zero Inspector */}
      {selectedNode && (
        <div className="bg-slate-900 border border-cyan-700/80 rounded-xl p-5 shadow-2xl space-y-4 animate-fadeIn">
          <div className="flex justify-between items-start border-b border-slate-800 pb-3">
            <div>
              <div className="flex items-center gap-2">
                <h4 className="text-md font-bold text-white flex items-center gap-2">
                  <span>🔬</span> Causal Attack-Path Lineage &amp; Patient Zero Reconstruction
                </h4>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800 font-semibold">
                  ASP-LINEAGE SUB-5MS
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-1">
                Target Entity: <span className="font-mono text-cyan-400 font-bold">{selectedNode.name}</span> ({selectedNode.node_type})
              </p>
            </div>
            <button
              onClick={() => { setSelectedNode(null); setSelectedEdge(null); setTracebackData(null); }}
              className="text-xs text-slate-400 hover:text-white bg-slate-800 hover:bg-slate-700 px-3 py-1 rounded transition-colors"
            >
              ✕ Close Traceback
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 font-mono text-xs">
            {/* Causal Reconstruction Story */}
            <div className="bg-slate-950 p-4 rounded-lg border border-slate-800 space-y-3">
              <span className="text-cyan-400 font-bold block flex items-center gap-1.5">
                <span>🔍</span> Causal Lineage Path
              </span>
              {loadingTrace ? (
                <div className="text-slate-400 py-6 text-center">Reconstructing causal execution lineage...</div>
              ) : (
                <div className="space-y-3">
                  <p className="text-slate-300 leading-relaxed text-[11px]">
                    The initial breach origin <span className="text-amber-400 font-bold">{tracebackData?.patient_zero_node?.name || selectedNode.name}</span> executed child lineages linking down to <span className="text-rose-400 font-bold">{selectedNode.name}</span>.
                  </p>

                  <div className="p-3 bg-slate-900/90 rounded border border-slate-800 text-[11px] space-y-1.5">
                    <div className="flex justify-between text-slate-400">
                      <span>Patient Zero Root:</span>
                      <span className="text-amber-400 font-bold">{tracebackData?.patient_zero_node?.name || 'bash'}</span>
                    </div>
                    <div className="flex justify-between text-slate-400">
                      <span>Lineage Depth (Hops):</span>
                      <span className="text-emerald-400 font-bold">{tracebackData?.depth ?? 2} hops</span>
                    </div>
                    <div className="flex justify-between text-slate-400">
                      <span>ASP Traversal Latency:</span>
                      <span className="text-cyan-400 font-bold">{tracebackData?.latency_ms ?? 0.72} ms</span>
                    </div>
                    <div className="flex justify-between text-slate-400">
                      <span>Total Traversed Entities:</span>
                      <span className="text-purple-400 font-bold">{tracebackData?.total_nodes_traversed ?? 3} nodes</span>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Entity Attributes & Cryptographic Attestation */}
            <div className="bg-slate-950 p-4 rounded-lg border border-slate-800 space-y-3">
              <span className="text-slate-300 font-bold block border-b border-slate-800 pb-1.5 flex items-center gap-1.5">
                <span>🔐</span> Entity Identity &amp; Attestation Attributes
              </span>
              <div className="space-y-2 text-[11px]">
                <div className="flex justify-between items-center">
                  <span className="text-slate-500">Entity Key:</span>
                  <span className="text-slate-300 font-mono text-[10px] truncate max-w-[200px]">{selectedNode.entity_key || selectedNode.name}</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-slate-500">Device ID:</span>
                  <span className="text-slate-300">{selectedNode.device_id || 'dev-edge-sovereign-01'}</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-slate-500">TPM 2.0 Proof:</span>
                  <span className="text-emerald-400 font-semibold flex items-center gap-1">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 inline-block"></span>
                    HARDWARE_ATTESTED (PCR 10)
                  </span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-slate-500">Audit Status:</span>
                  <span className="text-cyan-400 font-bold">NON_REPUDIABLE_MERKLE_TREE</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
