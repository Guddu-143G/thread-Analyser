import React, { useState, useEffect, useRef } from 'react';

export default function RealTimeSOCConsole({ orgId = '00000000-0000-0000-0000-000000000001' }) {
  const [connectionStatus, setConnectionStatus] = useState('CONNECTING');
  const [gpsMetrics, setGpsMetrics] = useState({
    state: 'STATIONARY',
    speed: 0.0,
    distance: 0.0,
    battery_pct: 95.0,
    next_interval: 300
  });
  const [networkAudit, setNetworkAudit] = useState({
    ip: '192.168.1.144',
    mac: '00:0a:95:9d:68:16',
    interface: 'wlan0',
    gatewayIp: '192.168.1.1',
    gatewayMac: 'a0:04:cb:11:ff:dd',
    arpMitmDetected: false
  });
  const [basebandStatus, setBasebandStatus] = useState({
    imei: '864201047192834',
    operator: 'Jio 4G (404/869)',
    cellId: '40121',
    timingAdvance: 4,
    triangulatedLat: 37.7752,
    triangulatedLon: -122.4196,
    ceirStatus: 'CLEAN'
  });
  const [ledgerVerified, setLedgerVerified] = useState(true);
  const [ledgerDetails, setLedgerDetails] = useState({
    total_blocks: 1,
    last_hash: '0000000000000000000000000000000000000000000000000000000000000000'
  });
  const [logEvents, setLogEvents] = useState([]);
  const wsRef = useRef(null);

  useEffect(() => {
    let reconnectTimeout = null;

    const connectWs = () => {
      try {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        // Connect to FastAPI backend
        const host = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1' 
          ? 'localhost:8000' 
          : window.location.host;
        const wsUrl = `${protocol}//${host}/api/v24/live?org_id=${orgId}`;

        const ws = new WebSocket(wsUrl);
        wsRef.current = ws;

        ws.onopen = () => {
          setConnectionStatus('CONNECTED');
          // Add initial connection event
          setLogEvents(prev => [
            {
              timestamp: new Date().toLocaleTimeString(),
              message: `WebSocket connected to V24 SOC telemetry stream [org_id: ${orgId.slice(0, 8)}...]`,
              action: 'WS_CONNECTED',
              severity: 'info'
            },
            ...prev.slice(0, 49)
          ]);
        };

        ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            if (data.status === 'HEARTBEAT_ACK') return;

            // GPS update event
            if (data.type === 'GPS_UPDATE' || data.event === 'GPS_UPDATE') {
              const m = data.metrics || data.data || {};
              setGpsMetrics({
                state: m.state || 'TRANSIT',
                speed: m.speed_kmh !== undefined ? m.speed_kmh : (m.speed !== undefined ? m.speed : 0),
                distance: m.distance_to_center_m !== undefined ? m.distance_to_center_m : (m.distance || 0),
                battery_pct: m.battery_pct !== undefined ? m.battery_pct : 88.0,
                next_interval: m.next_scheduled_interval || m.next_interval || 15
              });
            }

            // Network audit event
            if (data.type === 'NETWORK_AUDIT' || data.event === 'NETWORK_AUDIT') {
              const iface = data.interface || data.data || {};
              setNetworkAudit({
                ip: iface.ip || iface.ip_address || '192.168.1.144',
                mac: iface.mac || iface.mac_address || '00:0a:95:9d:68:16',
                interface: iface.name || iface.interface_name || 'wlan0',
                gatewayIp: iface.gateway_ip || '192.168.1.1',
                gatewayMac: iface.gateway_mac || iface.current_gateway_mac || 'a0:04:cb:11:ff:dd',
                arpMitmDetected: Boolean(iface.arp_mitm_detected || data.arp_mitm_detected)
              });
            }

            // Baseband & Cellular event
            if (data.type === 'BASEBAND_TELEMETRY' || data.event === 'BASEBAND_TELEMETRY') {
              const bb = data.data || data.telemetry || {};
              setBasebandStatus({
                imei: bb.imei || '864201047192834',
                operator: bb.operator_name || 'Jio 4G',
                cellId: bb.active_cell_id ? String(bb.active_cell_id) : '40121',
                timingAdvance: bb.timing_advance || 4,
                triangulatedLat: bb.triangulated_latitude || 37.7752,
                triangulatedLon: bb.triangulated_longitude || -122.4196,
                ceirStatus: bb.ceir_status || 'CLEAN'
              });
            }

            // Ledger Tamper Alert
            if (data.type === 'LEDGER_TAMPER_ALERT' || data.event === 'LEDGER_TAMPER_ALERT') {
              setLedgerVerified(false);
              setLogEvents(prev => [
                {
                  timestamp: new Date().toLocaleTimeString(),
                  message: `CRITICAL: Merkle hash chain breach detected at sequence #${data.sequence_id || 'N/A'}!`,
                  action: 'TAMPER_ALERT',
                  severity: 'critical'
                },
                ...prev.slice(0, 49)
              ]);
            }

            // Ledger Update
            if (data.type === 'LEDGER_UPDATE' || data.event === 'LEDGER_UPDATE') {
              setLedgerVerified(true);
              setLedgerDetails({
                total_blocks: data.total_blocks || 1,
                last_hash: data.current_ledger_hash || 'SHA256_VERIFIED'
              });
            }

            // Append raw event logs
            if (data.log) {
              setLogEvents(prev => [data.log, ...prev.slice(0, 49)]);
            } else if (data.message) {
              setLogEvents(prev => [
                {
                  timestamp: new Date().toLocaleTimeString(),
                  message: data.message,
                  action: data.type || data.event || 'TELEMETRY',
                  severity: data.severity || 'info'
                },
                ...prev.slice(0, 49)
              ]);
            }
          } catch (err) {
            console.error('Failed to parse WebSocket message:', err);
          }
        };

        ws.onclose = () => {
          setConnectionStatus('DISCONNECTED');
          // Attempt auto-reconnect after 4s
          reconnectTimeout = setTimeout(connectWs, 4000);
        };

        ws.onerror = () => {
          setConnectionStatus('ERROR');
        };
      } catch (err) {
        setConnectionStatus('FAILED');
      }
    };

    connectWs();

    return () => {
      if (reconnectTimeout) clearTimeout(reconnectTimeout);
      if (wsRef.current) wsRef.current.close();
    };
  }, [orgId]);

  return (
    <div className="bg-slate-950 p-5 rounded-xl text-slate-100 font-mono border border-slate-800 shadow-2xl">
      {/* 1. Header Banner */}
      <div className="flex flex-wrap justify-between items-center border-b border-slate-800 pb-3.5 mb-4 gap-2">
        <div className="flex items-center gap-2.5">
          <span className="text-xl text-emerald-400">⚡</span>
          <div>
            <h2 className="text-base font-bold text-emerald-400 tracking-wide">
              Real-Time Asset &amp; Cryptographic Log Tracker
            </h2>
            <p className="text-[11px] text-slate-400 font-mono">
              V24 WebSocket Engine &bull; Adaptive GPS &bull; MAC/IP Guard &bull; Merkle Ledger
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <span
            className={`px-2.5 py-1 rounded text-[11px] font-bold tracking-wider flex items-center gap-1.5 ${
              connectionStatus === 'CONNECTED'
                ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                : connectionStatus === 'CONNECTING'
                ? 'bg-amber-500/15 text-amber-400 border border-amber-500/30'
                : 'bg-rose-500/15 text-rose-400 border border-rose-500/30'
            }`}
          >
            <span
              className={`w-2 h-2 rounded-full ${
                connectionStatus === 'CONNECTED'
                  ? 'bg-emerald-400 animate-pulse'
                  : connectionStatus === 'CONNECTING'
                  ? 'bg-amber-400 animate-ping'
                  : 'bg-rose-400'
              }`}
            ></span>
            STATUS: {connectionStatus}
          </span>
        </div>
      </div>

      {/* 2. Live Grid Metrics (4 Cards) */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3.5 mb-5">
        {/* GPS Scheduler Status Card */}
        <div className="bg-slate-900/90 p-3.5 rounded-lg border border-slate-800 hover:border-amber-500/40 transition-all">
          <div className="flex items-center justify-between mb-1">
            <h3 className="text-[11px] text-slate-400 font-bold uppercase tracking-wider">GPS Scheduler</h3>
            <span className="text-[10px] text-amber-400 bg-amber-950/80 px-1.5 py-0.5 rounded border border-amber-800/60">
              {gpsMetrics.next_interval}s interval
            </span>
          </div>
          <p className="text-lg font-bold text-amber-400 mt-1">{gpsMetrics.state}</p>
          <div className="text-[11px] text-slate-400 mt-2 space-y-1">
            <div className="flex justify-between">
              <span>Velocity:</span>
              <span className="text-slate-200 font-semibold">{gpsMetrics.speed} km/h</span>
            </div>
            <div className="flex justify-between">
              <span>Geofence Dist:</span>
              <span className="text-slate-200 font-semibold">{gpsMetrics.distance}m</span>
            </div>
            <div className="flex justify-between">
              <span>Battery:</span>
              <span className={`font-semibold ${gpsMetrics.battery_pct < 20 ? 'text-rose-400' : 'text-emerald-400'}`}>
                {gpsMetrics.battery_pct}%
              </span>
            </div>
          </div>
        </div>

        {/* Network Interface Audit Card */}
        <div className="bg-slate-900/90 p-3.5 rounded-lg border border-slate-800 hover:border-blue-500/40 transition-all">
          <div className="flex items-center justify-between mb-1">
            <h3 className="text-[11px] text-slate-400 font-bold uppercase tracking-wider">Network Audit</h3>
            {networkAudit.arpMitmDetected ? (
              <span className="text-[10px] text-rose-400 bg-rose-950 px-1.5 py-0.5 rounded border border-rose-800 animate-pulse font-bold">
                ARP MITM
              </span>
            ) : (
              <span className="text-[10px] text-blue-400 bg-blue-950 px-1.5 py-0.5 rounded border border-blue-800">
                {networkAudit.interface}
              </span>
            )}
          </div>
          <p className="text-sm font-bold text-blue-400 mt-1 truncate">IP: {networkAudit.ip}</p>
          <div className="text-[11px] text-slate-400 mt-2 space-y-1">
            <div className="flex justify-between truncate">
              <span>MAC:</span>
              <span className="text-slate-200 font-mono text-[10px] truncate max-w-[120px]">{networkAudit.mac}</span>
            </div>
            <div className="flex justify-between truncate">
              <span>GW BSSID:</span>
              <span className="text-slate-200 font-mono text-[10px] truncate max-w-[120px]">{networkAudit.gatewayMac}</span>
            </div>
            <div className="flex justify-between">
              <span>Gateway IP:</span>
              <span className="text-slate-200 text-[10px]">{networkAudit.gatewayIp}</span>
            </div>
          </div>
        </div>

        {/* Baseband Modem Card */}
        <div className="bg-slate-900/90 p-3.5 rounded-lg border border-slate-800 hover:border-cyan-500/40 transition-all">
          <div className="flex items-center justify-between mb-1">
            <h3 className="text-[11px] text-slate-400 font-bold uppercase tracking-wider">Baseband Cellular</h3>
            <span className={`text-[10px] px-1.5 py-0.5 rounded border ${
              basebandStatus.ceirStatus === 'CLEAN' 
                ? 'text-emerald-400 bg-emerald-950 border-emerald-800' 
                : 'text-rose-400 bg-rose-950 border-rose-800'
            }`}>
              CEIR: {basebandStatus.ceirStatus}
            </span>
          </div>
          <p className="text-sm font-bold text-cyan-400 mt-1 truncate">
            IMEI: {basebandStatus.imei}
          </p>
          <div className="text-[11px] text-slate-400 mt-2 space-y-1">
            <div className="flex justify-between truncate">
              <span>Carrier:</span>
              <span className="text-slate-200 text-[10px] truncate max-w-[110px]">{basebandStatus.operator}</span>
            </div>
            <div className="flex justify-between">
              <span>Cell ID / TA:</span>
              <span className="text-slate-200 font-mono text-[10px]">{basebandStatus.cellId} (TA: {basebandStatus.timingAdvance})</span>
            </div>
            <div className="flex justify-between">
              <span>Coords (No GPS):</span>
              <span className="text-slate-200 font-mono text-[10px]">
                {basebandStatus.triangulatedLat.toFixed(4)}, {basebandStatus.triangulatedLon.toFixed(4)}
              </span>
            </div>
          </div>
        </div>

        {/* Merkle Ledger Status Card */}
        <div className="bg-slate-900/90 p-3.5 rounded-lg border border-slate-800 hover:border-emerald-500/40 transition-all">
          <div className="flex items-center justify-between mb-1">
            <h3 className="text-[11px] text-slate-400 font-bold uppercase tracking-wider">Ledger Integrity</h3>
            <span className="text-[10px] text-indigo-400 bg-indigo-950 px-1.5 py-0.5 rounded border border-indigo-800">
              SHA-256 Chain
            </span>
          </div>
          <p
            className={`text-lg font-bold mt-1 ${
              ledgerVerified ? 'text-emerald-400' : 'text-rose-500 animate-pulse'
            }`}
          >
            {ledgerVerified ? 'VERIFIED' : 'TAMPER_DETECTED'}
          </p>
          <div className="text-[11px] text-slate-400 mt-2 space-y-1">
            <div className="flex justify-between">
              <span>Blocks Chained:</span>
              <span className="text-slate-200 font-mono">{ledgerDetails.total_blocks}</span>
            </div>
            <div className="flex justify-between truncate">
              <span>Last Hash:</span>
              <span className="text-slate-200 font-mono text-[9px] truncate max-w-[120px]">
                {ledgerDetails.last_hash.slice(0, 16)}...
              </span>
            </div>
            <p className="text-[10px] text-slate-500 truncate">
              {ledgerVerified ? 'Cryptographic parent hashes aligned.' : 'CRITICAL: Hash mismatch in ledger!'}
            </p>
          </div>
        </div>
      </div>

      {/* 3. Scrolling Event Logs */}
      <div>
        <div className="flex items-center justify-between mb-2">
          <h3 className="text-xs text-slate-400 font-bold uppercase tracking-wider flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span>
            Live Compliance Audit Trail &amp; Sensor Telemetry
          </h3>
          <span className="text-[10px] text-slate-500 font-mono">
            Buffered Events: {logEvents.length}
          </span>
        </div>

        <div className="bg-slate-900 p-3 rounded-lg border border-slate-800 h-44 overflow-y-auto space-y-1.5 text-xs font-mono">
          {logEvents.length === 0 ? (
            <div className="text-slate-600 text-center py-14 italic">
              Listening for real-time tracking events, baseband modems, and Merkle transactions...
            </div>
          ) : (
            logEvents.map((ev, i) => (
              <div
                key={i}
                className="flex items-center justify-between border-b border-slate-800/50 pb-1 hover:bg-slate-800/40 px-1 rounded transition-colors"
              >
                <span className="text-emerald-400 text-[11px] w-20 shrink-0">{ev.timestamp}</span>
                <span className="text-slate-300 px-2 flex-1 truncate text-[11px]">
                  {ev.message}
                </span>
                <span
                  className={`text-[10px] font-bold px-1.5 py-0.5 rounded shrink-0 ${
                    ev.severity === 'critical'
                      ? 'bg-rose-950 text-rose-300 border border-rose-800'
                      : ev.severity === 'warning'
                      ? 'bg-amber-950 text-amber-300 border border-amber-800'
                      : 'bg-blue-950 text-blue-300 border border-blue-800'
                  }`}
                >
                  {ev.action}
                </span>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
