import { useEffect, useState } from 'react'
import client from '../api/client'

export default function BluetoothGuard() {
  const [threats, setThreats] = useState([])
  const [hciStatus, setHciStatus] = useState(null)
  const [loading, setLoading] = useState(true)
  const [simulating, setSimulating] = useState(false)
  const [feedback, setFeedback] = useState(null)
  const [containmentTarget, setContainmentTarget] = useState(null)

  const loadData = () => {
    Promise.all([
      client.get('/bluetooth/threats'),
      client.get('/bluetooth/status'),
    ])
      .then(([threatsRes, statusRes]) => {
        setThreats(threatsRes.data || [])
        setHciStatus(statusRes.data || {})
      })
      .catch((err) => {
        console.error('Failed to load Bluetooth telemetry:', err)
      })
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    loadData()
    const interval = setInterval(loadData, 8000)
    return () => clearInterval(interval)
  }, [])

  const handleSimulateAttack = async (vector) => {
    setSimulating(true)
    try {
      const { data } = await client.post('/bluetooth/simulate-attack', {
        exploit_vector: vector,
        source_mac: '00:1A:7D:DA:' + Math.floor(10 + Math.random() * 89) + ':' + Math.floor(10 + Math.random() * 89),
      })
      setFeedback({
        type: 'success',
        title: `🚨 ${data.threat_details?.anomaly_type || 'Attack Intercepted'}`,
        message: data.containment_response?.verdict || 'Attacker MAC instantly dropped and blocked by HCI Guard.',
      })
      loadData()
      setTimeout(() => setFeedback(null), 9000)
    } catch (err) {
      setFeedback({
        type: 'error',
        title: 'Simulation Failed',
        message: err.response?.data?.detail || err.message,
      })
    } finally {
      setSimulating(false)
    }
  }

  const handleContainMac = async (mac, action = 'block_mac') => {
    setContainmentTarget(mac)
    try {
      const { data } = await client.post('/bluetooth/contain', {
        attacker_mac: mac,
        action: action,
        interface: hciStatus?.interface || 'hci0',
      })
      setFeedback({
        type: 'success',
        title: 'Hardware Containment Dispatched',
        message: data.containment_verdict,
      })
      loadData()
      setTimeout(() => setFeedback(null), 6000)
    } catch (err) {
      setFeedback({
        type: 'error',
        title: 'Containment Failed',
        message: err.response?.data?.detail || err.message,
      })
    } finally {
      setContainmentTarget(null)
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
              <span>Bluetooth Module HCI Guard &amp; RF Edge SIEM</span>
              <span className="text-xs font-mono bg-blue-950 text-blue-300 px-2 py-0.5 rounded border border-blue-700 flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-blue-400 animate-pulse"></span>
                v9.0 Vanguard Layer
              </span>
            </h1>
          </div>
          <p className="text-slate-400 text-xs mt-0.5">
            Kernel-level raw Host Controller Interface (HCI) packet inspection, BlueBorne &amp; BleedingTooth prevention, and automated RFKill containment.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => handleContainMac('00:00:00:00:00:00', 'rfkill_radio')}
            className="bg-rose-950/80 hover:bg-rose-900 border border-rose-700 text-rose-200 text-xs px-3 py-2 rounded font-mono font-bold transition-all flex items-center gap-1.5 shadow-md"
          >
            <span>🔒</span>
            <span>Emergency RFKill Lockdown</span>
          </button>
        </div>
      </div>

      {/* Live Feedback Alert */}
      {feedback && (
        <div
          className={`p-4 rounded-xl border text-xs font-mono animate-fade-in ${
            feedback.type === 'success'
              ? 'bg-emerald-950/80 border-emerald-600 text-emerald-200'
              : 'bg-rose-950/80 border-rose-600 text-rose-200'
          }`}
        >
          <div className="font-bold text-sm mb-1">{feedback.title}</div>
          <div className="text-slate-300 font-sans">{feedback.message}</div>
        </div>
      )}

      {/* HCI Daemon Status Grid */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 font-mono">
        <div className="panel p-4 bg-base-900 border border-base-700 space-y-1">
          <div className="text-[10px] text-slate-500 uppercase">HCI Interface</div>
          <div className="text-base font-bold text-slate-100 flex items-center gap-2">
            <span>{hciStatus?.interface || 'hci0'}</span>
            <span className="text-[10px] bg-emerald-950 text-emerald-300 px-1.5 py-0.2 rounded border border-emerald-800">
              {hciStatus?.hardware_daemon || 'ONLINE'}
            </span>
          </div>
          <div className="text-[10px] text-slate-400">Driver: AF_BLUETOOTH RAW</div>
        </div>

        <div className="panel p-4 bg-base-900 border border-base-700 space-y-1">
          <div className="text-[10px] text-slate-500 uppercase">Radio Noise Floor</div>
          <div className="text-base font-bold text-cyan-300">{hciStatus?.noise_floor_rssi || -85} dBm</div>
          <div className="text-[10px] text-slate-400">Link Quality: {hciStatus?.current_link_quality || '98%'}</div>
        </div>

        <div className="panel p-4 bg-base-900 border border-base-700 space-y-1">
          <div className="text-[10px] text-slate-500 uppercase">Blocked Host MACs</div>
          <div className="text-base font-bold text-amber-300">{hciStatus?.active_blocked_macs?.length || 0} Filtered</div>
          <div className="text-[10px] text-slate-400">Zero-Trust Controller Drops</div>
        </div>

        <div className="panel p-4 bg-base-900 border border-base-700 space-y-1">
          <div className="text-[10px] text-slate-500 uppercase">RFKill Status</div>
          <div className="text-base font-bold text-emerald-400">
            {hciStatus?.rfkill_locked ? '🔒 LOCKED DOWN' : '🟢 ACTIVE MONITORING'}
          </div>
          <div className="text-[10px] text-slate-400">OCSF Class 6001 Live Stream</div>
        </div>
      </div>

      {/* Exploit Simulator Panel */}
      <div className="panel p-4 space-y-3 font-mono border border-blue-900/60 bg-gradient-to-r from-base-900 via-base-900 to-blue-950/30 rounded-xl">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-2 border-b border-base-800 pb-3">
          <div>
            <div className="flex items-center gap-2">
              <span className="text-blue-400 text-base">⚡</span>
              <h2 className="text-sm font-bold text-slate-100">Wireless Attack Vector Simulator</h2>
              <span className="text-[10px] bg-blue-950 text-blue-300 px-2 py-0.5 rounded border border-blue-800">
                Safe Red Team Tester
              </span>
            </div>
            <p className="text-[11px] text-slate-400 font-sans mt-0.5">
              Fire synthetic malformed L2CAP/SDP frames over simulated RF air-gaps to verify kernel prevention response latency.
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-1">
          <button
            onClick={() => handleSimulateAttack('BLUEBORNE_L2CAP_OVERFLOW')}
            disabled={simulating}
            className="p-3 bg-base-950 hover:bg-rose-950/40 border border-base-700 hover:border-rose-600 rounded-lg text-left transition-all space-y-1 group"
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-rose-300">BlueBorne Buffer Overflow</span>
              <span className="text-[9px] bg-rose-950 text-rose-300 px-1 rounded border border-rose-800">CVE-2017-1000251</span>
            </div>
            <p className="text-[10px] text-slate-400 font-sans">
              Transmits 65535-byte oversized L2CAP config frame on signaling channel (CID 0x0001).
            </p>
            <div className="text-[10px] text-accent group-hover:underline pt-1">⚡ Fire Simulation →</div>
          </button>

          <button
            onClick={() => handleSimulateAttack('BLEEDINGTOOTH_ZERO_CLICK')}
            disabled={simulating}
            className="p-3 bg-base-950 hover:bg-amber-950/40 border border-base-700 hover:border-amber-600 rounded-lg text-left transition-all space-y-1 group"
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-amber-300">BleedingTooth Zero-Click</span>
              <span className="text-[9px] bg-amber-950 text-amber-300 px-1 rounded border border-amber-800">CVE-2020-12351</span>
            </div>
            <p className="text-[10px] text-slate-400 font-sans">
              Injects malformed A2MP memory corruption frames to simulate privilege escalation.
            </p>
            <div className="text-[10px] text-accent group-hover:underline pt-1">⚡ Fire Simulation →</div>
          </button>

          <button
            onClick={() => handleSimulateAttack('BLE_ROGUE_PAIRING')}
            disabled={simulating}
            className="p-3 bg-base-950 hover:bg-purple-950/40 border border-base-700 hover:border-purple-600 rounded-lg text-left transition-all space-y-1 group"
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-purple-300">Rogue BLE Pairing Flood</span>
              <span className="text-[9px] bg-purple-950 text-purple-300 px-1 rounded border border-purple-800">SDP Impersonation</span>
            </div>
            <p className="text-[10px] text-slate-400 font-sans">
              Broadcasts rapid malicious SDP service descriptors to force unauthorized pairing.
            </p>
            <div className="text-[10px] text-accent group-hover:underline pt-1">⚡ Fire Simulation →</div>
          </button>
        </div>
      </div>

      {/* Intercepted Threats Table */}
      <div className="panel p-4 space-y-3 font-mono">
        <div className="flex items-center justify-between border-b border-base-800 pb-3">
          <div>
            <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <span>Intercepted RF Threats &amp; Controller Drops (OCSF Class 6001)</span>
              <span className="text-[10px] bg-base-950 text-slate-400 px-2 py-0.5 rounded border border-base-700">
                {threats.length} Events Logged
              </span>
            </h2>
            <p className="text-[11px] text-slate-400 font-sans mt-0.5">
              Live hardware controller audit trail of air-gap packets blocked at Layer 2.
            </p>
          </div>
        </div>

        {threats.length === 0 ? (
          <div className="p-8 text-center text-slate-500 text-xs">
            No wireless threats detected. Radio environment is clean. Run a simulation above to test the HCI Guard!
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-base-800 text-slate-500 uppercase text-[10px]">
                  <th className="py-2.5 px-3">Timestamp</th>
                  <th className="py-2.5 px-3">Attacker MAC</th>
                  <th className="py-2.5 px-3">Protocol / Sizing</th>
                  <th className="py-2.5 px-3">Threat Description</th>
                  <th className="py-2.5 px-3">RSSI</th>
                  <th className="py-2.5 px-3">Status</th>
                  <th className="py-2.5 px-3 text-right">Containment Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-base-800/60">
                {threats.map((t) => (
                  <tr key={t.id} className="hover:bg-base-950/60 transition-colors">
                    <td className="py-2.5 px-3 text-slate-400 text-[11px]">
                      {new Date(t.created_at).toLocaleTimeString()}
                    </td>
                    <td className="py-2.5 px-3 font-bold text-rose-300">
                      <code>{t.attacker_mac}</code>
                    </td>
                    <td className="py-2.5 px-3 text-slate-300">
                      <span className="text-cyan-300 font-bold">{t.protocol}</span>{' '}
                      <span className="text-slate-500">({t.payload_length_bytes} bytes)</span>
                    </td>
                    <td className="py-2.5 px-3 text-slate-200">
                      <div className="truncate max-w-xs">{t.anomaly_type}</div>
                      <div className="text-[10px] text-slate-500">{t.mitigation_action}</div>
                    </td>
                    <td className="py-2.5 px-3 text-amber-300 font-bold">{t.rssi} dBm</td>
                    <td className="py-2.5 px-3">
                      <span className="text-[10px] px-2 py-0.5 rounded font-bold bg-rose-950 text-rose-300 border border-rose-800">
                        {t.status}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-right">
                      <button
                        onClick={() => handleContainMac(t.attacker_mac, 'block_mac')}
                        disabled={containmentTarget === t.attacker_mac}
                        className="bg-base-950 hover:bg-rose-900/60 border border-rose-800/80 text-rose-200 text-[10px] px-2.5 py-1 rounded transition-colors font-bold"
                      >
                        {containmentTarget === t.attacker_mac ? 'Blocking...' : 'Re-Drop MAC'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
