import { NavLink } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'

const v20EdgeLinks = [
  { to: '/v20-edge', label: 'Edge Remediation & GPS', icon: '📡' },
]

const v19FleetLinks = [
  { to: '/v19-fleet', label: 'Fleet C2 & Live OSQuery', icon: '🌐' },
]

const v18LiveLinks = [
  { to: '/v18-live', label: 'Zero-Trust Live Response', icon: '⚡' },
]

const v17NeonLinks = [
  { to: '/v17-neon', label: 'Neon Serverless Mesh', icon: '⚡' },
]

const v16DefenseLinks = [
  { to: '/v16-defense', label: 'Real-Time Defense & Sandbox', icon: '🛡️' },
]

const links = [
  { to: '/', label: 'Threat Dashboard', icon: '◈' },
  { to: '/alerts', label: 'Alert Triage', icon: '▲' },
  { to: '/logs', label: 'Log Explorer', icon: '☷' },
  { to: '/rules', label: 'Detection Rules', icon: '⚙' },
  { to: '/intel', label: 'Threat Intel (IOCs)', icon: '◎' },
  { to: '/devices', label: 'Enrolled Devices', icon: '▣' },
  { to: '/upload', label: 'Log Ingest / Push', icon: '↑' },
  { to: '/audit-logs', label: 'Audit Trail', icon: '🛡' },
]

const pqcMeshLinks = [
  { to: '/pqc-mesh', label: 'Post-Quantum & Hardware', icon: '⚛️' },
]

const sovereignLinks = [
  { to: '/sovereign', label: 'Sovereign Edge (STRIDE)', icon: '🛡️' },
]

const aiSocLinks = [
  { to: '/ai-soc', label: 'AI SOC & Consensus', icon: '⚡' },
]

const realtimeLinks = [
  { to: '/telemetry', label: 'Live Telemetry & Stream', icon: '📡' },
]

const chaosLinks = [
  { to: '/chaos', label: 'Security Chaos (SCE)', icon: '💥' },
]

const vanguardLinks = [
  { to: '/bluetooth', label: 'Bluetooth HCI Guard', icon: '📡' },
  { to: '/tpm', label: 'TPM 2.0 Attestation', icon: '🔐' },
  { to: '/inventory', label: 'Tech Stack & Deception', icon: '🔬' },
]

export default function Sidebar() {
  const { user, logout } = useAuth()

  return (
    <aside className="w-64 shrink-0 bg-base-900 border-r border-base-700 flex flex-col h-screen sticky top-0">
      {/* Brand Header */}
      <div className="px-5 py-4 border-b border-base-700">
        <div className="flex items-center gap-2.5">
          <span className="text-accent text-xl font-mono font-bold">◆</span>
          <div>
            <span className="font-mono font-bold text-slate-100 tracking-wider text-sm block">THREAT ANALYSER</span>
            <span className="text-[10px] text-teal-400 font-mono tracking-widest uppercase">Edge Vanguard v20.0</span>
          </div>
        </div>
      </div>

      {/* Global Status Pill */}
      <div className="px-4 py-2.5 bg-base-950/60 border-b border-base-700/80 flex items-center justify-between text-xs">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-teal-400 animate-pulse"></span>
          <span className="text-slate-400 font-mono text-[11px]">ADAPTIVE GPS: <span className="text-teal-400 font-semibold">ACTIVE</span></span>
        </div>
        <span className="text-[10px] text-teal-400 font-mono font-bold">99.99999999/100</span>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-3 py-3 space-y-1 overflow-y-auto">
        <div className="px-3 py-1 text-[10px] uppercase font-mono tracking-wider text-teal-400 font-bold flex items-center justify-between">
          <span>Edge Remediation &amp; GPS</span>
          <span className="text-[9px] bg-teal-950 text-teal-300 px-1 rounded border border-teal-800">v20.0</span>
        </div>
        {v20EdgeLinks.map((l) => (
          <NavLink
            key={l.to}
            to={l.to}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-all ${
                isActive
                  ? 'bg-teal-950 text-teal-200 border border-teal-600/60 font-semibold shadow-sm'
                  : 'text-slate-300 hover:text-teal-200 hover:bg-base-800/80'
              }`
            }
          >
            <span className="w-4 text-center font-mono">{l.icon}</span>
            {l.label}
          </NavLink>
        ))}

        <div className="px-3 py-1 text-[10px] uppercase font-mono tracking-wider text-cyan-400 font-bold flex items-center justify-between">
          <span>Fleet C2 &amp; OSQuery</span>
          <span className="text-[9px] bg-cyan-950 text-cyan-300 px-1 rounded border border-cyan-800">v19.0</span>
        </div>
        {v19FleetLinks.map((l) => (
          <NavLink
            key={l.to}
            to={l.to}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-all ${
                isActive
                  ? 'bg-cyan-950 text-cyan-200 border border-cyan-600/60 font-semibold shadow-sm'
                  : 'text-slate-300 hover:text-cyan-200 hover:bg-base-800/80'
              }`
            }
          >
            <span className="w-4 text-center font-mono">{l.icon}</span>
            {l.label}
          </NavLink>
        ))}

        <div className="px-3 py-1 text-[10px] uppercase font-mono tracking-wider text-emerald-400 font-bold flex items-center justify-between">
          <span>Zero-Trust Live Response</span>
          <span className="text-[9px] bg-emerald-950 text-emerald-300 px-1 rounded border border-emerald-800">v18.0</span>
        </div>
        {v18LiveLinks.map((l) => (
          <NavLink
            key={l.to}
            to={l.to}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-all ${
                isActive
                  ? 'bg-emerald-950 text-emerald-200 border border-emerald-600/60 font-semibold shadow-sm'
                  : 'text-slate-300 hover:text-emerald-200 hover:bg-base-800/80'
              }`
            }
          >
            <span className="w-4 text-center font-mono">{l.icon}</span>
            {l.label}
          </NavLink>
        ))}

        <div className="px-3 py-1 text-[10px] uppercase font-mono tracking-wider text-cyan-400 font-bold flex items-center justify-between">
          <span>Neon Serverless Core</span>
          <span className="text-[9px] bg-cyan-950 text-cyan-300 px-1 rounded border border-cyan-800">v17.0</span>
        </div>
        {v17NeonLinks.map((l) => (
          <NavLink
            key={l.to}
            to={l.to}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-all ${
                isActive
                  ? 'bg-cyan-950 text-cyan-200 border border-cyan-600/60 font-semibold shadow-sm'
                  : 'text-slate-300 hover:text-cyan-200 hover:bg-base-800/80'
              }`
            }
          >
            <span className="w-4 text-center font-mono">{l.icon}</span>
            {l.label}
          </NavLink>
        ))}

        <div className="px-3 py-1 text-[10px] uppercase font-mono tracking-wider text-cyan-400 font-bold flex items-center justify-between">
          <span>Real-Time Defense &amp; Sandbox</span>
          <span className="text-[9px] bg-cyan-950 text-cyan-300 px-1 rounded border border-cyan-800">v16.0</span>
        </div>
        {v16DefenseLinks.map((l) => (
          <NavLink
            key={l.to}
            to={l.to}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-all ${
                isActive
                  ? 'bg-cyan-950 text-cyan-200 border border-cyan-600/60 font-semibold shadow-sm'
                  : 'text-slate-300 hover:text-cyan-200 hover:bg-base-800/80'
              }`
            }
          >
            <span className="w-4 text-center font-mono">{l.icon}</span>
            {l.label}
          </NavLink>
        ))}
        <div className="px-3 py-1 text-[10px] uppercase font-mono tracking-wider text-cyan-400 font-bold flex items-center justify-between">
          <span>Physical &amp; Quantum Mesh</span>
          <span className="text-[9px] bg-cyan-950 text-cyan-300 px-1 rounded border border-cyan-800">v15.0</span>
        </div>
        {pqcMeshLinks.map((l) => (
          <NavLink
            key={l.to}
            to={l.to}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-all ${
                isActive
                  ? 'bg-cyan-950 text-cyan-200 border border-cyan-600/60 font-semibold shadow-sm'
                  : 'text-slate-300 hover:text-cyan-200 hover:bg-base-800/80'
              }`
            }
          >
            <span className="w-4 text-center font-mono">{l.icon}</span>
            {l.label}
          </NavLink>
        ))}

        <div className="px-3 pt-2.5 pb-1 text-[10px] uppercase font-mono tracking-wider text-purple-400 font-bold flex items-center justify-between">
          <span>Sovereign Zero-Trust</span>
          <span className="text-[9px] bg-purple-950 text-purple-300 px-1 rounded border border-purple-800">v14.0</span>
        </div>
        {sovereignLinks.map((l) => (
          <NavLink
            key={l.to}
            to={l.to}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-all ${
                isActive
                  ? 'bg-purple-950 text-purple-200 border border-purple-600/60 font-semibold shadow-sm'
                  : 'text-slate-300 hover:text-purple-200 hover:bg-base-800/80'
              }`
            }
          >
            <span className="w-4 text-center font-mono">{l.icon}</span>
            {l.label}
          </NavLink>
        ))}

        <div className="px-3 pt-2.5 pb-1 text-[10px] uppercase font-mono tracking-wider text-cyan-400 font-bold flex items-center justify-between">
          <span>Autonomous AI SOC</span>
          <span className="text-[9px] bg-cyan-950 text-cyan-300 px-1 rounded border border-cyan-800">v13.0</span>
        </div>
        {aiSocLinks.map((l) => (
          <NavLink
            key={l.to}
            to={l.to}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-all ${
                isActive
                  ? 'bg-cyan-950 text-cyan-200 border border-cyan-600/60 font-semibold shadow-sm'
                  : 'text-slate-300 hover:text-cyan-200 hover:bg-base-800/80'
              }`
            }
          >
            <span className="w-4 text-center font-mono">{l.icon}</span>
            {l.label}
          </NavLink>
        ))}

        <div className="px-3 pt-2.5 pb-1 text-[10px] uppercase font-mono tracking-wider text-emerald-400 font-bold flex items-center justify-between">
          <span>Real-Time Telemetry</span>
          <span className="text-[9px] bg-emerald-950 text-emerald-300 px-1 rounded border border-emerald-800">v12.0</span>
        </div>
        {realtimeLinks.map((l) => (
          <NavLink
            key={l.to}
            to={l.to}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-all ${
                isActive
                  ? 'bg-emerald-950 text-emerald-200 border border-emerald-600/60 font-semibold shadow-sm'
                  : 'text-slate-300 hover:text-emerald-200 hover:bg-base-800/80'
              }`
            }
          >
            <span className="w-4 text-center font-mono">{l.icon}</span>
            {l.label}
          </NavLink>
        ))}

        <div className="px-3 pt-2.5 pb-1 text-[10px] uppercase font-mono tracking-wider text-rose-400 font-bold flex items-center justify-between">
          <span>Security Chaos &amp; SCE</span>
          <span className="text-[9px] bg-rose-950 text-rose-300 px-1 rounded border border-rose-800">v10.0</span>
        </div>
        {chaosLinks.map((l) => (
          <NavLink
            key={l.to}
            to={l.to}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-all ${
                isActive
                  ? 'bg-rose-950 text-rose-200 border border-rose-600/60 font-semibold shadow-sm'
                  : 'text-slate-300 hover:text-rose-200 hover:bg-base-800/80'
              }`
            }
          >
            <span className="w-4 text-center font-mono">{l.icon}</span>
            {l.label}
          </NavLink>
        ))}

        <div className="px-3 pt-2.5 pb-1 text-[10px] uppercase font-mono tracking-wider text-cyan-400 font-bold flex items-center justify-between">
          <span>Vanguard Edge &amp; HW</span>
          <span className="text-[9px] bg-cyan-950 text-cyan-300 px-1 rounded border border-cyan-800">v9.0</span>
        </div>
        {vanguardLinks.map((l) => (
          <NavLink
            key={l.to}
            to={l.to}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-all ${
                isActive
                  ? 'bg-cyan-950 text-cyan-200 border border-cyan-600/60 font-semibold shadow-sm'
                  : 'text-slate-300 hover:text-cyan-200 hover:bg-base-800/80'
              }`
            }
          >
            <span className="w-4 text-center font-mono">{l.icon}</span>
            {l.label}
          </NavLink>
        ))}

        <div className="px-3 pt-3 pb-1 text-[10px] uppercase font-mono tracking-wider text-slate-500 font-semibold">Operations</div>
        {links.slice(0, 3).map((l) => (
          <NavLink
            key={l.to}
            to={l.to}
            end={l.to === '/'}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-all ${
                isActive
                  ? 'bg-accent/15 text-accent border border-accent/30 font-semibold shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-base-800'
              }`
            }
          >
            <span className="w-4 text-center font-mono">{l.icon}</span>
            {l.label}
          </NavLink>
        ))}

        <div className="px-3 pt-3 pb-1 text-[10px] uppercase font-mono tracking-wider text-slate-500 font-semibold">Detection &amp; Intel</div>
        {links.slice(3, 5).map((l) => (
          <NavLink
            key={l.to}
            to={l.to}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-all ${
                isActive
                  ? 'bg-accent/15 text-accent border border-accent/30 font-semibold shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-base-800'
              }`
            }
          >
            <span className="w-4 text-center font-mono">{l.icon}</span>
            {l.label}
          </NavLink>
        ))}

        <div className="px-3 pt-3 pb-1 text-[10px] uppercase font-mono tracking-wider text-slate-500 font-semibold">Administration &amp; Forensic</div>
        {links.slice(5).map((l) => (
          <NavLink
            key={l.to}
            to={l.to}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-all ${
                isActive
                  ? 'bg-accent/15 text-accent border border-accent/30 font-semibold shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-base-800'
              }`
            }
          >
            <span className="w-4 text-center font-mono">{l.icon}</span>
            {l.label}
          </NavLink>
        ))}
      </nav>

      {/* User / Org Footer */}
      <div className="px-3 py-3 border-t border-base-700 bg-base-950/40">
        <div className="px-3 py-1.5 mb-2 bg-base-800/80 rounded border border-base-700 text-xs">
          <div className="truncate text-slate-200 font-medium">{user?.email}</div>
          <div className="flex items-center justify-between mt-0.5">
            <span className="uppercase text-[10px] font-mono tracking-wider text-accent font-bold">{user?.role}</span>
            <span className="text-[10px] text-slate-500 font-mono truncate max-w-[100px]">{user?.org_id?.slice(0, 8)}...</span>
          </div>
        </div>
        <button
          onClick={logout}
          className="w-full text-left px-3 py-1.5 rounded text-xs text-slate-400 hover:bg-base-800 hover:text-rose-400 transition-colors flex items-center justify-between"
        >
          <span>Sign Out</span>
          <span className="font-mono text-[10px]">⏻</span>
        </button>
      </div>
    </aside>
  )
}
