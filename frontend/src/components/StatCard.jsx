export default function StatCard({ label, value, accent = false }) {
  return (
    <div className="panel p-4">
      <div className="text-xs text-slate-500 uppercase tracking-wide mb-1">{label}</div>
      <div className={`text-2xl font-mono font-semibold ${accent ? 'text-accent' : 'text-slate-100'}`}>
        {value}
      </div>
    </div>
  )
}
