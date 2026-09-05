import React, { useState, useEffect } from 'react';
import GSDTDashboard from '../components/GSDTDashboard';
import { useAuth } from '../context/AuthContext';

const RangeIcons = {
  Twin: () => (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z" />
    </svg>
  ),
  Shield: () => (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
    </svg>
  ),
  Zap: () => (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 10V3L4 14h7v7l9-11h-7z" />
    </svg>
  ),
  Chain: () => (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
    </svg>
  )
};

export default function V30CyberRange() {
  const { user } = useAuth();
  const [statusData, setStatusData] = useState(null);
  const [loading, setLoading] = useState(true);

  const orgId = user?.org_id || 'default-org';

  useEffect(() => {
    const fetchStatus = async () => {
      try {
        const token = localStorage.getItem('ta_token') || localStorage.getItem('token');
        const res = await fetch('/api/v30/status', {
          headers: token ? { Authorization: `Bearer ${token}` } : {}
        });
        if (res.ok) {
          const data = await res.json();
          setStatusData(data);
        }
      } catch (err) {
        console.warn('Failed to fetch V30 status:', err);
      } finally {
        setLoading(false);
      }
    };
    fetchStatus();
  }, []);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-6 font-sans space-y-6">
      {/* Top Stat Badges */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex items-center gap-3 shadow-lg">
          <div className="p-2.5 bg-cyan-500/10 border border-cyan-500/20 rounded-lg text-cyan-400">
            <RangeIcons.Twin />
          </div>
          <div>
            <div className="text-[11px] text-slate-400 uppercase font-mono">Generative Digital Twin</div>
            <div className="text-sm font-bold text-white flex items-center gap-2 mt-0.5">
              <span>ACTIVE</span>
              <span className="text-[10px] bg-cyan-950 text-cyan-300 px-1.5 py-0.2 rounded border border-cyan-800 font-mono">Zero-PII</span>
            </div>
          </div>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex items-center gap-3 shadow-lg">
          <div className="p-2.5 bg-rose-500/10 border border-rose-500/20 rounded-lg text-rose-400">
            <RangeIcons.Shield />
          </div>
          <div>
            <div className="text-[11px] text-slate-400 uppercase font-mono">Autonomous Range (ACR)</div>
            <div className="text-sm font-bold text-white flex items-center gap-2 mt-0.5">
              <span>GAAN LOOP</span>
              <span className="text-[10px] bg-rose-950 text-rose-300 px-1.5 py-0.2 rounded border border-rose-800 font-mono">Red vs Blue</span>
            </div>
          </div>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex items-center gap-3 shadow-lg">
          <div className="p-2.5 bg-amber-500/10 border border-amber-500/20 rounded-lg text-amber-400">
            <RangeIcons.Zap />
          </div>
          <div>
            <div className="text-[11px] text-slate-400 uppercase font-mono">Traffic Ingestion Engine</div>
            <div className="text-sm font-bold text-white flex items-center gap-2 mt-0.5">
              <span>1,000,000+ EPS</span>
              <span className="text-[10px] bg-amber-950 text-amber-300 px-1.5 py-0.2 rounded border border-amber-800 font-mono">eBPF XDP</span>
            </div>
          </div>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex items-center gap-3 shadow-lg">
          <div className="p-2.5 bg-emerald-500/10 border border-emerald-500/20 rounded-lg text-emerald-400">
            <RangeIcons.Chain />
          </div>
          <div>
            <div className="text-[11px] text-slate-400 uppercase font-mono">Neon Serverless Ledger</div>
            <div className="text-sm font-bold text-white flex items-center gap-2 mt-0.5">
              <span>IMMUTABLE</span>
              <span className="text-[10px] bg-emerald-950 text-emerald-300 px-1.5 py-0.2 rounded border border-emerald-800 font-mono">Merkle Hash</span>
            </div>
          </div>
        </div>
      </div>

      {/* Main GSDT Dashboard */}
      <GSDTDashboard orgId={orgId} />
    </div>
  );
}
