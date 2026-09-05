import React, { useState, useEffect } from 'react';
import SyntheticSimulationDashboard from '../components/SyntheticSimulationDashboard';

const TopIcons = {
  Flame: () => (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M17.657 18.657A8 8 0 016.343 7.343S7 9 9 10c0-2 .5-5 2.986-7C14 5 16.09 5.777 17.656 7.343A7.975 7.975 0 0120 13a7.975 7.975 0 01-2.343 5.657z" />
    </svg>
  ),
  Activity: () => (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 10V3L4 14h7v7l9-11h-7z" />
    </svg>
  ),
  Cpu: () => (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 3v2m6-2v2M9 19v2m6-2v2M3 9h2m-2 6h2m14-6h2m-2 6h2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z" />
    </svg>
  ),
  Server: () => (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01" />
    </svg>
  )
};

export default function V29SimulationSTG() {
  const [statusData, setStatusData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchStatus = async () => {
      try {
        const token = localStorage.getItem('ta_token') || localStorage.getItem('token');
        const res = await fetch('/api/v29/status', {
          headers: token ? { Authorization: `Bearer ${token}` } : {}
        });
        if (res.ok) {
          const data = await res.json();
          setStatusData(data);
        }
      } catch (err) {
        console.error('Failed to fetch V29 status:', err);
      } finally {
        setLoading(false);
      }
    };
    fetchStatus();
  }, []);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-6 font-sans space-y-6">
      {/* Top Capability Badges */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex items-center gap-3 shadow-lg">
          <div className="p-2.5 bg-purple-500/10 border border-purple-500/20 rounded-lg text-purple-400">
            <TopIcons.Flame />
          </div>
          <div>
            <div className="text-[11px] text-slate-400 uppercase font-mono">Purple-Team Engine</div>
            <div className="text-sm font-bold text-white mt-0.5">
              {statusData?.purple_team_emulation_active ? 'Active & Ready' : 'Standby'}
            </div>
          </div>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex items-center gap-3 shadow-lg">
          <div className="p-2.5 bg-indigo-500/10 border border-indigo-500/20 rounded-lg text-indigo-400">
            <TopIcons.Activity />
          </div>
          <div>
            <div className="text-[11px] text-slate-400 uppercase font-mono">STG Diurnal Curves</div>
            <div className="text-sm font-bold text-white mt-0.5">OCSF v1.2 Compliant</div>
          </div>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex items-center gap-3 shadow-lg">
          <div className="p-2.5 bg-emerald-500/10 border border-emerald-500/20 rounded-lg text-emerald-400">
            <TopIcons.Cpu />
          </div>
          <div>
            <div className="text-[11px] text-slate-400 uppercase font-mono">Cold-Start ML</div>
            <div className="text-sm font-bold text-white mt-0.5">Zero-Data Bootstrapped</div>
          </div>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex items-center gap-3 shadow-lg">
          <div className="p-2.5 bg-cyan-500/10 border border-cyan-500/20 rounded-lg text-cyan-400">
            <TopIcons.Server />
          </div>
          <div>
            <div className="text-[11px] text-slate-400 uppercase font-mono">KEDA Autoscaler</div>
            <div className="text-sm font-bold text-white mt-0.5">2 → 50 Celery Pods</div>
          </div>
        </div>
      </div>

      {/* Main Dashboard Hub */}
      <SyntheticSimulationDashboard orgId="current-tenant" />
    </div>
  );
}
