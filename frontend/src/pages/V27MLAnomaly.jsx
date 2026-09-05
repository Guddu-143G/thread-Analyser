import React, { useState, useEffect } from 'react';
import MLAnomalyDashboard from '../components/MLAnomalyDashboard';

export default function V27MLAnomaly() {
  const [modelDetails, setModelDetails] = useState(null);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(false);
  const [notification, setNotification] = useState(null);

  const fetchModelDetails = async () => {
    try {
      const token = localStorage.getItem('ta_token') || localStorage.getItem('token');
      const res = await fetch('/api/v27/models', {
        headers: token ? { 'Authorization': `Bearer ${token}` } : {}
      });
      if (res.ok) {
        const data = await res.json();
        setModelDetails(data);
      }
    } catch (err) {
      console.error('Failed to fetch V27 model details:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchModelDetails();
    const interval = setInterval(fetchModelDetails, 6000);
    return () => clearInterval(interval);
  }, []);

  const showNotification = (msg, isError = false) => {
    setNotification({ msg, isError });
    setTimeout(() => setNotification(null), 4000);
  };

  const handleRetrain = async () => {
    setActionLoading(true);
    try {
      const token = localStorage.getItem('ta_token') || localStorage.getItem('token');
      const res = await fetch('/api/v27/train', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { 'Authorization': `Bearer ${token}` } : {})
        },
        body: JSON.stringify({
          lookback_days: 30,
          contamination: 0.05,
          n_estimators: 100,
          include_synthetic: true
        })
      });

      if (res.ok) {
        const data = await res.json();
        showNotification(`Pipeline retrained successfully in ${data.duration_sec}s using ${data.samples_used} samples!`);
        fetchModelDetails();
      } else {
        showNotification('Model retraining failed', true);
      }
    } catch (err) {
      showNotification('Retraining request failed', true);
    } finally {
      setActionLoading(false);
    }
  };

  const handleSimulateBurst = async () => {
    setActionLoading(true);
    try {
      const token = localStorage.getItem('ta_token') || localStorage.getItem('token');
      const res = await fetch('/api/v27/simulate-telemetry?count=15', {
        method: 'POST',
        headers: token ? { 'Authorization': `Bearer ${token}` } : {}
      });

      if (res.ok) {
        const data = await res.json();
        showNotification(`Simulated and scored ${data.count} telemetry events! Check the live feed tab.`);
      } else {
        showNotification('Simulation failed', true);
      }
    } catch (err) {
      showNotification('Simulation request failed', true);
    } finally {
      setActionLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-base-700/80">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold font-mono tracking-wider text-slate-100 uppercase">
              ML Anomaly Engine &amp; Multi-Tenant Pipelines
            </h1>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-950 text-cyan-300 border border-cyan-800">
              v27.0
            </span>
          </div>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Real-time multi-tenant Isolation Forest scoring, statistical baseline tuning, and Celery self-training pipelines
          </p>
        </div>

        {/* Global Status Indicator */}
        <div className="flex items-center gap-3">
          <div className="px-3 py-1.5 rounded-lg bg-base-900 border border-base-700 text-xs font-mono flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse"></span>
            <span className="text-slate-400">ISOLATION FOREST:</span>
            <span className="text-cyan-300 font-semibold">ACTIVE</span>
          </div>
        </div>
      </div>

      {/* Notification Toast */}
      {notification && (
        <div className={`p-3 rounded-lg border text-xs font-mono transition-all flex items-center justify-between ${
          notification.isError
            ? 'bg-rose-950/80 text-rose-200 border-rose-700'
            : 'bg-cyan-950/80 text-cyan-200 border-cyan-700'
        }`}>
          <div className="flex items-center gap-2">
            <span>{notification.isError ? '⚠️' : '✓'}</span>
            <span>{notification.msg}</span>
          </div>
          <button onClick={() => setNotification(null)} className="text-slate-400 hover:text-white">✕</button>
        </div>
      )}

      {/* Main Dashboard Component */}
      {loading && !modelDetails ? (
        <div className="py-24 text-center text-slate-500 font-mono text-sm">
          <span className="w-6 h-6 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin inline-block mr-2"></span>
          Bootstrapping tenant ML anomaly detector...
        </div>
      ) : (
        <MLAnomalyDashboard
          modelDetails={modelDetails}
          onRetrain={handleRetrain}
          onSimulate={handleSimulateBurst}
          isActionLoading={actionLoading}
        />
      )}
    </div>
  );
}
