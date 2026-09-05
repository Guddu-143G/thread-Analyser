import React, { useState, useEffect } from 'react';
import MLFederationConsole from '../components/MLFederationConsole';

export default function V28FederatedML() {
  const [globalModel, setGlobalModel] = useState(null);
  const [statusData, setStatusData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(false);
  const [notification, setNotification] = useState(null);

  const fetchGlobalState = async () => {
    try {
      const token = localStorage.getItem('ta_token') || localStorage.getItem('token');
      const [resStatus, resModel] = await Promise.all([
        fetch('/api/v28/status', {
          headers: token ? { 'Authorization': `Bearer ${token}` } : {}
        }),
        fetch('/api/v28/global-model', {
          headers: token ? { 'Authorization': `Bearer ${token}` } : {}
        })
      ]);

      if (resStatus.ok) {
        const data = await resStatus.json();
        setStatusData(data);
      }
      if (resModel.ok) {
        const data = await resModel.json();
        setGlobalModel(data);
      }
    } catch (err) {
      console.error('Failed to fetch V28 global state:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchGlobalState();
    const interval = setInterval(fetchGlobalState, 5000);
    return () => clearInterval(interval);
  }, []);

  const showNotification = (msg, isError = false) => {
    setNotification({ msg, isError });
    setTimeout(() => setNotification(null), 4000);
  };

  const handleSubmitWeights = async () => {
    setActionLoading(true);
    try {
      const token = localStorage.getItem('ta_token') || localStorage.getItem('token');
      const res = await fetch('/api/v28/submit-weights', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { 'Authorization': `Bearer ${token}` } : {})
        },
        body: JSON.stringify({
          sample_count: 150
        })
      });

      if (res.ok) {
        const data = await res.json();
        showNotification(`Encrypted local model parameters uploaded (Checksum: ${data.checksum_signature.slice(0, 12)}...)`);
        fetchGlobalState();
      } else {
        showNotification('Weight submission failed', true);
      }
    } catch (err) {
      showNotification('Weight submission request failed', true);
    } finally {
      setActionLoading(false);
    }
  };

  const handleTriggerConsensus = async () => {
    setActionLoading(true);
    try {
      const token = localStorage.getItem('ta_token') || localStorage.getItem('token');
      const res = await fetch('/api/v28/aggregate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { 'Authorization': `Bearer ${token}` } : {})
        },
        body: JSON.stringify({
          model_name: 'global_anomaly_forest',
          min_clients: 2,
          dp_epsilon: 1.2
        })
      });

      if (res.ok) {
        const data = await res.json();
        showNotification(`Consensus epoch consolidated across ${data.active_client_count} tenant nodes! Loss: ${data.aggregated_loss.toFixed(5)}`);
        fetchGlobalState();
      } else {
        showNotification('Consensus aggregation failed', true);
      }
    } catch (err) {
      showNotification('Consensus request failed', true);
    } finally {
      setActionLoading(false);
    }
  };

  const handleSimulateBurst = async () => {
    setActionLoading(true);
    try {
      const token = localStorage.getItem('ta_token') || localStorage.getItem('token');
      const res = await fetch('/api/v28/simulate-mesh?peers_count=4', {
        method: 'POST',
        headers: token ? { 'Authorization': `Bearer ${token}` } : {}
      });

      if (res.ok) {
        const data = await res.json();
        showNotification(`Simulated multi-tenant burst: ${data.active_peers} peer updates aggregated into Epoch v${data.total_epochs_trained}!`);
        fetchGlobalState();
      } else {
        showNotification('Mesh simulation failed', true);
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
              Federated Learning &amp; Collaborative Threat Mesh
            </h1>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-indigo-950 text-indigo-300 border border-indigo-800">
              v28.0
            </span>
          </div>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Privacy-preserving Federated Averaging (FedAvg), Ring-LWE Homomorphic parameter encryption, and Neon Serverless consensus ledger
          </p>
        </div>

        {/* Global Status Pill */}
        <div className="flex items-center gap-3">
          <div className="px-3 py-1.5 rounded-lg bg-base-900 border border-base-700 text-xs font-mono flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-indigo-400 animate-pulse"></span>
            <span className="text-slate-400">FEDERATION MESH:</span>
            <span className="text-indigo-300 font-semibold">ACTIVE</span>
          </div>
        </div>
      </div>

      {/* Notification Toast */}
      {notification && (
        <div className={`p-3 rounded-lg border text-xs font-mono transition-all flex items-center justify-between ${
          notification.isError
            ? 'bg-rose-950/80 text-rose-200 border-rose-700'
            : 'bg-indigo-950/80 text-indigo-200 border-indigo-700'
        }`}>
          <div className="flex items-center gap-2">
            <span>{notification.isError ? '⚠️' : '✓'}</span>
            <span>{notification.msg}</span>
          </div>
          <button onClick={() => setNotification(null)} className="text-slate-400 hover:text-white">✕</button>
        </div>
      )}

      {/* Main Console */}
      {loading && !globalModel ? (
        <div className="py-24 text-center text-slate-500 font-mono text-sm">
          <span className="w-6 h-6 border-2 border-indigo-400 border-t-transparent rounded-full animate-spin inline-block mr-2"></span>
          Synchronizing with Sovereign Federation Mesh...
        </div>
      ) : (
        <MLFederationConsole
          orgId={globalModel?.org_id}
          onTriggerConsensus={handleTriggerConsensus}
          onSubmitWeights={handleSubmitWeights}
          onSimulateBurst={handleSimulateBurst}
          isActionLoading={actionLoading}
        />
      )}
    </div>
  );
}
