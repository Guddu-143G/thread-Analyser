import { Routes, Route, Navigate } from 'react-router-dom'
import { useAuth } from './context/AuthContext'
import Sidebar from './components/Sidebar'
import Login from './pages/Login'
import Register from './pages/Register'
import Dashboard from './pages/Dashboard'
import Alerts from './pages/Alerts'
import Devices from './pages/Devices'
import ThreatIntel from './pages/ThreatIntel'
import Rules from './pages/Rules'
import LogUpload from './pages/LogUpload'
import LogExplorer from './pages/LogExplorer'
import AuditLogs from './pages/AuditLogs'
import LandingPage from './pages/LandingPage'
import BluetoothGuard from './pages/BluetoothGuard'
import TPMAttestation from './pages/TPMAttestation'
import TechInventory from './pages/TechInventory'
import ChaosEngineering from './pages/ChaosEngineering'
import ForgotPassword from './pages/ForgotPassword'
import ResetPassword from './pages/ResetPassword'
import AISocConsensus from './pages/AISocConsensus'
import LiveTelemetry from './pages/LiveTelemetry'
import SovereignEdge from './pages/SovereignEdge'
import PostQuantumMesh from './pages/PostQuantumMesh'
import V16DefenseMesh from './pages/V16DefenseMesh'
import V17NeonMesh from './pages/V17NeonMesh'
import V18LiveResponse from './pages/V18LiveResponse'
import V19FleetMesh from './pages/V19FleetMesh'
import V20EdgeRemediation from './pages/V20EdgeRemediation'
import V21MobileForensics from './pages/V21MobileForensics'
import V23SpatialLedger from './pages/V23SpatialLedger'
import V24BasebandLedger from './pages/V24BasebandLedger'
import V25CognitiveMatrix from './pages/V25CognitiveMatrix'
import V26CausalProvenance from './pages/V26CausalProvenance'
import V27MLAnomaly from './pages/V27MLAnomaly'
import V28FederatedML from './pages/V28FederatedML'
import V29SimulationSTG from './pages/V29SimulationSTG'
import V30CyberRange from './pages/V30CyberRange'


function ProtectedLayout({ children }) {
  const { user, loading } = useAuth()

  if (loading) {
    return <div className="min-h-screen flex items-center justify-center text-slate-500 font-mono text-sm">Loading security console…</div>
  }
  if (!user) {
    return <Navigate to="/login" replace />
  }

  return (
    <div className="flex bg-base-950 min-h-screen">
      <Sidebar />
      <main className="flex-1 p-6 max-w-7xl mx-auto w-full overflow-x-hidden">{children}</main>
    </div>
  )
}

function HomeRoute() {
  const { user, loading } = useAuth()
  if (loading) {
    return <div className="min-h-screen flex items-center justify-center text-slate-500 font-mono text-sm">Loading…</div>
  }
  if (user) {
    return (
      <ProtectedLayout>
        <Dashboard />
      </ProtectedLayout>
    )
  }
  return <LandingPage />
}

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<HomeRoute />} />
      <Route path="/landing" element={<LandingPage />} />
      <Route path="/login" element={<Login />} />
      <Route path="/register" element={<Register />} />
      <Route path="/forgot-password" element={<ForgotPassword />} />
      <Route path="/reset-password" element={<ResetPassword />} />
      <Route path="/dashboard" element={<ProtectedLayout><Dashboard /></ProtectedLayout>} />
      <Route path="/v30-range" element={<ProtectedLayout><V30CyberRange /></ProtectedLayout>} />
      <Route path="/digital-twin" element={<ProtectedLayout><V30CyberRange /></ProtectedLayout>} />
      <Route path="/cyber-range" element={<ProtectedLayout><V30CyberRange /></ProtectedLayout>} />
      <Route path="/v29-simulation" element={<ProtectedLayout><V29SimulationSTG /></ProtectedLayout>} />
      <Route path="/purple-team" element={<ProtectedLayout><V29SimulationSTG /></ProtectedLayout>} />
      <Route path="/v28-federation" element={<ProtectedLayout><V28FederatedML /></ProtectedLayout>} />
      <Route path="/federated-ml" element={<ProtectedLayout><V28FederatedML /></ProtectedLayout>} />
      <Route path="/v27-anomaly" element={<ProtectedLayout><V27MLAnomaly /></ProtectedLayout>} />
      <Route path="/ml-anomaly" element={<ProtectedLayout><V27MLAnomaly /></ProtectedLayout>} />
      <Route path="/v26-provenance" element={<ProtectedLayout><V26CausalProvenance /></ProtectedLayout>} />


      <Route path="/causal-soar" element={<ProtectedLayout><V26CausalProvenance /></ProtectedLayout>} />
      <Route path="/v25-matrix" element={<ProtectedLayout><V25CognitiveMatrix /></ProtectedLayout>} />
      <Route path="/mitre-cognitive" element={<ProtectedLayout><V25CognitiveMatrix /></ProtectedLayout>} />
      <Route path="/v24-baseband" element={<ProtectedLayout><V24BasebandLedger /></ProtectedLayout>} />
      <Route path="/baseband-ledger" element={<ProtectedLayout><V24BasebandLedger /></ProtectedLayout>} />

      <Route path="/v23-spatial" element={<ProtectedLayout><V23SpatialLedger /></ProtectedLayout>} />
      <Route path="/spatial-ledger" element={<ProtectedLayout><V23SpatialLedger /></ProtectedLayout>} />
      <Route path="/v21-forensics" element={<ProtectedLayout><V21MobileForensics /></ProtectedLayout>} />
      <Route path="/mobile-forensics" element={<ProtectedLayout><V21MobileForensics /></ProtectedLayout>} />
      <Route path="/v20-edge" element={<ProtectedLayout><V20EdgeRemediation /></ProtectedLayout>} />
      <Route path="/edge-remediation" element={<ProtectedLayout><V20EdgeRemediation /></ProtectedLayout>} />
      <Route path="/v19-fleet" element={<ProtectedLayout><V19FleetMesh /></ProtectedLayout>} />
      <Route path="/fleet-c2" element={<ProtectedLayout><V19FleetMesh /></ProtectedLayout>} />
      <Route path="/v18-live" element={<ProtectedLayout><V18LiveResponse /></ProtectedLayout>} />
      <Route path="/live-response" element={<ProtectedLayout><V18LiveResponse /></ProtectedLayout>} />
      <Route path="/v17-neon" element={<ProtectedLayout><V17NeonMesh /></ProtectedLayout>} />
      <Route path="/neon-mesh" element={<ProtectedLayout><V17NeonMesh /></ProtectedLayout>} />
      <Route path="/v16-defense" element={<ProtectedLayout><V16DefenseMesh /></ProtectedLayout>} />
      <Route path="/live-mesh" element={<ProtectedLayout><V16DefenseMesh /></ProtectedLayout>} />
      <Route path="/pqc-mesh" element={<ProtectedLayout><PostQuantumMesh /></ProtectedLayout>} />
      <Route path="/sovereign" element={<ProtectedLayout><SovereignEdge /></ProtectedLayout>} />
      <Route path="/ai-soc" element={<ProtectedLayout><AISocConsensus /></ProtectedLayout>} />
      <Route path="/telemetry" element={<ProtectedLayout><LiveTelemetry /></ProtectedLayout>} />
      <Route path="/chaos" element={<ProtectedLayout><ChaosEngineering /></ProtectedLayout>} />
      <Route path="/bluetooth" element={<ProtectedLayout><BluetoothGuard /></ProtectedLayout>} />
      <Route path="/tpm" element={<ProtectedLayout><TPMAttestation /></ProtectedLayout>} />
      <Route path="/inventory" element={<ProtectedLayout><TechInventory /></ProtectedLayout>} />
      <Route path="/alerts" element={<ProtectedLayout><Alerts /></ProtectedLayout>} />
      <Route path="/logs" element={<ProtectedLayout><LogExplorer /></ProtectedLayout>} />
      <Route path="/rules" element={<ProtectedLayout><Rules /></ProtectedLayout>} />
      <Route path="/intel" element={<ProtectedLayout><ThreatIntel /></ProtectedLayout>} />
      <Route path="/devices" element={<ProtectedLayout><Devices /></ProtectedLayout>} />
      <Route path="/upload" element={<ProtectedLayout><LogUpload /></ProtectedLayout>} />
      <Route path="/audit-logs" element={<ProtectedLayout><AuditLogs /></ProtectedLayout>} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
