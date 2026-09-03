# Threat Analyser eBPF Kernel Probes (v4.0)

## Overview
Threat Analyser v4 introduces **eBPF (Extended Berkeley Packet Filter)** in-kernel telemetry collection using the Rust [`aya`](https://aya-rs.dev/) framework.

Unlike user-space log forwarders that tail files in `/var/log` (which can be manipulated or terminated by attackers with local root privileges), eBPF bytecode is verified by the kernel JIT engine and runs sandboxed at ring 0, directly capturing system calls at execution boundaries.

---

## 🏗 Kernel Architecture

```
Linux Kernel Space
┌─────────────────────────────────────────────────────────────┐
│  Tracepoints:                                               │
│    • sys_enter_execve  -> Captures binary launch, PID, UID  │
│    • sys_enter_connect -> Captures socket binding & egress  │
│                                                             │
│  In-Kernel Ring Buffer Map (1MB Lockless Shared Memory)    │
│  [ TELEMETRY_EVENTS RingBuf ]                               │
└──────────────────────────────┬──────────────────────────────┘
                               │ Zero-Copy Shared Memory
User Space Daemon              ▼
┌─────────────────────────────────────────────────────────────┐
│  • Polls Aya Ring Buffer without context-switch latency     │
│  • Maps binary syscalls into OCSF v1.1.0 JSON entities       │
│  • Streams batches to Threat Analyser Ingestion API         │
└─────────────────────────────────────────────────────────────┘
```

---

## 🚀 Building & Loading

### Prerequisites
- Linux Kernel $\ge 5.8$ (with `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_EVENTS=y`)
- Rust nightly toolchain with `bpf-linker`:
  ```bash
  cargo install bpf-linker
  ```

### Build In-Kernel Bytecode
```bash
cargo build --release --target bpfel-unknown-none
```

### Run User-Space Daemon (Root / CAP_BPF required)
```bash
sudo ./target/release/threat-analyser-ebpf --api-url https://soc.company.internal/api/ingest/push --api-key <DEVICE_API_KEY>
```
