# Threat Analyser Endpoint Agents

This directory contains endpoint collectors and probes for real-time telemetry extraction:

## 1. `ta_agent.py` - Log Forwarder Agent
- Real-time tailing of log files (`/var/log/syslog`, `/var/log/auth.log`, application logs).
- In-memory queue + SQLite WAL-backed offline buffer to guarantee **zero log loss** during network disconnects.
- Automatic batch aggregation (500 events or 2.0s flush interval).
- Exponential backoff with random jitter on network retry.
- TLS HTTPS POST transport to `/api/ingest/push` authenticated with `X-API-Key`.

### Usage:
```bash
python ta_agent.py --server http://localhost:8000 --api-key <YOUR_DEVICE_KEY> --watch /var/log/syslog /var/log/auth.log
```

## 2. `hci_monitor.go` - Bluetooth Low Energy / HCI RF Sensor
- Captures Bluetooth Low Energy (BLE) and HCI RF packets.
- Monitors L2CAP payload anomalies and BlueBorne exploit attempts (OCSF Class 6001).

## 3. `ebpf/` - In-Kernel Security Probes
- High-performance Rust/eBPF kernel tracepoints for process execution, network socket connect, and file integrity monitoring.
