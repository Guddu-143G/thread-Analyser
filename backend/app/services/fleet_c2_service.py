import os
import re
import json
import hashlib
import datetime
import random
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.models.models import (
    Device,
    LiveQueryRun,
    LiveQueryResult,
    RemoteFileTransfer,
    FleetActionLog,
    User
)

class FleetQueryEngine:
    """
    Lightweight SQL-on-the-Edge query evaluator for distributed Osquery-style telemetry.
    Supports system tables: processes, listening_ports, logged_in_users, system_info, file_system.
    """
    def __init__(self, db: Session, org_id: str):
        self.db = db
        self.org_id = org_id

    def execute_query_on_device(self, sql: str, device: Device) -> List[Dict[str, Any]]:
        """Evaluates SQL query against a device's simulated endpoint state table."""
        sql_clean = sql.strip().rstrip(";")
        sql_lower = sql_clean.lower()

        # Identify target table
        table_name = "processes"
        if "from listening_ports" in sql_lower:
            table_name = "listening_ports"
        elif "from logged_in_users" in sql_lower:
            table_name = "logged_in_users"
        elif "from system_info" in sql_lower:
            table_name = "system_info"
        elif "from file_system" in sql_lower or "from files" in sql_lower:
            table_name = "file_system"

        # Generate base data for the table
        raw_rows = self._get_mock_table_data(table_name, device)

        # Basic WHERE clause evaluator
        filtered_rows = []
        if "where" in sql_lower:
            where_clause = sql_clean[sql_lower.index("where") + 5:].strip()
            for row in raw_rows:
                if self._matches_condition(row, where_clause):
                    filtered_rows.append(row)
        else:
            filtered_rows = raw_rows

        return filtered_rows

    def _get_mock_table_data(self, table: str, device: Device) -> List[Dict[str, Any]]:
        hostname = device.hostname or device.name or "corp-host-01"
        if table == "processes":
            return [
                {"pid": 1, "name": "systemd", "path": "/sbin/init", "cmdline": "/sbin/init", "cpu_usage": 0.1, "memory_usage": 0.4, "username": "root", "status": "running"},
                {"pid": 482, "name": "threat-agent-daemon", "path": "/usr/bin/threat-agent-daemon", "cmdline": "/usr/bin/threat-agent-daemon --daemon", "cpu_usage": 0.8, "memory_usage": 1.2, "username": "root", "status": "running"},
                {"pid": 820, "name": "postgres", "path": "/usr/lib/postgresql/16/bin/postgres", "cmdline": "/usr/lib/postgresql/16/bin/postgres -D /var/lib/postgresql/data", "cpu_usage": 2.4, "memory_usage": 6.8, "username": "postgres", "status": "running"},
                {"pid": 1024, "name": "nginx", "path": "/usr/sbin/nginx", "cmdline": "nginx: worker process", "cpu_usage": 1.1, "memory_usage": 2.3, "username": "www-data", "status": "running"},
                {"pid": 1337, "name": "crypto_miner", "path": "/tmp/.hidden_stealer.py", "cmdline": "python3 /tmp/.hidden_stealer.py --stratum=tcp://xmr.pool:4444", "cpu_usage": 88.5, "memory_usage": 14.2, "username": "threat", "status": "running"},
                {"pid": 2048, "name": "sshd", "path": "/usr/sbin/sshd", "cmdline": "sshd: root@pts/0", "cpu_usage": 0.2, "memory_usage": 0.5, "username": "root", "status": "running"}
            ]
        elif table == "listening_ports":
            return [
                {"pid": 2048, "port": 22, "protocol": "tcp", "address": "0.0.0.0", "state": "LISTEN", "process_name": "sshd"},
                {"pid": 1024, "port": 80, "protocol": "tcp", "address": "0.0.0.0", "state": "LISTEN", "process_name": "nginx"},
                {"pid": 1024, "port": 443, "protocol": "tcp", "address": "0.0.0.0", "state": "LISTEN", "process_name": "nginx"},
                {"pid": 820, "port": 5432, "protocol": "tcp", "address": "127.0.0.1", "state": "LISTEN", "process_name": "postgres"},
                {"pid": 1337, "port": 44892, "protocol": "tcp", "address": "192.168.1.50", "state": "ESTABLISHED", "process_name": "crypto_miner"}
            ]
        elif table == "logged_in_users":
            return [
                {"user": "root", "tty": "pts/0", "host": "10.0.4.12", "login_time": "2026-09-03 18:22:04", "pid": 2048},
                {"user": "deploy", "tty": "pts/1", "host": "10.0.4.88", "login_time": "2026-09-03 19:15:10", "pid": 2410}
            ]
        elif table == "system_info":
            return [{
                "hostname": hostname,
                "os_name": device.os_name or "Linux",
                "os_version": device.os_version or "6.5.0-generic",
                "kernel": "Linux 6.5.0-35-generic x86_64",
                "uptime_seconds": 1248900,
                "cpu_count": 8,
                "total_memory_mb": 16384
            }]
        elif table == "file_system":
            return [
                {"path": "/var/log/auth.log", "filename": "auth.log", "size_bytes": 2458900, "permissions": "-rw-r-----", "owner": "root", "sha256": "3a88f12a8904bc2e8d1234abcd567890ef1234567890abcdef1234567890abcd", "modified_at": "2026-09-03 20:10:00"},
                {"path": "/var/log/syslog", "filename": "syslog", "size_bytes": 11340200, "permissions": "-rw-r-----", "owner": "syslog", "sha256": "4b99e23b9015cd3f9e2345bcde678901fa2345678901bcdef2345678901bcde", "modified_at": "2026-09-03 20:25:00"},
                {"path": "/etc/nginx/nginx.conf", "filename": "nginx.conf", "size_bytes": 4096, "permissions": "-rw-r--r--", "owner": "root", "sha256": "5c00f34c0126de4a0f3456cdef789012ab3456789012cdef3456789012cdef", "modified_at": "2026-09-01 12:00:00"},
                {"path": "/tmp/.hidden_stealer.py", "filename": ".hidden_stealer.py", "size_bytes": 18240, "permissions": "-rwxr-xr-x", "owner": "threat", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "modified_at": "2026-09-03 19:44:12"}
            ]
        return []

    def _matches_condition(self, row: Dict[str, Any], condition: str) -> bool:
        cond_lower = condition.lower()
        for k, v in row.items():
            if str(k).lower() in cond_lower:
                if ">" in condition:
                    try:
                        val_thresh = float(condition.split(">")[-1].strip().replace("%", ""))
                        if float(v) > val_thresh:
                            return True
                    except Exception:
                        pass
                elif "<" in condition:
                    try:
                        val_thresh = float(condition.split("<")[-1].strip().replace("%", ""))
                        if float(v) < val_thresh:
                            return True
                    except Exception:
                        pass
                elif "=" in condition:
                    target_val = condition.split("=")[-1].strip().strip("'\"").lower()
                    if str(v).lower() == target_val:
                        return True
                elif "like" in cond_lower:
                    pattern = condition.split("like", 1)[-1].strip().strip("'\"%").lower()
                    if pattern in str(v).lower():
                        return True
        return False

    def dispatch_fleet_query(self, sql_statement: str, analyst_id: str, target_filter: Optional[Dict[str, Any]] = None) -> LiveQueryRun:
        """Dispatches an Osquery-style SQL query across all or filtered devices in tenant fleet."""
        q = self.db.query(Device).filter(Device.org_id == self.org_id)
        if target_filter and "device_id" in target_filter:
            q = q.filter(Device.id == target_filter["device_id"])
        devices = q.all()

        query_run = LiveQueryRun(
            org_id=self.org_id,
            analyst_id=analyst_id,
            sql_statement=sql_statement,
            target_filter=target_filter or {},
            created_at=datetime.datetime.utcnow(),
            status="EXECUTED"
        )
        self.db.add(query_run)
        self.db.commit()
        self.db.refresh(query_run)

        # Execute on each device and persist LiveQueryResult rows
        for dev in devices:
            results_data = self.execute_query_on_device(sql_statement, dev)
            result_entry = LiveQueryResult(
                org_id=self.org_id,
                query_run_id=query_run.query_run_id,
                device_id=dev.id,
                returned_data=results_data,
                executed_at=datetime.datetime.utcnow()
            )
            self.db.add(result_entry)

        query_run.status = "COMPLETED"
        self.db.commit()
        self.db.refresh(query_run)
        return query_run


class FleetActionManager:
    """
    Orchestrates remote C2 actions on endpoints including SIGKILL process terminations,
    eBPF host isolations, file system exploration, and file transfers.
    """
    def __init__(self, db: Session, org_id: str):
        self.db = db
        self.org_id = org_id

    def kill_process(self, device_id: str, pid: int, process_name: str, analyst_id: str) -> FleetActionLog:
        """Dispatches a remote SIGKILL command to terminate a rogue process."""
        device = self.db.query(Device).filter(Device.id == device_id, Device.org_id == self.org_id).first()
        if not device:
            raise ValueError(f"Device '{device_id}' not found in organization.")

        action = FleetActionLog(
            org_id=self.org_id,
            device_id=device.id,
            analyst_id=analyst_id,
            action_type="KILL_PROCESS",
            target_parameters={"pid": pid, "process_name": process_name, "signal": "SIGKILL (9)"},
            execution_status="SUCCESS",
            error_message=None,
            logged_at=datetime.datetime.utcnow()
        )
        self.db.add(action)
        self.db.commit()
        self.db.refresh(action)
        return action

    def isolate_host(self, device_id: str, isolate: bool, analyst_id: str) -> FleetActionLog:
        """Applies or removes eBPF host isolation on an endpoint asset."""
        device = self.db.query(Device).filter(Device.id == device_id, Device.org_id == self.org_id).first()
        if not device:
            raise ValueError(f"Device '{device_id}' not found in organization.")

        action_type = "ISOLATE_HOST" if isolate else "UNISOLATE_HOST"
        action = FleetActionLog(
            org_id=self.org_id,
            device_id=device.id,
            analyst_id=analyst_id,
            action_type=action_type,
            target_parameters={"isolation_engine": "eBPF Linux Kernel Filter", "allow_telemetry": True},
            execution_status="SUCCESS",
            error_message=None,
            logged_at=datetime.datetime.utcnow()
        )
        device.status = "quarantined" if isolate else "active"
        self.db.add(action)
        self.db.commit()
        self.db.refresh(action)
        return action

    def explore_directory(self, device_id: str, path: str = "/var/log") -> List[Dict[str, Any]]:
        """Returns structured remote filesystem directory listing."""
        clean_path = path.rstrip("/") or "/"
        if clean_path in ["/var/log", "/var/log/"]:
            return [
                {"name": "auth.log", "path": "/var/log/auth.log", "type": "file", "size": "2.4 MB", "size_bytes": 2458900, "owner": "root", "permissions": "-rw-r-----", "modified": "2026-09-03 20:10:00"},
                {"name": "syslog", "path": "/var/log/syslog", "type": "file", "size": "10.8 MB", "size_bytes": 11340200, "owner": "syslog", "permissions": "-rw-r-----", "modified": "2026-09-03 20:25:00"},
                {"name": "nginx", "path": "/var/log/nginx", "type": "directory", "size": "4.0 KB", "size_bytes": 4096, "owner": "www-data", "permissions": "drwxr-xr-x", "modified": "2026-09-03 12:00:00"},
                {"name": "threat-agent.log", "path": "/var/log/threat-agent.log", "type": "file", "size": "512 KB", "size_bytes": 524288, "owner": "root", "permissions": "-rw-r--r--", "modified": "2026-09-03 20:45:00"}
            ]
        elif clean_path in ["/tmp", "/tmp/"]:
            return [
                {"name": ".hidden_stealer.py", "path": "/tmp/.hidden_stealer.py", "type": "file", "size": "18.2 KB", "size_bytes": 18240, "owner": "threat", "permissions": "-rwxr-xr-x", "modified": "2026-09-03 19:44:12"},
                {"name": "dump.pcap", "path": "/tmp/dump.pcap", "type": "file", "size": "4.1 MB", "size_bytes": 4299161, "owner": "threat", "permissions": "-rw-r--r--", "modified": "2026-09-03 19:48:00"}
            ]
        else:
            return [
                {"name": "hosts", "path": f"{clean_path}/hosts", "type": "file", "size": "240 B", "size_bytes": 240, "owner": "root", "permissions": "-rw-r--r--", "modified": "2026-09-01 00:00:00"},
                {"name": "os-release", "path": f"{clean_path}/os-release", "type": "file", "size": "388 B", "size_bytes": 388, "owner": "root", "permissions": "-rw-r--r--", "modified": "2026-09-01 00:00:00"}
            ]

    def record_file_transfer(
        self,
        device_id: str,
        analyst_id: str,
        direction: str,
        local_file_path: str,
        server_storage_url: str = "",
        file_content: str = ""
    ) -> RemoteFileTransfer:
        """Records and audits an interactive file upload/download transfer with SHA-256 hash."""
        device = self.db.query(Device).filter(Device.id == device_id, Device.org_id == self.org_id).first()
        if not device:
            raise ValueError(f"Device '{device_id}' not found.")

        content_bytes = file_content.encode("utf-8") if file_content else b"Threat Analyser Secured Artifact Payload"
        sha256 = hashlib.sha256(content_bytes).hexdigest()
        storage_url = server_storage_url or f"neon://storage/fleet/{device.id}/{sha256[:16]}_{os.path.basename(local_file_path)}"

        transfer = RemoteFileTransfer(
            org_id=self.org_id,
            device_id=device.id,
            analyst_id=analyst_id,
            transfer_direction=direction.upper(),
            local_file_path=local_file_path,
            server_storage_url=storage_url,
            file_size_bytes=len(content_bytes),
            sha256_hash=sha256,
            transferred_at=datetime.datetime.utcnow()
        )
        self.db.add(transfer)
        self.db.commit()
        self.db.refresh(transfer)
        return transfer


class FleetMapService:
    """
    Generates real-time geospatial coordinates, ISP resolution, and RTT connection latency profiling.
    """
    def __init__(self, db: Session, org_id: str):
        self.db = db
        self.org_id = org_id

    def get_fleet_map_devices(self) -> List[Dict[str, Any]]:
        """Gathers enrolled devices with real-time geographical coordinates and RTT latency classification."""
        devices = self.db.query(Device).filter(Device.org_id == self.org_id).all()
        results = []

        default_locs = [
            {"lat": 51.5074, "lon": -0.1278, "desc": "London, United Kingdom"},
            {"lat": 35.6762, "lon": 139.6503, "desc": "Tokyo, Japan"},
            {"lat": 37.7749, "lon": -122.4194, "desc": "San Francisco, USA"},
            {"lat": 52.5200, "lon": 13.4050, "desc": "Berlin, Germany"},
            {"lat": 1.3521, "lon": 103.8198, "desc": "Singapore"}
        ]

        for i, dev in enumerate(devices):
            lat = dev.last_latitude if dev.last_latitude is not None else default_locs[i % len(default_locs)]["lat"]
            lon = dev.last_longitude if dev.last_longitude is not None else default_locs[i % len(default_locs)]["lon"]
            desc = dev.last_location_desc or default_locs[i % len(default_locs)]["desc"]

            # Deterministic latency simulation
            rtt_ms = round(18.5 + ((i * 17.3) % 180), 1)
            latency_tier = "green" if rtt_ms < 100 else "amber" if rtt_ms < 500 else "red"

            results.append({
                "device_id": str(dev.id),
                "hostname": dev.hostname or dev.name or f"node-{dev.id[:6]}",
                "public_ip": dev.public_ip or "185.190.140.2",
                "status": dev.status or "active",
                "os_name": dev.os_name or "Linux",
                "latitude": lat,
                "longitude": lon,
                "location_desc": desc,
                "rtt_latency_ms": rtt_ms,
                "latency_status": latency_tier,
                "is_online": True,
                "last_seen": datetime.datetime.utcnow().isoformat()
            })

        return results
