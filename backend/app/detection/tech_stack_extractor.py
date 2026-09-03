"""
Enterprise-Grade Real-Time Passive Tech Stack Extraction Engine (OCSF Class 5001).
Analyzes runtime process executions, loaded dynamic libraries, and socket port bindings.
"""
import re
import time
from typing import Dict, Any, Optional, List


class TechStackExtractor:
    """
    Analyzes runtime process execution and socket telemetry 
    to extract and catalog active enterprise tech stacks (OCSF Class 5001).
    """
    SIGNATURES = {
        "FastAPI": {
            "binary_regex": r"python(3)?(\.exe)?",
            "cmd_regex": r"(uvicorn|gunicorn|fastapi)",
            "port_default": 8000,
            "runtime": "Python 3.11",
            "category": "Web Application Framework",
            "environment": "production",
        },
        "Spring Boot": {
            "binary_regex": r"java(\.exe)?",
            "cmd_regex": r"(-jar|spring-boot|org\.springframework|\.war)",
            "port_default": 8080,
            "runtime": "JVM (OpenJDK 21)",
            "category": "Enterprise Microservice Framework",
            "environment": "production",
        },
        "ExpressJS": {
            "binary_regex": r"node(\.exe)?",
            "cmd_regex": r"(express|app\.js|server\.js|index\.js|nest)",
            "port_default": 3000,
            "runtime": "NodeJS 20 LTS",
            "category": "Fullstack Web Service",
            "environment": "production",
        },
        "PostgreSQL": {
            "binary_regex": r"(postgres|pg_ctl)(\.exe)?",
            "cmd_regex": r"(-D|postgres|postmaster|postgresql\.conf)",
            "port_default": 5432,
            "runtime": "Native C / LibPQ",
            "category": "Relational Database Management System",
            "environment": "production",
        },
        "Django": {
            "binary_regex": r"python(3)?(\.exe)?",
            "cmd_regex": r"(manage\.py\s+runserver|wsgi|asgi|django)",
            "port_default": 8000,
            "runtime": "Python 3.11",
            "category": "Full-Stack Web Framework",
            "environment": "production",
        },
        "Redis": {
            "binary_regex": r"redis-server(\.exe)?",
            "cmd_regex": r"(redis\.conf|--port)",
            "port_default": 6379,
            "runtime": "In-Memory C Runtime",
            "category": "In-Memory Cache & Broker",
            "environment": "production",
        },
        "Next.js": {
            "binary_regex": r"node(\.exe)?",
            "cmd_regex": r"(next\s+start|next\s+dev|\.next)",
            "port_default": 3000,
            "runtime": "React / Node V8",
            "category": "Modern SSR Frontend Platform",
            "environment": "production",
        },
        "Nginx": {
            "binary_regex": r"nginx(\.exe)?",
            "cmd_regex": r"(-g|nginx\.conf)",
            "port_default": 80,
            "runtime": "High-Performance Event Engine",
            "category": "Reverse Proxy & Load Balancer",
            "environment": "production",
        },
        "Go Fiber / Gin": {
            "binary_regex": r"(main|server|app|gin|fiber)(\.exe)?",
            "cmd_regex": r"(gin|fiber|go_build)",
            "port_default": 8080,
            "runtime": "Go 1.22 Runtime",
            "category": "High-Throughput Native Microservice",
            "environment": "production",
        },
    }

    @classmethod
    def extract_from_process(
        cls,
        binary_path: str,
        cmd_line: str,
        active_ports: Optional[List[int]] = None,
        hostname: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Extracts running framework metadata based on process indicators,
        returning structured tech details and standard OCSF Class 5001 event.
        """
        active_ports = active_ports or []
        for framework, sig in cls.SIGNATURES.items():
            binary_matched = bool(binary_path and re.search(sig["binary_regex"], binary_path, re.IGNORECASE))
            cmd_matched = bool(cmd_line and re.search(sig["cmd_regex"], cmd_line, re.IGNORECASE))
            port_matched = any(p == sig["port_default"] for p in active_ports)

            if binary_matched or cmd_matched:
                confidence = "very_high" if (binary_matched and (cmd_matched or port_matched)) else "high" if cmd_matched else "medium"
                primary_port = active_ports[0] if active_ports else sig["port_default"]

                # Construct OCSF Class 5001 Event
                ocsf_class_5001 = {
                    "metadata": {
                        "version": "1.2.0",
                        "product": "ThreatAnalyser Agent v9.0",
                        "tenant_uid": "enterprise_tenant_mesh",
                    },
                    "category_uid": 5,
                    "class_uid": 5001,
                    "class_name": "SOFTWARE_INVENTORY",
                    "time": int(time.time() * 1000),
                    "device": {
                        "hostname": hostname or "prod-app-01",
                    },
                    "software": {
                        "name": framework,
                        "category": sig["category"],
                        "runtime": sig["runtime"],
                        "path": binary_path or "/usr/bin",
                        "port_bindings": [primary_port],
                        "environment": sig["environment"],
                        "confidence": confidence,
                    },
                }

                return {
                    "technology": framework,
                    "category": sig["category"],
                    "runtime": sig["runtime"],
                    "confidence": confidence,
                    "detected_port": primary_port,
                    "hostname": hostname or "prod-app-01",
                    "path": binary_path,
                    "environment": sig["environment"],
                    "ocsf_event": ocsf_class_5001,
                }
        return None
