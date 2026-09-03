from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from app.models.models import TenantTechnologyInventory


TECH_VULNERABILITY_CATALOG: Dict[str, Dict[str, Any]] = {
    "FastAPI": {
        "software_id": "fastapi",
        "default_version": "0.100.0",
        "vulnerabilities": [
            {
                "id": "CVE-2023-XXXX1",
                "cwe_class": "CWE-400",
                "name": "Asynchronous Header Resource Exhaustion (DoS)",
                "severity": 7.5,
                "remediation": "Upgrade FastAPI to version 0.109.0+ and configure Starlette header limits."
            },
            {
                "id": "CVE-2024-XXXX2",
                "cwe_class": "CWE-639",
                "name": "BOLA / IDOR Dependency Injection Tenant Leak",
                "severity": 8.2,
                "remediation": "Enforce explicit Org-scoped tenant dependencies in all route signatures."
            }
        ],
        "verification_test_available": True,
        "simulation_handler_id": "fastapi_headers_dos"
    },
    "Spring Boot": {
        "software_id": "spring-boot",
        "default_version": "2.7.14",
        "vulnerabilities": [
            {
                "id": "CVE-2022-22965",
                "cwe_class": "CWE-94",
                "name": "Spring4Shell Remote Code Execution via DataBinder",
                "severity": 9.8,
                "remediation": "Upgrade Spring Framework to 5.3.18+ / 5.2.20+ and patch Tomcat."
            },
            {
                "id": "CVE-2023-20883",
                "cwe_class": "CWE-120",
                "name": "Spring Boot Actuator Memory Buffer Drift",
                "severity": 7.1,
                "remediation": "Restrict Actuator endpoints to internal loopback interfaces."
            }
        ],
        "verification_test_available": True,
        "simulation_handler_id": "spring4shell_rce_test"
    },
    "ExpressJS": {
        "software_id": "express",
        "default_version": "4.18.2",
        "vulnerabilities": [
            {
                "id": "CVE-2024-29041",
                "cwe_class": "CWE-290",
                "name": "Express Query String Parser Prototype Pollution",
                "severity": 7.5,
                "remediation": "Sanitize query objects and enable prototype-safe parsers."
            },
            {
                "id": "CVE-2022-24999",
                "cwe_class": "CWE-89",
                "name": "Unescaped Route Parameter SQL Injection",
                "severity": 8.8,
                "remediation": "Use parameterized queries with pg-promise or Prisma ORM."
            }
        ],
        "verification_test_available": True,
        "simulation_handler_id": "express_proto_pollution_test"
    },
    "PostgreSQL": {
        "software_id": "postgresql",
        "default_version": "16.1",
        "vulnerabilities": [
            {
                "id": "CVE-2024-10979",
                "cwe_class": "CWE-89",
                "name": "PL/Perl Environment Variable SQL Injection",
                "severity": 8.8,
                "remediation": "Upgrade PostgreSQL to 16.5+ and disable untrusted language extensions."
            },
            {
                "id": "CVE-2023-39417",
                "cwe_class": "CWE-284",
                "name": "Extension Script Improper Access Control Privilege Escalation",
                "severity": 7.5,
                "remediation": "Restrict superuser execution rights on dynamic extension installers."
            }
        ],
        "verification_test_available": True,
        "simulation_handler_id": "postgres_plperl_sqli_test"
    },
    "Django": {
        "software_id": "django",
        "default_version": "4.2.7",
        "vulnerabilities": [
            {
                "id": "CVE-2024-42005",
                "cwe_class": "CWE-89",
                "name": "Django QuerySet Truncation SQL Injection",
                "severity": 8.1,
                "remediation": "Upgrade Django to 4.2.15+ / 5.0.8+."
            }
        ],
        "verification_test_available": True,
        "simulation_handler_id": "django_sqli_test"
    },
    "Redis": {
        "software_id": "redis",
        "default_version": "7.0.12",
        "vulnerabilities": [
            {
                "id": "CVE-2023-45145",
                "cwe_class": "CWE-119",
                "name": "Buffer Overflow in Redis Memory Allocator",
                "severity": 7.8,
                "remediation": "Upgrade Redis to 7.0.14+."
            }
        ],
        "verification_test_available": True,
        "simulation_handler_id": "redis_buffer_alloc_test"
    }
}


DEFECT_TAXONOMY_REGISTRY = [
    {
        "defect_class": "I. Logical & Access Controls",
        "bug_variety": "Tenant Isolation Bypass",
        "cwe_mapping": "CWE-639",
        "severity": "HIGH",
        "simulation_method": "BOLA cross-tenant JWT header injection",
        "description": "Simulates an adversarial BOLA attack attempting to query records across tenant boundaries."
    },
    {
        "defect_class": "I. Logical & Access Controls",
        "bug_variety": "SQL / Command Injection Attempt",
        "cwe_mapping": "CWE-89",
        "severity": "CRITICAL",
        "simulation_method": "Synthetic SQL syntax payloads & terminal escape symbols",
        "description": "Pushes application logs containing common SQL injection delimiters or terminal escape sequences."
    },
    {
        "defect_class": "II. System & Memory Lifecycle",
        "bug_variety": "Buffer Overflow Attempt",
        "cwe_mapping": "CWE-120",
        "severity": "HIGH",
        "simulation_method": "8KB oversized command arguments & stack bloating",
        "description": "Simulates edge-level buffer overflow command injection with oversized input buffers."
    },
    {
        "defect_class": "II. System & Memory Lifecycle",
        "bug_variety": "Resource Exhaustion Attempt",
        "cwe_mapping": "CWE-400",
        "severity": "MEDIUM",
        "simulation_method": "Worker thread pool starvation calculation loop",
        "description": "Safely simulates worker thread saturation and high calculations to test rate limiting."
    },
    {
        "defect_class": "III. Over-the-Air & Edge RF",
        "bug_variety": "BlueBorne L2CAP Overflow",
        "cwe_mapping": "CWE-119",
        "severity": "CRITICAL",
        "simulation_method": "Malformed L2CAP 0xFFFF pointer configuration",
        "description": "Simulates BlueBorne zero-click memory leak via malformed L2CAP configuration frames."
    },
    {
        "defect_class": "III. Over-the-Air & Edge RF",
        "bug_variety": "Wireless MAC/SSID Spoofing",
        "cwe_mapping": "CWE-290",
        "severity": "HIGH",
        "simulation_method": "Rapid SSID handshakes & deauth packet surge",
        "description": "Generates localized HCI events showing rapid SSID handshakes and rogue MAC associations."
    },
    {
        "defect_class": "IV. Cryptographic & Protocol",
        "bug_variety": "Insecure Transmit Protocol",
        "cwe_mapping": "CWE-319",
        "severity": "MEDIUM",
        "simulation_method": "Plaintext HTTP port 80 auth header transmission",
        "description": "Simulates non-TLS, unencrypted HTTP connection attempts carrying credentials."
    },
    {
        "defect_class": "IV. Cryptographic & Protocol",
        "bug_variety": "Expired or Weak Certificate Handshake",
        "cwe_mapping": "CWE-295",
        "severity": "HIGH",
        "simulation_method": "Deprecated TLS 1.0 & RC4 cipher negotiation",
        "description": "Forces connections to negotiate using deprecated TLS v1.0 and expired SSL certificates."
    },
    {
        "defect_class": "V. ML Anomaly Blind Spots",
        "bug_variety": "Model Evasion Attempt",
        "cwe_mapping": "CWE-1039",
        "severity": "MEDIUM",
        "simulation_method": "Sparse auth traffic spaced over 5-minute intervals",
        "description": "Simulates stealthy, slow-moving attacks designed to bypass Isolation Forest thresholds."
    }
]


class BugVersioningEngine:
    """
    Matches detected software inventory with version-specific vulnerability profiles.
    """
    def __init__(self, tenant_uid: str, db: Optional[Session] = None):
        self.tenant_uid = tenant_uid
        self.db = db

    def get_version_profiles(self) -> List[Dict[str, Any]]:
        """
        Queries tenant technology inventory and returns matched vulnerability profiles.
        """
        profiles = []
        discovered_techs = set()

        if self.db:
            inv = self.db.query(TenantTechnologyInventory).filter(
                TenantTechnologyInventory.org_id == self.tenant_uid
            ).all()
            for item in inv:
                discovered_techs.add((item.technology, item.runtime or "1.0.0"))

        # Fallback defaults if no inventory in DB yet
        if not discovered_techs:
            discovered_techs = {
                ("FastAPI", "Python 3.11 / FastAPI 0.100.0"),
                ("PostgreSQL", "PostgreSQL 16.1"),
                ("ExpressJS", "Node.js 20 / Express 4.18.2"),
                ("Redis", "Redis 7.0.12")
            }

        for tech_name, runtime in discovered_techs:
            for cat_name, catalog in TECH_VULNERABILITY_CATALOG.items():
                if cat_name.lower() in tech_name.lower() or cat_name.lower() in runtime.lower():
                    profiles.append({
                        "software_id": catalog["software_id"],
                        "software_name": cat_name,
                        "detected_version": runtime,
                        "vulnerabilities": catalog["vulnerabilities"],
                        "verification_test_available": catalog["verification_test_available"],
                        "simulation_handler_id": catalog["simulation_handler_id"]
                    })
                    break

        return profiles
