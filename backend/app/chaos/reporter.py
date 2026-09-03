import time
from datetime import datetime
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from app.models.models import TenantChaosSimulation


class SecurityResilienceReporter:
    """
    Generates high-fidelity audit reports detailing the organization's
    operational coverage metrics and dynamic simulation results.
    """
    def __init__(self, tenant_uid: str, db: Optional[Session] = None):
        self.tenant_uid = tenant_uid
        self.db = db

    def compile_model_report(self, active_detections: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """
        Aggregates historical fault injection metrics, parsing active rules
        to output the Defensive Coverage Index (DCI) and an audit-ready Markdown report.
        """
        # Fetch from DB if active_detections not provided
        if active_detections is None and self.db:
            sims = self.db.query(TenantChaosSimulation).filter(
                TenantChaosSimulation.org_id == self.tenant_uid
            ).order_by(TenantChaosSimulation.injected_at.desc()).limit(100).all()

            active_detections = []
            for s in sims:
                active_detections.append({
                    "test_id": s.simulation_id,
                    "bug_variety": s.bug_variety,
                    "cwe_id": s.cwe_class,
                    "severity": s.severity,
                    "injected_at_str": s.injected_at.strftime("%Y-%m-%d %H:%M:%S UTC") if s.injected_at else "N/A",
                    "injected_at_ms": int(s.injected_at.timestamp() * 1000) if s.injected_at else 0,
                    "detected_at_ms": int(s.detected_at.timestamp() * 1000) if s.detected_at else 0,
                    "detection_latency_ms": s.detection_latency_ms,
                    "alert_triggered": s.alert_triggered,
                    "status": s.status,
                    "sla_compliance": s.sla_compliance,
                    "execution_notes": s.execution_notes or ""
                })

        if active_detections is None:
            active_detections = []

        total_injections = len(active_detections)
        successful_detections = 0
        tested_cwes = set()
        vulnerability_log = []
        total_latency = 0
        latency_count = 0
        sla_met_count = 0
        sla_failed_count = 0

        for det in active_detections:
            cwe = det.get("cwe_id", det.get("cwe", "Unknown"))
            tested_cwes.add(cwe)

            is_detected = det.get("alert_triggered", False)
            latency = det.get("detection_latency_ms", -1)
            sla_compliance = det.get("sla_compliance", "MET" if (is_detected and latency <= 5000) else "FAILED")

            if is_detected:
                successful_detections += 1
                if latency > 0:
                    total_latency += latency
                    latency_count += 1

            if sla_compliance == "MET":
                sla_met_count += 1
            else:
                sla_failed_count += 1

            vulnerability_log.append({
                "test_id": det.get("test_id", det.get("simulation_id")),
                "bug_variety": det.get("bug_variety"),
                "cwe": cwe,
                "severity": det.get("severity", "HIGH"),
                "injected_at": det.get("injected_at_str", str(datetime.utcnow())),
                "status": "RESOLVED_ALERT" if is_detected else "UNDETECTED",
                "detection_latency_ms": latency if is_detected else -1,
                "sla_compliance": sla_compliance,
                "execution_notes": det.get("execution_notes", "")
            })

        # Calculate Defensive Coverage Index (DCI)
        coverage_pct = (successful_detections / total_injections) * 100 if total_injections > 0 else 100.0
        avg_latency = round(total_latency / latency_count, 2) if latency_count > 0 else 0.0
        regulatory_tier = "EXCELLENT (SOC2 Ready)" if coverage_pct >= 90.0 else "WARNING (Unmitigated Blind Spots)"
        report_ref = f"SRR-{datetime.utcnow().strftime('%Y-%m-%d')}-{self.tenant_uid[:6].upper()}"

        markdown_report = self.generate_markdown_report(
            tenant_uid=self.tenant_uid,
            report_ref=report_ref,
            coverage_pct=coverage_pct,
            regulatory_tier=regulatory_tier,
            vulnerability_log=vulnerability_log,
            avg_latency=avg_latency,
            unique_cwes=len(tested_cwes)
        )

        return {
            "tenant_uid": self.tenant_uid,
            "report_reference": report_ref,
            "report_generation_timestamp": int(time.time()),
            "metrics": {
                "total_fault_simulations_run": total_injections,
                "successfully_blocked_and_logged": successful_detections,
                "defensive_coverage_index": round(coverage_pct, 2),
                "unique_cwe_classes_tested": len(tested_cwes),
                "remediations_required_count": total_injections - successful_detections,
                "avg_detection_latency_ms": avg_latency,
                "sla_met_count": sla_met_count,
                "sla_failed_count": sla_failed_count
            },
            "compliance_evaluation": {
                "assessment_tier": regulatory_tier,
                "recommending_active_mitigations": coverage_pct < 100.0
            },
            "detailed_simulation_ledger": vulnerability_log,
            "markdown_report": markdown_report
        }

    def generate_markdown_report(
        self,
        tenant_uid: str,
        report_ref: str,
        coverage_pct: float,
        regulatory_tier: str,
        vulnerability_log: List[Dict[str, Any]],
        avg_latency: float,
        unique_cwes: int
    ) -> str:
        """
        Generates the Model Security Resilience Report in audit-ready Markdown.
        """
        status_icon = "🛡️" if coverage_pct >= 90.0 else "⚠️"
        
        table_rows = []
        for v in vulnerability_log[:15]:
            status_symbol = "✅ TRIGGERED" if v["status"] == "RESOLVED_ALERT" else "❌ UNDETECTED"
            if v["sla_compliance"] == "FAILED" and v["status"] == "RESOLVED_ALERT":
                status_symbol = "⚠️ TIMEOUT"
            table_rows.append(
                f"| {v['bug_variety']:<30} | {v['cwe']:<12} | {v['severity']:<8} | {v['detection_latency_ms']}ms | {status_symbol} |"
            )

        rows_formatted = "\n".join(table_rows) if table_rows else "| No active simulations recorded yet | - | - | - | - |"

        notes_sections = []
        for i, v in enumerate(vulnerability_log[:5], 1):
            notes_sections.append(
                f"### Test {i}: {v['bug_variety']}\n"
                f"- **Target CWE:** `{v['cwe']}`\n"
                f"- **Severity:** `{v['severity']}`\n"
                f"- **Detection Mechanics:** {v.get('execution_notes', 'Evaluated against SIEM detection engine.')}\n"
                f"- **Result:** **{'PASSED' if v['status'] == 'RESOLVED_ALERT' and v['sla_compliance'] == 'MET' else 'FAILED / WARNING'}** (Latency: `{v['detection_latency_ms']}ms` | SLA Threshold: `<5000ms`)\n"
            )
        notes_formatted = "\n".join(notes_sections) if notes_sections else "_Execute interactive fault injections in the Simulation Arena to generate deep forensic notes._"

        report = f"""# {status_icon} Model Security Resilience & Defect Verification Report
**Tenant ID:** `{tenant_uid}`  
**Report Reference:** `{report_ref}`  
**Defense Status:** **{regulatory_tier}**  
**Defensive Coverage Index (DCI):** **{coverage_pct:.2f}%**  
**Average Detection Latency:** **{avg_latency} ms**  
**Unique CWE Classes Tested:** **{unique_cwes}**  

---

## 📊 Executive Threat Coverage Matrix

The Threat Analyser Chaos Engine has completed automated safety evaluations across primary defect taxonomies using the active backend parsing engine and rule definitions.

| Target Defect Variety | CWE Class | Severity | Latency | Alert Status |
| :--- | :--- | :--- | :--- | :--- |
{rows_formatted}

---

## 🔍 Simulation Execution Ledger & Deep Forensic Notes

{notes_formatted}

---

## 🛠️ Actionable Remediation & Hardening Guidance

1. **Harden Model Lookbacks (`app/detection/anomaly.py`)**:
   Maintain Isolation Forest contamination boundaries below `0.05` to retain sensitivity against low-frequency stealthy authentication drift.
2. **Real-Time Pipeline SLA Watchdog**:
   Ensure all RF HCI and eBPF system call telemetry ingress within the 5,000ms SLA window before triggering hardware containment.
3. **Continuous Synthetic Fuzzing**:
   Schedule recurring Security Chaos Engineering (SCE) runs to validate active Sigma and OCSF rule health.
"""
        return report
