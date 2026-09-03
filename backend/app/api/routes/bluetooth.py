"""
API Routes for Bluetooth Module Attack Prevention & Kernel HCI Guard (v9.0).
"""
import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import get_current_user
from app.models.models import User, TenantBluetoothThreat, Alert, Severity
from app.detection.bluetooth_guard import hci_guard
from app.schemas.schemas import (
    BluetoothThreatOut,
    BluetoothContainmentRequest,
    BluetoothContainmentResponse,
    BluetoothSimulateRequest,
)
from app.security.ledger import CryptographicAuditLedger

router = APIRouter(prefix="/api/bluetooth", tags=["bluetooth"])


@router.get("/threats", response_model=List[BluetoothThreatOut])
def list_bluetooth_threats(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Returns all detected Bluetooth RF edge threats and anomalous packets."""
    threats = (
        db.query(TenantBluetoothThreat)
        .filter(TenantBluetoothThreat.org_id == user.org_id)
        .order_by(TenantBluetoothThreat.created_at.desc())
        .all()
    )
    return threats


@router.get("/status")
def get_bluetooth_status(user: User = Depends(get_current_user)):
    """Returns the live status of the local Bluetooth Host Controller Interface (HCI)."""
    return hci_guard.get_status()


@router.post("/contain", response_model=BluetoothContainmentResponse)
def dispatch_bluetooth_containment(
    payload: BluetoothContainmentRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Executes hardware containment (drops attacker MAC on controller or engages RFKill lockdown).
    """
    res = hci_guard.execute_hardware_containment(
        attacker_mac=payload.attacker_mac,
        action=payload.action or "block_mac",
    )

    # Update state in DB
    db.query(TenantBluetoothThreat).filter(
        TenantBluetoothThreat.org_id == user.org_id,
        TenantBluetoothThreat.attacker_mac == payload.attacker_mac,
    ).update({"status": "CONTAINED", "mitigation_action": res["verdict"]})
    db.commit()

    CryptographicAuditLedger.append_audit_log(
        db=db,
        org_id=user.org_id,
        actor_user_id=user.id,
        action="bluetooth_hardware_containment",
        target=payload.attacker_mac,
        meta={"action": payload.action, "interface": payload.interface, "verdict": res["verdict"]},
    )

    return BluetoothContainmentResponse(
        status="SUCCESS",
        action_dispatched=payload.action or "block_mac",
        target_mac=payload.attacker_mac,
        interface=payload.interface or "hci0",
        containment_verdict=res["verdict"],
        timestamp=datetime.datetime.utcnow(),
    )


@router.post("/simulate-attack")
def simulate_bluetooth_attack(
    payload: BluetoothSimulateRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Simulates a rogue physical RF exploit (BlueBorne buffer overflow or BleedingTooth zero-click)
    against the HCI daemon to demonstrate live detection and hardware containment.
    """
    vector = payload.exploit_vector or "BLUEBORNE_L2CAP_OVERFLOW"
    attacker_mac = payload.source_mac or "00:1A:7D:DA:71:11"

    if vector == "BLUEBORNE_L2CAP_OVERFLOW":
        # Raw L2CAP frame with signaling channel ID (0x0001) and 65535 payload length
        fake_packet = b"\xff\xff\x01\x00" + b"\x90" * 200
    elif vector == "BLEEDINGTOOTH_ZERO_CLICK":
        # A2MP / SMP channel ID (0x0003) with oversized payload
        fake_packet = b"\x00\x20\x03\x00" + b"\xcc" * 200
    else:
        # Rogue SDP config flood
        fake_packet = b"\x00\x10\x01\x00\x08\x00\x00\x00"

    threat_event = hci_guard.analyze_l2cap_packet(fake_packet, source_mac=attacker_mac, rssi=-38)
    
    if threat_event:
        # Persist threat record
        record = TenantBluetoothThreat(
            org_id=user.org_id,
            interface=threat_event["interface"],
            protocol=threat_event["protocol"],
            attacker_mac=threat_event["attacker_mac"],
            rssi=threat_event["rssi"],
            payload_length_bytes=threat_event["payload_length_bytes"],
            anomaly_type=threat_event["anomaly_type"],
            mitigation_action=threat_event["mitigation_action"],
            status="BLOCKED",
        )
        db.add(record)

        # Trigger immediate SIEM alert
        alert = Alert(
            org_id=user.org_id,
            severity=Severity.critical,
            title=f"RF Edge Defense: {threat_event['anomaly_type']}",
            description=f"HCI Guard intercepted malicious {threat_event['protocol']} frame from MAC {attacker_mac}. Hardware containment dispatched.",
            evidence=threat_event,
        )
        db.add(alert)
        db.commit()

        # Execute automated containment
        containment = hci_guard.execute_hardware_containment(attacker_mac, action="block_mac")

        return {
            "simulation_status": "THREAT_DETECTED_AND_CONTAINED",
            "vector": vector,
            "threat_details": threat_event,
            "containment_response": containment,
            "alert_created": alert.id,
        }

    return {"simulation_status": "NO_ANOMALY", "message": "Packet inspected cleanly."}
