"""
Version 21: Hardware-Assisted Mobile Forensics & Passcode Auditing Service
Implements Shannon Entropy Metrics, 3x3 Gesture Grid Traversals, PIN Dictionaries,
Adaptive Lockout Rate Controller, and Multi-Tenant Neon Postgres Integration.
"""

import os
import time
import math
import hashlib
import json
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy.orm import Session

from app.models.models import MobileForensicSession, PasscodeGuessAttempt, User, Organization
from app.detection.forensics import MobileDeviceDetector

try:
    import redis
    def get_redis_client():
        redis_url = os.getenv("REDIS_URL", "redis://redis:6379/0")
        try:
            return redis.Redis.from_url(redis_url, decode_responses=True, socket_connect_timeout=1)
        except Exception:
            return None
except Exception:
    def get_redis_client():
        return None

logger = logging.getLogger("mobile_forensics")

# Common 3x3 Gesture Patterns represented as coordinate sequences [0..8]
# 0  1  2
# 3  4  5
# 6  7  8
COMMON_PATTERNS = [
    [0, 1, 2, 5, 8],          # Shape '7'
    [0, 3, 6, 7, 8],          # Shape 'L'
    [0, 1, 2, 4, 6, 7, 8],    # Shape 'Z'
    [2, 1, 0, 3, 6, 7, 8],    # Shape 'C'
    [2, 1, 0, 3, 4, 5, 8, 7, 6], # Shape 'S'
    [0, 3, 6, 7, 8, 5, 2],    # Shape 'U'
    [0, 1, 2, 5, 8, 7, 6, 3], # Perimeter Box
    [0, 4, 8],                # Main Diagonal
    [2, 4, 6],                # Anti Diagonal
    [0, 1, 2, 4, 7],          # T-shape
    [1, 4, 7, 6, 8],          # Tree shape
    [3, 4, 5, 1, 7],          # Plus cross
    [0, 4, 8, 5, 2],          # Diagonal N
    [6, 3, 0, 4, 8, 5, 2],    # Shape 'M'
    [0, 3, 4, 5, 8],          # Lightning
    [0, 1, 4, 7, 8],          # Step pattern
]

# Top statistical PIN combinations (Probabilistic dictionary)
COMMON_PINS_4 = [
    "1234", "1111", "0000", "1212", "7777", "1004", "2000", "4444", "2222", "6969",
    "9999", "3333", "5555", "6666", "1122", "1313", "8888", "4321", "2001", "1010",
    "1994", "1995", "1990", "1998", "1999", "2002", "2003", "2004", "2005", "2024"
]

COMMON_PINS_6 = [
    "123456", "111111", "000000", "123123", "654321", "112233", "121212", "200000",
    "199401", "199505", "199010", "202401", "789456", "159357", "987654", "010203"
]


class PasscodeThrottleController:
    """
    Tracks exponential backoff and cooldown timers when physical target endpoints
    trigger anti-bruteforce lockouts (e.g. 30s after 5 invalid attempts).
    """
    def __init__(self):
        self.lockouts: Dict[str, float] = {} # session_id -> cooldown_expiry_timestamp

    def trigger_cooldown(self, session_id: str, duration_sec: float = 30.0) -> float:
        expiry = time.time() + duration_sec
        self.lockouts[session_id] = expiry
        return duration_sec

    def get_remaining_cooldown(self, session_id: str) -> float:
        if session_id not in self.lockouts:
            return 0.0
        remaining = self.lockouts[session_id] - time.time()
        if remaining <= 0:
            del self.lockouts[session_id]
            return 0.0
        return round(remaining, 2)

    def is_locked_out(self, session_id: str) -> bool:
        return self.get_remaining_cooldown(session_id) > 0.0


# Global controller instance for active sessions
throttle_controller = PasscodeThrottleController()


class MobileForensicAuditEngine:
    """
    Core executor for hardware-assisted mobile forensics, password complexity/entropy evaluations,
    USB OTG-HID emulation, and OCSF 3002 event normalization.
    """

    @staticmethod
    def calculate_passcode_entropy(passcode: str, passcode_type: str) -> float:
        """
        Calculates Shannon Entropy based on passcode structure and possible permutations.
        H = L * log2(R) for characters or log2(P(9, n)) for 3x3 gesture paths.
        """
        if not passcode:
            return 0.0

        passcode_type = passcode_type.upper()
        if passcode_type in ("PIN_4", "PIN_6", "PIN_8", "PIN"):
            alphabet_size = 10  # digits 0-9
            entropy = len(passcode) * math.log2(alphabet_size)
            return round(entropy, 2)

        elif passcode_type == "PATTERN":
            # For 3x3 grid pattern, length is the number of touched nodes (max 9).
            # Nodes cannot repeat. Permutations = P(9, n) = 9! / (9-n)!
            try:
                # If passcode is comma-separated or string of digits
                if "," in passcode:
                    nodes = [int(x.strip()) for x in passcode.split(",") if x.strip()]
                else:
                    nodes = [int(c) for c in passcode if c.isdigit()]
                n = len(nodes)
            except Exception:
                n = len(passcode)

            if n <= 1:
                return 0.0
            n = min(9, max(1, n))
            permutations = math.perm(9, n)
            return round(math.log2(permutations), 2)

        else:
            # Complex alphanumeric check
            has_lower = any(c.islower() for c in passcode)
            has_upper = any(c.isupper() for c in passcode)
            has_digit = any(c.isdigit() for c in passcode)
            has_symbol = any(not c.isalnum() for c in passcode)

            alphabet_size = 0
            if has_lower: alphabet_size += 26
            if has_upper: alphabet_size += 26
            if has_digit: alphabet_size += 10
            if has_symbol: alphabet_size += 32
            alphabet_size = max(1, alphabet_size)

            entropy = len(passcode) * math.log2(alphabet_size)
            return round(entropy, 2)

    @staticmethod
    def get_candidate_for_index(passcode_type: str, attempt_index: int) -> Tuple[str, Optional[List[int]]]:
        """
        Retrieves or generates a candidate passcode string and pattern coordinate array for a given attempt index.
        """
        p_type = passcode_type.upper()
        if p_type == "PATTERN":
            idx = attempt_index % len(COMMON_PATTERNS)
            coords = COMMON_PATTERNS[idx]
            candidate_str = "".join(str(c) for c in coords)
            return candidate_str, coords
        elif p_type == "PIN_6":
            if attempt_index < len(COMMON_PINS_6):
                pin = COMMON_PINS_6[attempt_index]
            else:
                pin = f"{(attempt_index * 1337) % 1000000:06d}"
            return pin, None
        elif p_type == "ALPHANUMERIC":
            word_list = ["Admin", "Security", "Passw0rd", "Root", "Spring2024", "Welcome1", "Dragon99", "Secret#1"]
            base = word_list[attempt_index % len(word_list)]
            cand = f"{base}!{attempt_index}"
            return cand, None
        else:
            # Default PIN_4
            if attempt_index < len(COMMON_PINS_4):
                pin = COMMON_PINS_4[attempt_index]
            else:
                pin = f"{(attempt_index * 7919) % 10000:04d}"
            return pin, None

    @classmethod
    def execute_audit_attempt(
        cls,
        db: Session,
        session_obj: MobileForensicSession,
        attempt_index: int,
        candidate: str,
        pattern_path: Optional[List[int]] = None,
        target_secret: Optional[str] = None
    ) -> Tuple[PasscodeGuessAttempt, Dict[str, Any]]:
        """
        Executes a single passcode guess attempt, calculating latency, hashing,
        detecting lockouts, saving to DB, and preparing the OCSF 3002 payload.
        """
        start_time = time.perf_counter()

        # Check if active lockout backoff is running
        remaining_cd = throttle_controller.get_remaining_cooldown(session_obj.session_id)
        if remaining_cd > 0:
            attempt_hash = hashlib.sha256(candidate.encode()).hexdigest()
            attempt_rec = PasscodeGuessAttempt(
                session_id=session_obj.session_id,
                org_id=session_obj.org_id,
                attempt_index=attempt_index,
                passcode_attempt_hash=attempt_hash,
                pattern_path=pattern_path,
                is_successful=False,
                response_latency_ms=10,
                response_code="LOCKED_OUT",
                timestamp=datetime.utcnow()
            )
            db.add(attempt_rec)
            db.commit()
            db.refresh(attempt_rec)

            ocsf_event = MobileDeviceDetector.build_ocsf_forensic_auth_event(
                tenant_uid=session_obj.org_id,
                device_uid=session_obj.serial_number,
                target_udid=session_obj.udid,
                attempt_index=attempt_index,
                passcode_type=session_obj.passcode_type,
                is_successful=False,
                entropy=cls.calculate_passcode_entropy(candidate, session_obj.passcode_type),
                pattern_coords=pattern_path,
                speed_gps=0.0,
                cooldown_sec=remaining_cd,
                os_info={"name": session_obj.os_name, "version": session_obj.os_version}
            )
            return attempt_rec, ocsf_event

        # Determine target mock secret
        effective_secret = target_secret or "1994"
        if session_obj.passcode_type == "PATTERN" and not target_secret:
            effective_secret = "01258" # Pattern '7'
        elif session_obj.passcode_type == "PIN_6" and not target_secret:
            effective_secret = "199401"

        # Compare
        is_correct = (candidate == effective_secret)
        entropy = cls.calculate_passcode_entropy(candidate, session_obj.passcode_type)

        # Trigger adaptive lockout on every 5th consecutive failure in simulated mode
        backoff_triggered = 0.0
        if not is_correct and attempt_index > 0 and attempt_index % 5 == 0:
            backoff_triggered = throttle_controller.trigger_cooldown(session_obj.session_id, 30.0)
            response_code = "LOCKED_OUT"
            session_obj.status = "LOCKED_OUT"
        else:
            response_code = "SUCCESS" if is_correct else "REJECTED"
            if is_correct:
                session_obj.status = "COMPLETED"
                session_obj.completed_at = datetime.utcnow()

        latency_ms = max(5, int((time.perf_counter() - start_time) * 1000) + 40)
        candidate_hash = hashlib.sha256(candidate.encode()).hexdigest()

        attempt_rec = PasscodeGuessAttempt(
            session_id=session_obj.session_id,
            org_id=session_obj.org_id,
            attempt_index=attempt_index,
            passcode_attempt_hash=candidate_hash,
            pattern_path=pattern_path,
            is_successful=is_correct,
            response_latency_ms=latency_ms,
            response_code=response_code,
            timestamp=datetime.utcnow()
        )

        db.add(attempt_rec)
        db.commit()
        db.refresh(attempt_rec)

        # Construct OCSF 3002 event
        ocsf_event = MobileDeviceDetector.build_ocsf_forensic_auth_event(
            tenant_uid=session_obj.org_id,
            device_uid=session_obj.serial_number,
            target_udid=session_obj.udid,
            attempt_index=attempt_index,
            passcode_type=session_obj.passcode_type,
            is_successful=is_correct,
            entropy=entropy,
            pattern_coords=pattern_path,
            speed_gps=round(1000.0 / max(10, latency_ms), 2),
            cooldown_sec=backoff_triggered,
            os_info={"name": session_obj.os_name, "version": session_obj.os_version}
        )

        # Broadcast via Redis Pub/Sub if available
        r = get_redis_client()
        if r:
            try:
                channel = f"forensics:live:{session_obj.session_id}"
                msg = {
                    "type": "AUDIT_SUCCESS" if is_correct else "AUDIT_TICK",
                    "session_id": session_obj.session_id,
                    "attempt": {
                        "attempt_id": attempt_rec.attempt_id,
                        "attempt_index": attempt_index,
                        "entropy": entropy,
                        "is_successful": is_correct,
                        "response_code": response_code,
                        "latency_ms": latency_ms,
                        "candidate_hash": candidate_hash,
                        "pattern_path": pattern_path,
                        "backoff_triggered_sec": backoff_triggered
                    },
                    "guesses_per_sec": round(1000.0 / max(10, latency_ms), 2),
                    "ocsf_event": ocsf_event
                }
                r.publish(channel, json.dumps(msg))
                r.publish("forensics:global:events", json.dumps(msg))
            except Exception as e:
                logger.warning(f"Failed to publish to redis: {e}")

        return attempt_rec, ocsf_event
