import sys
import os
from datetime import datetime, timedelta

# Add backend root directory to path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.detection.heartbeat import DeviceTrackingMonitor
from app.detection.email_guard import EmailSecurityScanner
from app.detection.url_sandbox import RealtimeURLChecker

print("=== [V16.0 Unit Test Suite - Real-Time Tracking, URL Sandbox & Email Mesh] ===")

# 1. Test Device Tracking & Geolocation Resolution
print("\n1. Testing Device Geolocation Resolution & Haversine Distance...")
monitor = DeviceTrackingMonitor()

# Known Hub Resolution
london = monitor.resolve_geolocation("185.190.140.2")
tokyo = monitor.resolve_geolocation("203.0.113.88")
print(f"  [+] London Node: {london['city']}, {london['country']} ({london['lat']}, {london['lon']})")
print(f"  [+] Tokyo Node: {tokyo['city']}, {tokyo['country']} ({tokyo['lat']}, {tokyo['lon']})")
assert london["city"] == "London"
assert tokyo["city"] == "Tokyo"

# Haversine Distance London to Tokyo (~9560 km)
dist = monitor.haversine_distance(london["lat"], london["lon"], tokyo["lat"], tokyo["lon"])
print(f"  [+] Great Circle Distance London -> Tokyo: {dist:.1f} km")
assert 9000 < dist < 10000

# 2. Test Impossible Travel Anomaly Detection
print("\n2. Testing Impossible Travel Velocity Evaluation...")
now = datetime.utcnow()
prev_time = now - timedelta(minutes=15)  # 15 minutes ago

is_impossible, dist_km, time_min, vel = monitor.evaluate_impossible_travel(
    london["lat"], london["lon"], prev_time,
    tokyo["lat"], tokyo["lon"], now
)
print(f"  [+] Movement across {dist_km:.1f}km in {time_min:.1f}m => Velocity: {vel:.1f} km/h")
print(f"  [+] Impossible Travel Verdict: {is_impossible}")
assert is_impossible is True
assert vel > 800.0

# Realistic travel: same city in 15 mins
is_imp_local, _, _, vel_local = monitor.evaluate_impossible_travel(
    london["lat"], london["lon"], prev_time,
    51.5150, -0.1200, now
)
assert is_imp_local is False
print("  [+] Local urban transit check correctly verified as non-impossible.")

# 3. Test OCSF 5001 Normalization
ocsf_5001 = monitor.normalize_to_ocsf_5001(
    "org_test", "dev_01", "host-01", "laptop", "Windows 11", "23H2", "185.190.140.2", london, 15.0, 4000.0
)
assert ocsf_5001["class_uid"] == 5001
assert ocsf_5001["category_uid"] == 5
print("  [+] OCSF Class 5001 Device Inventory Info normalized cleanly.")

# 4. Test Serverless Email Security (OCSF 4009)
print("\n4. Testing Email Security Scanner (SPF, DKIM, DMARC, Spam/Phishing ML)...")
email_scanner = EmailSecurityScanner("org_test")

sample_phish = """From: "Helpdesk Administrator" <support@fake-microsoft-portal.xyz>
To: target@company.internal
Subject: IMMEDIATE ACTION REQUIRED: Account Suspended
Date: Fri, 04 Sep 2026 01:00:00 +0000
DKIM-Signature: v=1; a=rsa-sha256; d=fake-microsoft-portal.xyz; s=mail; bh=xxx; b=yyy
Content-Type: text/plain

Your corporate email account has been suspended due to suspicious activity.
Please verify password and confirm credentials immediately by clicking here:
https://fake-microsoft-portal.xyz/verify-login?session=active
"""

ocsf_4009 = email_scanner.scan_message(sample_phish, sender_ip="185.220.101.5")
email_act = ocsf_4009["email_activity"]
print(f"  [+] From: {email_act['from']}")
print(f"  [+] SPF: {email_act['spf_status']} | DKIM: {email_act['dkim_status']}")
print(f"  [+] Spam Risk Score: {email_act['risk_score']*100:.1f}% (Phishing: {email_act['is_phishing_or_spam']})")
print(f"  [+] Phishing Indicators Matched: {len(email_act['phishing_indicators'])}")
print(f"  [+] URLs Extracted: {email_act['urls_found']}")
assert email_act["is_phishing_or_spam"] is True
assert ocsf_4009["class_uid"] == 4009
assert len(email_act["urls_found"]) >= 1

# Clean email test
clean_mail = """From: colleague@corp.internal
To: dev@corp.internal
Subject: Team Sync Agenda
Date: Fri, 04 Sep 2026 01:00:00 +0000

Hi Team, let's review the sprint tasks during our regular meeting today.
"""
ocsf_clean = email_scanner.scan_message(clean_mail, sender_ip="192.168.1.10")
assert ocsf_clean["email_activity"]["is_phishing_or_spam"] is False
assert ocsf_clean["email_activity"]["risk_score"] < 0.20
print("  [+] Clean corporate email scored safely with zero false positives.")

# 5. Test Non-Destructive URL Sandbox (OCSF 4002)
print("\n5. Testing Real-Time URL Safety Checker & Sandbox Preview (OCSF 4002)...")
url_checker = RealtimeURLChecker("org_test")

# Test Malicious Domain (Tier 01 Match)
ocsf_url_t1 = url_checker.analyze_url("https://phish-bank-login.xyz/auth.php")
assert ocsf_url_t1["http_activity"]["is_malicious"] is True
assert "Tier-01" in ocsf_url_t1["http_activity"]["tier_matched"]
assert ocsf_url_t1["class_uid"] == 4002
print(f"  [+] Tier-01 Malicious IOC matched: {ocsf_url_t1['http_activity']['tier_matched']}")

# Test Suspicious Keyword Trigger (Tier 03 Ephemeral Sandbox)
ocsf_url_t3 = url_checker.analyze_url("https://random-dynamic-site.internal/update-password?token=123")
assert ocsf_url_t3["http_activity"]["emulation_triggered"] is True
assert "Tier-03" in ocsf_url_t3["http_activity"]["tier_matched"]
assert ocsf_url_t3["http_activity"]["sandbox_screenshot_path"] is not None
print(f"  [+] Tier-03 Ephemeral Sandbox triggered: {ocsf_url_t3['http_activity']['detection_reason']}")

# Test SVG Visual Snapshot Generator
svg_preview = url_checker.generate_sandbox_svg_preview(
    "https://random-dynamic-site.internal/update-password",
    "random-dynamic-site.internal",
    "Authentication Gateway",
    True
)
assert "<svg" in svg_preview
assert "SANDBOX" in svg_preview
print(f"  [+] Safe SVG snapshot generated cleanly ({len(svg_preview)} bytes).")

print("\n>>> ALL V16.0 UNIT TESTS PASSED WITH 100% PRECISION! <<<")
