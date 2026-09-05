"""
Threat Analyser - Version 21 Mobile USB Hotplug & HID Passcode Auditor Agent
Probes local host USB subsystem (udev/libusb/usbmuxd/ADB) and streams
mobile hardware events to the central SaaS platform.
"""

import sys
import time
import json
import argparse
import urllib.request
import urllib.error

MOBILE_VIDS = ["0x05ac", "0x18d1", "0x04e8", "0x2717", "0x12d1"]

def probe_local_devices():
    """Simulates detecting connected mobile assets via local USB bus."""
    return [
        {
            "usb_port_path": "/dev/bus/usb/001/004",
            "probe_protocol": "AUTO"
        }
    ]

def forward_discovery(server_url: str, token: str):
    devices = probe_local_devices()
    for d in devices:
        url = f"{server_url.rstrip('/')}/api/v21/forensics/device/discover"
        req = urllib.request.Request(
            url,
            data=json.dumps(d).encode('utf-8'),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token}"
            },
            method="POST"
        )
        try:
            with urllib.request.urlopen(req) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                print(f"[+] Discovered Physical Device: {data.get('manufacturer')} {data.get('model')} (Serial: {data.get('serial_number')})")
        except Exception as e:
            print(f"[-] Discovery push error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="V21 Physical Mobile USB Hotplug Probe")
    parser.add_argument("--server", default="http://localhost:8000", help="Threat Analyser API server")
    parser.add_argument("--token", default="", help="JWT bearer token")
    args = parser.parse_args()

    print("[*] Starting V21 Physical Mobile Device & USB Hotplug Poller...")
    forward_discovery(args.server, args.token)
