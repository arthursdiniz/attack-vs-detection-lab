#!/usr/bin/env python3
"""
Scenario: INC-007 - Controlled Web Application Attack Simulator
MITRE ATT&CK: T1110.001 (Password Guessing) / T1190 (Exploit Public-Facing Application)
Target: Web App on lab-ubuntu (http://192.168.56.30:8080)
Author: Senior DevSecOps & Detection Engineer
"""

import argparse
import json
import time
import urllib.request
import urllib.error
from datetime import datetime

FAIL_PASSWORDS = [
    "123456", "admin123", "password", "root123", "Welcome1!",
    "Admin#2024", "Secret123", "P@ssword", "LetMeIn!", "Test#999",
    "Winter2024", "Summer2024"
]

SUSPICIOUS_ROUTES = [
    "/admin.php", "/.env", "/wp-login.php", "/actuator/env", "/api/v1/internal/config"
]

def parse_args():
    parser = argparse.ArgumentParser(description="INC-007 Controlled Web Security Simulator")
    parser.add_argument("--url", default="http://192.168.56.30:8080", help="Web App URL (default: http://192.168.56.30:8080)")
    return parser.parse_args()

def send_request(url, method="GET", data=None, headers=None):
    if headers is None:
        headers = {}
    if data:
        data_bytes = json.dumps(data).encode("utf-8")
        headers["Content-Type"] = "application/json"
    else:
        data_bytes = None

    req = urllib.request.Request(url, data=data_bytes, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            return resp.status, resp.read().decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="ignore")
    except Exception as e:
        return 0, str(e)

def main():
    args = parse_args()
    print("==================================================================")
    print("   ATTACK vs DETECTION LAB -- INC-007 Web Security Simulator      ")
    print("==================================================================")
    print(f"Target URL: {args.url}")
    print(f"Timestamp : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    # 1. Test 1: Web Login Brute Force (T1110.001)
    print("[*] Stage 1: Simulating Web Application Login Brute Force (/login)...")
    login_url = f"{args.url}/login"
    for i, pwd in enumerate(FAIL_PASSWORDS, start=1):
        status, body = send_request(login_url, method="POST", data={"username": "admin", "password": pwd})
        print(f"  [{i:02d}/{len(FAIL_PASSWORDS):02d}] POST /login user='admin' pwd='{pwd}' -> HTTP {status}")
        time.sleep(1)

    print("\n[*] Stage 2: Simulating Repeated Unauthorized Access to Restricted Endpoint (/api/users)...")
    users_url = f"{args.url}/api/users"
    for i in range(1, 6):
        status, body = send_request(users_url, method="GET")
        print(f"  [{i}/5] GET /api/users (No Auth Header) -> HTTP {status} (Expected 403 Forbidden)")
        time.sleep(1)

    print("\n[*] Stage 3: Simulating Probing of Non-Existent Administrative Endpoints (Reconnaissance)...")
    for route in SUSPICIOUS_ROUTES:
        probe_url = f"{args.url}{route}"
        status, body = send_request(probe_url, method="GET")
        print(f"  [-] GET {route} -> HTTP {status} (Expected 404 Not Found)")
        time.sleep(1)

    print("\n======================= SIMULATION SUMMARY =======================")
    print("[+] All 3 web application attack scenarios executed.")
    print("    Expected Alerts:")
    print("      - Rule 100061: Web Login Brute Force (>= 10 failures in 60s)")
    print("      - Rule 100062: Repeated Access Denied to Restricted API")
    print("      - Rule 100063: Anomalous Route Probing Burst")
    print("==================================================================\n")

if __name__ == "__main__":
    main()
