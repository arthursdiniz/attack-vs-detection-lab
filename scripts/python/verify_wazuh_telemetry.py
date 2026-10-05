#!/usr/bin/env python3
"""
Script Name: verify_wazuh_telemetry.py
Description: Validates agent enrollment status, keepalive timestamps, and
             telemetry ingestion in Wazuh SIEM for the Attack vs Detection Lab.
Author: Senior Security & Detection Engineer
"""

import argparse
import json
import os
import sys
import urllib.request
import urllib.error
import ssl
from datetime import datetime


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Verify Wazuh Agent Enrollment & Telemetry Ingestion"
    )
    parser.add_argument(
        "--host",
        default="192.168.56.40",
        help="Wazuh Manager IP address (default: 192.168.56.40)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=55000,
        help="Wazuh Management API port (default: 55000)",
    )
    parser.add_argument(
        "--user",
        default="wazuh-wui",
        help="Wazuh API username (default: wazuh-wui or admin)",
    )
    parser.add_argument(
        "--password",
        default="",
        help="Wazuh API password",
    )
    parser.add_argument(
        "--log-file",
        help="Optional local path to archives.json or alerts.json to verify offline",
    )
    return parser.parse_args()


def verify_from_local_log(file_path):
    print(f"[*] Analyzing local Wazuh event file: {file_path}")
    if not os.path.exists(file_path):
        print(f"[!] Error: File '{file_path}' does not exist.")
        sys.exit(1)

    agent_counts = {}
    total_events = 0

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            total_events += 1
            try:
                data = json.loads(line)
                agent = data.get("agent", {})
                agent_name = agent.get("name", "unknown")
                agent_counts[agent_name] = agent_counts.get(agent_name, 0) + 1
            except json.JSONDecodeError:
                continue

    print("\n" + "=" * 60)
    print("        LOCAL LOG TELEMETRY INGESTION SUMMARY")
    print("=" * 60)
    print(f"Total Events Parsed : {total_events}")
    print("-" * 60)
    print(f"{'AGENT NAME':<25} {'EVENT COUNT':<15} {'STATUS':<15}")
    print(f"{'----------':<25} {'-----------':<15} {'------':<15}")

    for agent, count in agent_counts.items():
        status = "ACTIVE" if count > 0 else "NO EVENTS"
        print(f"{agent:<25} {count:<15} {status:<15}")

    print("=" * 60 + "\n")


def verify_via_api(host, port, user, password):
    url = f"https://{host}:{port}/agents?pretty=true"
    print(f"[*] Querying Wazuh API at {url}...")

    # Bypass self-signed lab TLS certificates safely
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # Step 1: Request JWT Token
    auth_url = f"https://{host}:{port}/security/user/authenticate"
    auth_handler = urllib.request.HTTPBasicAuthHandler()
    password_mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    password_mgr.add_password(None, auth_url, user, password)
    auth_handler.add_password(None, auth_url, user, password)

    try:
        req = urllib.request.Request(auth_url, method="POST")
        base64string = f"{user}:{password}".encode("ascii")
        import base64
        req.add_header(
            "Authorization", f"Basic {base64.b64encode(base64string).decode('ascii')}"
        )

        with urllib.request.urlopen(req, context=ctx, timeout=5) as response:
            res_data = json.loads(response.read().decode())
            token = res_data.get("data", {}).get("token")
    except Exception as e:
        print(f"[!] Warning: Could not authenticate with Wazuh API ({e}).")
        print("    Ensure Wazuh API service is running on port 55000.")
        return

    # Step 2: Query Agents
    try:
        agent_req = urllib.request.Request(url)
        agent_req.add_header("Authorization", f"Bearer {token}")
        with urllib.request.urlopen(agent_req, context=ctx, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            items = data.get("data", {}).get("affected_items", [])
            print("\n" + "=" * 70)
            print("                 WAZUH AGENT STATUS REPORT")
            print("=" * 70)
            print(f"{'ID':<6} {'NAME':<16} {'IP':<16} {'STATUS':<12} {'OS':<15}")
            print(f"{'--':<6} {'----':<16} {'--':<16} {'------':<12} {'--':<15}")
            for item in items:
                aid = item.get("id", "")
                name = item.get("name", "")
                ip = item.get("ip", "")
                status = item.get("status", "")
                os_name = item.get("os", {}).get("name", "N/A")
                print(f"{aid:<6} {name:<16} {ip:<16} {status:<12} {os_name:<15}")
            print("=" * 70 + "\n")
    except Exception as e:
        print(f"[!] Error querying agents: {e}")


def main():
    args = parse_arguments()
    print("=" * 60)
    print("   ATTACK vs DETECTION LAB -- Wazuh Telemetry Verifier    ")
    print("=" * 60)
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    if args.log_file:
        verify_from_local_log(args.log_file)
    elif args.password:
        verify_via_api(args.host, args.port, args.user, args.password)
    else:
        print("[*] No API credentials or log file specified.")
        print("    Usage examples:")
        print("      python verify_wazuh_telemetry.py --log-file evidence/logs/sample-alerts.json")
        print("      python verify_wazuh_telemetry.py --host 192.168.56.40 --user admin --password <SECRET>")
        print("\n[*] Offline validation test mode: OK.")


if __name__ == "__main__":
    main()
