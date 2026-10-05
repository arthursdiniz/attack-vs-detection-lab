#!/usr/bin/env python3
"""
Script Name: parse_logs.py
Description: Normalizes and extracts security IOCs (source IPs, usernames, commands,
             and timestamps) from raw JSON and syslog evidence logs.
Author: Senior SOC Analyst
"""

import argparse
import json
import os
import re
import sys

def parse_json_log(filepath):
    print(f"[*] Parsing JSON log: {filepath}")
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        try:
            data = json.load(f)
            if isinstance(data, list):
                for idx, entry in enumerate(data, start=1):
                    ts = entry.get("timestamp", "N/A")
                    rule = entry.get("rule", {}).get("description", entry.get("event", "Event"))
                    print(f"  [{idx:02d}] {ts} | {rule}")
            elif isinstance(data, dict):
                print(f"  [01] {data.get('timestamp')} | {data.get('rule', {}).get('description')}")
        except json.JSONDecodeError:
            # Multi-line JSON stream
            f.seek(0)
            for idx, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    print(f"  [{idx:02d}] {obj.get('timestamp')} | {obj.get('event', obj.get('rule', {}).get('id'))}")
                except Exception:
                    continue

def parse_syslog(filepath):
    print(f"[*] Parsing Syslog file: {filepath}")
    auth_fail_regex = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)")
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        matches = 0
        for line in f:
            m = auth_fail_regex.search(line)
            if m:
                matches += 1
                user, ip, port = m.groups()
                print(f"  [Match {matches:02d}] User: {user:<15} | Source IP: {ip:<15} | Port: {port}")
    print(f"[+] Total matched failed authentications: {matches}")

def main():
    parser = argparse.ArgumentParser(description="Normalize & Inspect Evidence Logs")
    parser.add_argument("file", help="Path to evidence log file")
    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"[!] Error: File '{args.file}' not found.")
        sys.exit(1)

    if args.file.endswith(".json"):
        parse_json_log(args.file)
    else:
        parse_syslog(args.file)

if __name__ == "__main__":
    main()
