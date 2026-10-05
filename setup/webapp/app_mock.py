#!/usr/bin/env python3
"""
Script Name: app_mock.py
Description: Lightweight Python HTTP mock server for the DetectLab Security Web App.
             Provides the exact same endpoints (/login, /api/users, /api/profile)
             and writes identical structured JSON logs to app-security.json for Wazuh ingestion.
Author: Senior DevSecOps & Detection Engineer
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import os
import sys
from datetime import datetime

PORT = 8080
LOG_FILE = "/var/log/detectlab/app-security.json" if os.name != 'nt' else "app-security.json"

# Ensure log directory exists
log_dir = os.path.dirname(LOG_FILE)
if log_dir and not os.path.exists(log_dir):
    try:
        os.makedirs(log_dir, exist_ok=True)
    except Exception:
        LOG_FILE = "app-security.json"

def log_event(event, username, source_ip, endpoint, status, message):
    log_entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "event": event,
        "username": username,
        "sourceIp": source_ip,
        "endpoint": endpoint,
        "httpStatus": status,
        "message": message
    }
    json_str = json.dumps(log_entry)
    print(f"[*] AUDIT: {json_str}")
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json_str + "\n")
    except Exception as e:
        print(f"[!] Warning: Could not write to {LOG_FILE}: {e}")

class SecurityHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        client_ip = self.client_address[0]
        if self.path == "/login":
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length).decode('utf-8')
            try:
                body = json.loads(post_data)
            except Exception:
                body = {}
            
            user = body.get("username", "anonymous")
            pwd = body.get("password", "")

            if user == "admin" and pwd == "SuperAdminSecret#2024":
                log_event("LOGIN_SUCCESS", user, client_ip, "/login", 200, "User authenticated successfully")
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{"status":"SUCCESS","token":"lab-jwt-token-9988"}')
            else:
                log_event("LOGIN_FAILED", user, client_ip, "/login", 401, "Invalid credentials provided")
                self.send_response(401)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{"status":"FAILED","error":"Bad credentials"}')
        else:
            log_event("ENDPOINT_NOT_FOUND", "anonymous", client_ip, self.path, 404, "Invalid route requested")
            self.send_response(404)
            self.end_headers()

    def do_GET(self):
        client_ip = self.client_address[0]
        if self.path == "/api/users":
            auth = self.headers.get("Authorization", "")
            if auth == "Bearer lab-jwt-token-9988":
                log_event("ENDPOINT_ACCESSED", "admin", client_ip, "/api/users", 200, "Authorized query to user list")
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{"users":["admin","analyst","svc_wazuh"]}')
            else:
                log_event("ACCESS_DENIED", "unauthenticated", client_ip, "/api/users", 403, "Unauthorized access attempt to restricted endpoint")
                self.send_response(403)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{"error":"Access Denied"}')
        elif self.path == "/api/profile":
            log_event("PROFILE_VIEWED", "anonymous", client_ip, "/api/profile", 200, "Public profile viewed")
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"app":"DetectLab API","version":"1.0"}')
        else:
            log_event("ENDPOINT_NOT_FOUND", "anonymous", client_ip, self.path, 404, "Resource not found (probing)")
            self.send_response(404)
            self.end_headers()

def run_server():
    server_address = ('0.0.0.0', PORT)
    httpd = HTTPServer(server_address, SecurityHandler)
    print(f"[*] DetectLab Security Web App running on port {PORT}...")
    print(f"[*] Audit logs writing to: {LOG_FILE}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] Server stopped.")

if __name__ == "__main__":
    run_server()
