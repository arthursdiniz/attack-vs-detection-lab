package com.detectlab.webapp.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@RestController
public class SecurityController {

    private static final Logger auditLogger = LoggerFactory.getLogger("SECURITY_AUDIT");

    private void logSecurityEvent(String event, String user, String endpoint, int status, String message, HttpServletRequest request) {
        String clientIp = request.getHeader("X-Forwarded-For");
        if (clientIp == null || clientIp.isEmpty()) {
            clientIp = request.getRemoteAddr();
        }

        // Output single-line structured JSON log
        String jsonLog = String.format(
            "{\"timestamp\":\"%s\",\"event\":\"%s\",\"username\":\"%s\",\"sourceIp\":\"%s\",\"endpoint\":\"%s\",\"httpStatus\":%d,\"message\":\"%s\"}",
            Instant.now().toString(), event, user, clientIp, endpoint, status, message
        );
        auditLogger.info(jsonLog);
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody Map<String, String> body, HttpServletRequest request) {
        String username = body.getOrDefault("username", "anonymous");
        String password = body.getOrDefault("password", "");

        Map<String, Object> response = new HashMap<>();

        // Controlled lab credentials
        if ("admin".equals(username) && "SuperAdminSecret#2024".equals(password)) {
            logSecurityEvent("LOGIN_SUCCESS", username, "/login", 200, "User authenticated successfully", request);
            response.put("status", "SUCCESS");
            response.put("token", "lab-session-jwt-token-9988");
            return ResponseEntity.ok(response);
        } else {
            logSecurityEvent("LOGIN_FAILED", username, "/login", 401, "Invalid credentials provided", request);
            response.put("status", "FAILED");
            response.put("error", "Bad credentials");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }
    }

    @GetMapping("/api/users")
    public ResponseEntity<Map<String, Object>> getUsers(@RequestHeader(value = "Authorization", required = false) String authHeader, HttpServletRequest request) {
        Map<String, Object> response = new HashMap<>();

        if (authHeader == null || !authHeader.startsWith("Bearer lab-session-jwt-token")) {
            logSecurityEvent("ACCESS_DENIED", "unauthenticated", "/api/users", 403, "Unauthorized access attempt to restricted endpoint", request);
            response.put("error", "Access Denied: Administrative role required");
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
        }

        logSecurityEvent("ENDPOINT_ACCESSED", "admin", "/api/users", 200, "Authorized query to user list", request);
        response.put("users", new String[]{"admin", "analyst", "svc_wazuh", "lab_user"});
        return ResponseEntity.ok(response);
    }

    @GetMapping("/api/profile")
    public ResponseEntity<Map<String, String>> getProfile(HttpServletRequest request) {
        logSecurityEvent("PROFILE_VIEWED", "anonymous", "/api/profile", 200, "Public profile viewed", request);
        Map<String, String> profile = new HashMap<>();
        profile.put("app", "Attack vs Detection Lab Security API");
        profile.put("version", "1.0.0");
        return ResponseEntity.ok(profile);
    }
}
