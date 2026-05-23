#!/usr/bin/env python3
"""
nginx-defender Python Wrapper

This provides Python bindings for the nginx-defender Go library via HTTP API.
Install with: pip install nginx-defender
"""

import requests
import json
import subprocess
import time
import threading
from typing import Any, Callable, Dict, List, Optional
from dataclasses import dataclass


@dataclass
class ThreatEvent:
    ip: str
    score: int
    threat_types: List[str]
    action: str
    timestamp: str
    geo_info: Optional[Dict] = None


@dataclass
class BlockEvent:
    ip: str
    reason: str
    duration: str
    timestamp: str


class NginxDefender:
    """
    Python wrapper for nginx-defender WAF library.
    
    Usage:
        defender = NginxDefender()
        defender.start()
        
        # Check if IP should be blocked
        if defender.should_block("192.168.1.100"):
            # Handle blocking logic
            pass
            
        # Monitor log files
        defender.monitor_log_file("/var/log/nginx/access.log", "combined")
        
        # Set up event handlers
        defender.on_threat_detected(lambda event: print(f"Threat: {event.ip}"))
    """
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {
            "log_level": "info",
            "dry_run": False,
            "web_ui": True,
            "web_ui_port": 8080,
            "metrics_port": 9090,
        }
        self.base_url = f"http://localhost:{self.config['web_ui_port']}"
        self.is_running = False
        self._threat_callbacks = []
        self._block_callbacks = []
        self._process = None
        self._session = requests.Session()
        self._check_cache: Dict[str, Dict[str, Any]] = {}
        self._check_cache_ttl = 1.0
        self._lock = threading.RLock()

    def _check_ip(self, ip: str) -> Dict[str, Any]:
        with self._lock:
            if self._session is None:
                self._session = requests.Session()

            cache_entry = self._check_cache.get(ip)
            now = time.monotonic()
            if cache_entry and now - cache_entry["timestamp"] < self._check_cache_ttl:
                return cache_entry["result"]

            response = self._session.post(f"{self.base_url}/api/check", json={"ip": ip}, timeout=5)
            response.raise_for_status()
            result = response.json()
            self._check_cache[ip] = {"timestamp": now, "result": result}
            return result

    def check_ip(self, ip: str) -> Dict[str, Any]:
        """Fetch the current threat assessment for an IP address."""
        try:
            return self._check_ip(ip)
        except requests.RequestException:
            return {}
        
    def start(self) -> bool:
        """Start the nginx-defender service."""
        try:
            with self._lock:
                if self._session is None:
                    self._session = requests.Session()
                self._check_cache.clear()

            # Start the Go binary as a subprocess
            cmd = ["./nginx-defender-service", "--api-mode", "--port", str(self.config['web_ui_port'])]
            self._process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Wait for service to be ready
            for _ in range(30):  # 30 second timeout
                try:
                    response = self._session.get(f"{self.base_url}/health", timeout=1)
                    if response.status_code == 200:
                        self.is_running = True
                        return True
                except requests.RequestException:
                    time.sleep(1)
                    
            return False
        except Exception as e:
            print(f"Failed to start nginx-defender: {e}")
            return False
    
    def stop(self) -> None:
        """Stop the nginx-defender service."""
        with self._lock:
            if self._process:
                self._process.terminate()
                self._process.wait()
                self._process = None
            if self._session is not None:
                self._session.close()
                self._session = None
            self._check_cache.clear()
            self.is_running = False

    def close(self) -> None:
        """Release resources held by the wrapper."""
        self.stop()
    
    def should_block(self, ip: str) -> bool:
        """Check if an IP should be blocked."""
        data = self.check_ip(ip)
        return bool(data.get("should_block", False))
    
    def get_threat_score(self, ip: str) -> int:
        """Get threat score for an IP."""
        data = self.check_ip(ip)
        return int(data.get("threat_score", 0))
    
    def block_ip(self, ip: str, duration_minutes: int = 60, reason: str = "Manual block") -> bool:
        """Block an IP address."""
        try:
            response = requests.post(f"{self.base_url}/api/block", json={
                "ip": ip,
                "duration": f"{duration_minutes}m",
                "reason": reason
            }, timeout=5)
            return response.status_code == 200
        except requests.RequestException:
            return False
    
    def unblock_ip(self, ip: str) -> bool:
        """Unblock an IP address."""
        try:
            response = requests.post(f"{self.base_url}/api/unblock", 
                                   json={"ip": ip}, timeout=5)
            return response.status_code == 200
        except requests.RequestException:
            return False
    
    def monitor_log_file(self, path: str, format_type: str = "combined") -> bool:
        """Monitor a log file for threats."""
        try:
            response = requests.post(f"{self.base_url}/api/monitor", json={
                "path": path,
                "format": format_type
            }, timeout=5)
            return response.status_code == 200
        except requests.RequestException:
            return False
    
    def get_metrics(self) -> Dict:
        """Get current system metrics."""
        try:
            response = requests.get(f"{self.base_url}/api/metrics", timeout=5)
            if response.status_code == 200:
                return response.json()
        except requests.RequestException:
            pass
        return {}
    
    def on_threat_detected(self, callback: Callable[[ThreatEvent], None]) -> None:
        """Register callback for threat detection events."""
        with self._lock:
            self._threat_callbacks.append(callback)
    
    def on_block_decision(self, callback: Callable[[BlockEvent], None]) -> None:
        """Register callback for block decision events."""
        with self._lock:
            self._block_callbacks.append(callback)
    
    def __enter__(self):
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()


# Flask/Django middleware
class FlaskDefenderMiddleware:
    """Flask middleware for nginx-defender integration."""
    
    def __init__(self, app, defender: NginxDefender):
        self.app = app
        self.defender = defender
        self.app.before_request(self._before_request)
    
    def _before_request(self):
        from flask import request, abort
        
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        if self.defender.should_block(client_ip):
            abort(403, "Access denied by security system")


class DjangoDefenderMiddleware:
    """Django middleware for nginx-defender integration."""
    
    def __init__(self, get_response):
        self.get_response = get_response
        self.defender = NginxDefender()
        self.defender.start()
    
    def __call__(self, request):
        client_ip = self._get_client_ip(request)
        
        if self.defender.should_block(client_ip):
            from django.http import HttpResponseForbidden
            return HttpResponseForbidden("Access denied by security system")
        
        response = self.get_response(request)
        return response
    
    def _get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0]
        return request.META.get('REMOTE_ADDR')


# Example usage
if __name__ == "__main__":
    # Basic usage
    with NginxDefender() as defender:
        print("nginx-defender Python Example")
        
        # Set up event handlers
        defender.on_threat_detected(lambda event: 
            print(f"Threat: {event.ip} (Score: {event.score})"))
        
        defender.on_block_decision(lambda event: 
            print(f"Blocked: {event.ip} ({event.reason})"))
        
        # Monitor log file
        defender.monitor_log_file("/var/log/nginx/access.log", "combined")
        
        # Test some IPs
        test_ips = ["192.168.1.100", "10.0.0.1", "203.0.113.1"]
        
        for ip in test_ips:
            check = defender.check_ip(ip)
            score = check.get("threat_score", 0)
            blocked = check.get("should_block", False)
            print(f"IP {ip}: Score={score}, Blocked={blocked}")
        
        # Block a suspicious IP
        defender.block_ip("203.0.113.1", 30, "Suspicious activity")
        
        # Show metrics
        metrics = defender.get_metrics()
        print(f"Metrics: {metrics}")
        
        print("Running for 30 seconds...")
        time.sleep(30)
