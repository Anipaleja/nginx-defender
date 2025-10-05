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
from typing import Dict, List, Optional, Callable
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
    
    def __init__(self, config: Optional[Dict] = None, config_file: Optional[str] = None):
        # Load configuration from file if provided
        if config_file:
            try:
                import json
                try:
                    import yaml
                except ImportError:
                    yaml = None
                
                with open(config_file, 'r') as f:
                    if config_file.endswith('.json'):
                        file_config = json.load(f)
                    elif config_file.endswith(('.yml', '.yaml')):
                        if yaml is None:
                            raise ValueError(f"YAML config file {config_file} requires PyYAML. Install it with: pip install PyYAML")
                        file_config = yaml.safe_load(f)
                    else:
                        # Try to parse as JSON first, then YAML if available
                        content = f.read()
                        try:
                            file_config = json.loads(content)
                        except json.JSONDecodeError:
                            if yaml is None:
                                raise ValueError(f"Could not parse {config_file} as JSON and PyYAML is not available. Install PyYAML with: pip install PyYAML")
                            try:
                                file_config = yaml.safe_load(content)
                            except Exception as e:
                                raise ValueError(f"Failed to parse {config_file} as JSON or YAML: {e}")
                
                # Merge with provided config - runtime config parameter takes precedence
                self.config = {**file_config, **(config or {})}
            except (FileNotFoundError, json.JSONDecodeError) as e:
                raise ValueError(f"Failed to load config file {config_file}: {e}")
            except Exception as e:
                raise ValueError(f"Failed to load config file {config_file}: {e}")
        else:
            self.config = config or {}
        
        # Apply defaults for missing values
        default_config = {
            "log_level": "info",
            "dry_run": False,
            "web_ui": True,
            "web_ui_port": 8080,
            "metrics_port": 9090,
        }
        for key, value in default_config.items():
            if key not in self.config:
                self.config[key] = value
                
        self.base_url = f"http://localhost:{self.config['web_ui_port']}"
        self.is_running = False
        self._threat_callbacks = []
        self._block_callbacks = []
        self._process = None
        
    def start(self) -> bool:
        """Start the nginx-defender service."""
        import shutil
        import logging
        
        # Get configurable binary path
        binary_path = self.config.get('binary_path')
        if not binary_path:
            # Search in PATH
            binary_path = shutil.which('nginx-defender-service')
            if not binary_path:
                # Try local binary as fallback
                binary_path = './nginx-defender-service'
        
        try:
            # Validate port is valid integer in range
            port = self.config['web_ui_port']
            if not isinstance(port, int) or port < 1 or port > 65535:
                logging.error(f"Invalid web_ui_port: {port}. Must be integer between 1-65535")
                return False
            
            # Build command safely
            cmd = [binary_path, "--api-mode", "--port", str(port)]
            
            # Start subprocess with safe options
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                close_fds=True,
                env=None  # Use clean environment
            )
            
            # Wait for service to be ready
            for _ in range(30):  # 30 second timeout
                try:
                    response = requests.get(f"{self.base_url}/health", timeout=1)
                    if response.status_code == 200:
                        self.is_running = True
                        return True
                except requests.RequestException:
                    time.sleep(1)
                    
            logging.error("Service failed to become ready within timeout")
            return False
            
        except FileNotFoundError as e:
            logging.error(f"nginx-defender binary not found at {binary_path}: {e}")
            return False
        except ValueError as e:
            logging.error(f"Invalid port configuration: {e}")
            return False
        except subprocess.SubprocessError as e:
            logging.error(f"Failed to start subprocess: {e}")
            return False
        except requests.RequestException as e:
            logging.error(f"Failed to connect to service: {e}")
            return False
        except Exception as e:
            logging.error(f"Unexpected error starting nginx-defender: {e}", exc_info=True)
            return False
    
    def stop(self) -> None:
        """Stop the nginx-defender service."""
        if self._process:
            self._process.terminate()
            self._process.wait()
        self.is_running = False
    
    def should_block(self, ip: str) -> bool:
        """Check if an IP should be blocked."""
        try:
            response = requests.post(f"{self.base_url}/api/check", 
                                   json={"ip": ip}, timeout=5)
            if response.status_code == 200:
                data = response.json()
                return data.get("should_block", False)
        except requests.RequestException:
            pass
        return False
    
    def get_threat_score(self, ip: str) -> int:
        """Get threat score for an IP."""
        try:
            response = requests.post(f"{self.base_url}/api/check", 
                                   json={"ip": ip}, timeout=5)
            if response.status_code == 200:
                data = response.json()
                return data.get("threat_score", 0)
        except requests.RequestException:
            pass
        return 0
    
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
        self._threat_callbacks.append(callback)
    
    def on_block_decision(self, callback: Callable[[BlockEvent], None]) -> None:
        """Register callback for block decision events."""
        self._block_callbacks.append(callback)
    
    def __enter__(self):
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()


# Flask/Django middleware
class FlaskDefenderMiddleware:
    """Flask middleware for nginx-defender integration."""
    
    def __init__(self, app, defender: NginxDefender = None):
        self.app = app
        self.defender = defender or _get_global_defender()
        self.app.before_request(self._before_request)
    
    def _before_request(self):
        from flask import request, abort
        
        client_ip = self._get_client_ip(request)
        if self.defender.should_block(client_ip):
            abort(403, "Access denied by security system")
            
    def _get_client_ip(self, request):
        """Extract client IP from request, only trusting X-Forwarded-For from configured trusted proxies."""
        import ipaddress
        
        remote_addr = request.remote_addr
        trusted_proxies = self.defender.config.get('trusted_proxies', [])
        
        # Only trust X-Forwarded-For if the immediate client is a trusted proxy
        if trusted_proxies and remote_addr:
            try:
                remote_ip = ipaddress.ip_address(remote_addr)
                is_trusted = False
                
                for proxy in trusted_proxies:
                    try:
                        if '/' in proxy:
                            # CIDR network
                            if remote_ip in ipaddress.ip_network(proxy, strict=False):
                                is_trusted = True
                                break
                        else:
                            # Single IP
                            if remote_ip == ipaddress.ip_address(proxy):
                                is_trusted = True
                                break
                    except ValueError:
                        continue
                
                if is_trusted:
                    x_forwarded_for = request.environ.get('HTTP_X_FORWARDED_FOR', '')
                    if x_forwarded_for:
                        # Parse comma-separated IPs and return first valid one
                        ips = [ip.strip() for ip in x_forwarded_for.split(',')]
                        for ip in ips:
                            if ip:
                                try:
                                    ipaddress.ip_address(ip)  # Validate IP syntax
                                    return ip
                                except ValueError:
                                    continue
            except ValueError:
                pass
        
        return remote_addr


class DjangoDefenderMiddleware:
    """Django middleware for nginx-defender integration."""
    
    def __init__(self, get_response, defender: NginxDefender = None):
        self.get_response = get_response
        self.defender = defender or _get_global_defender()
        
        # Initialize defender with error handling
        if not self.defender.is_running:
            try:
                success = self.defender.start()
                if not success:
                    import logging
                    logging.error("Failed to start nginx-defender service")
                    raise RuntimeError("nginx-defender service failed to start")
            except Exception as e:
                import logging
                logging.error(f"Error starting nginx-defender: {e}")
                raise
        
        # Register cleanup on process shutdown
        import atexit
        atexit.register(self._cleanup)
    
    def __call__(self, request):
        client_ip = self._get_client_ip(request)
        
        if self.defender.should_block(client_ip):
            from django.http import HttpResponseForbidden
            return HttpResponseForbidden("Access denied by security system")
        
        response = self.get_response(request)
        return response
    
    def _get_client_ip(self, request):
        """Extract client IP from request, only trusting X-Forwarded-For from configured trusted proxies."""
        import ipaddress
        
        remote_addr = request.META.get('REMOTE_ADDR')
        trusted_proxies = self.defender.config.get('trusted_proxies', [])
        
        # Only trust X-Forwarded-For if the immediate client is a trusted proxy
        if trusted_proxies and remote_addr:
            try:
                remote_ip = ipaddress.ip_address(remote_addr)
                is_trusted = False
                
                for proxy in trusted_proxies:
                    try:
                        if '/' in proxy:
                            # CIDR network
                            if remote_ip in ipaddress.ip_network(proxy, strict=False):
                                is_trusted = True
                                break
                        else:
                            # Single IP
                            if remote_ip == ipaddress.ip_address(proxy):
                                is_trusted = True
                                break
                    except ValueError:
                        continue
                
                if is_trusted:
                    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR', '')
                    if x_forwarded_for:
                        # Parse comma-separated IPs and return first valid one
                        ips = [ip.strip() for ip in x_forwarded_for.split(',')]
                        for ip in ips:
                            if ip:
                                try:
                                    ipaddress.ip_address(ip)  # Validate IP syntax
                                    return ip
                                except ValueError:
                                    continue
            except ValueError:
                pass
        
        return remote_addr
        
    def _cleanup(self):
        """Clean up defender resources on shutdown."""
        if self.defender and self.defender.is_running:
            self.defender.stop()


# Global defender singleton for middleware use
_global_defender = None

def _get_global_defender():
    """Get or create global defender instance."""
    global _global_defender
    if _global_defender is None:
        _global_defender = NginxDefender()
    return _global_defender


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
            score = defender.get_threat_score(ip)
            blocked = defender.should_block(ip)
            print(f"IP {ip}: Score={score}, Blocked={blocked}")
        
        # Block a suspicious IP
        defender.block_ip("203.0.113.1", 30, "Suspicious activity")
        
        # Show metrics
        metrics = defender.get_metrics()
        print(f"Metrics: {metrics}")
        
        print("Running for 30 seconds...")
        time.sleep(30)
