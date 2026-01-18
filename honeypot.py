"""
Honeypot Module for Threat Map
Captures real attacks against decoy services
"""

import asyncio
import socket
import random
import string
from datetime import datetime
from dataclasses import dataclass
from typing import Callable, Optional
import json


@dataclass
class HoneypotEvent:
    """Represents a captured attack event"""
    timestamp: str
    honeypot_type: str
    attacker_ip: str
    attacker_port: int
    target_port: int
    payload: str
    credentials: Optional[dict] = None
    user_agent: Optional[str] = None
    request_path: Optional[str] = None


class SSHHoneypot:
    """
    Fake SSH server that captures brute force attempts
    Mimics OpenSSH banner and captures credentials
    """

    SSH_BANNER = b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"

    def __init__(self, port: int = 2222, callback: Callable = None):
        self.port = port
        self.callback = callback
        self.server = None
        self.running = False

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle an SSH connection attempt"""
        peer = writer.get_extra_info('peername')
        attacker_ip = peer[0] if peer else "unknown"
        attacker_port = peer[1] if peer else 0

        try:
            # Send SSH banner
            writer.write(self.SSH_BANNER)
            await writer.drain()

            # Read client banner
            client_banner = await asyncio.wait_for(reader.readline(), timeout=10)

            # Simulate key exchange (just read some data)
            data = await asyncio.wait_for(reader.read(1024), timeout=10)

            # Create event
            event = HoneypotEvent(
                timestamp=datetime.utcnow().isoformat() + "Z",
                honeypot_type="SSH",
                attacker_ip=attacker_ip,
                attacker_port=attacker_port,
                target_port=self.port,
                payload=data.hex()[:200] if data else "",
                credentials=None  # Would need full SSH implementation to capture
            )

            if self.callback:
                await self.callback(event)

        except asyncio.TimeoutError:
            pass
        except Exception as e:
            print(f"SSH Honeypot error: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

    async def start(self):
        """Start the SSH honeypot"""
        try:
            self.server = await asyncio.start_server(
                self.handle_client,
                '0.0.0.0',
                self.port
            )
            self.running = True
            print(f"[Honeypot] SSH honeypot listening on port {self.port}")

            async with self.server:
                await self.server.serve_forever()
        except PermissionError:
            print(f"[Honeypot] Cannot bind to port {self.port} - need root or use port > 1024")
        except Exception as e:
            print(f"[Honeypot] SSH honeypot error: {e}")

    async def stop(self):
        """Stop the honeypot"""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            self.running = False


class HTTPHoneypot:
    """
    Fake HTTP server that captures web attacks
    Captures SQL injection, XSS, path traversal, etc.
    """

    # Fake responses for different paths
    RESPONSES = {
        "/": b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><head><title>Welcome</title></head><body><h1>Welcome</h1></body></html>",
        "/admin": b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"Admin\"\r\n\r\nUnauthorized",
        "/login": b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><form method='post'><input name='user'><input name='pass' type='password'><button>Login</button></form></html>",
        "/wp-admin": b"HTTP/1.1 302 Found\r\nLocation: /wp-login.php\r\n\r\n",
        "/phpmyadmin": b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><title>phpMyAdmin</title><body>phpMyAdmin</body></html>",
    }

    # Attack patterns to detect
    ATTACK_PATTERNS = {
        "sql_injection": [
            "' OR '1'='1", "UNION SELECT", "DROP TABLE", "INSERT INTO",
            "1=1", "' OR ''='", "admin'--", "1' OR '1'='1"
        ],
        "xss": [
            "<script>", "javascript:", "onerror=", "onload=",
            "<img src=", "<svg", "alert("
        ],
        "path_traversal": [
            "../", "..\\", "/etc/passwd", "/etc/shadow",
            "c:\\windows", "..%2f", "..%5c"
        ],
        "command_injection": [
            "; ls", "| cat", "&& whoami", "`id`",
            "$(cat", "; nc ", "| nc "
        ],
        "scanner": [
            "nikto", "sqlmap", "nmap", "masscan",
            "zgrab", "censys", "shodan"
        ]
    }

    def __init__(self, port: int = 8080, callback: Callable = None):
        self.port = port
        self.callback = callback
        self.server = None
        self.running = False

    def detect_attack_type(self, request: str) -> str:
        """Detect the type of attack from the request"""
        request_lower = request.lower()

        for attack_type, patterns in self.ATTACK_PATTERNS.items():
            for pattern in patterns:
                if pattern.lower() in request_lower:
                    return attack_type

        return "reconnaissance"

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle an HTTP connection"""
        peer = writer.get_extra_info('peername')
        attacker_ip = peer[0] if peer else "unknown"
        attacker_port = peer[1] if peer else 0

        try:
            # Read HTTP request
            request_data = await asyncio.wait_for(reader.read(4096), timeout=10)
            request = request_data.decode('utf-8', errors='ignore')

            # Parse request
            lines = request.split('\r\n')
            request_line = lines[0] if lines else ""
            parts = request_line.split(' ')
            method = parts[0] if parts else "GET"
            path = parts[1] if len(parts) > 1 else "/"

            # Extract headers
            user_agent = ""
            for line in lines:
                if line.lower().startswith("user-agent:"):
                    user_agent = line[11:].strip()
                    break

            # Detect attack type
            attack_type = self.detect_attack_type(request)

            # Map to threat types
            threat_type_map = {
                "sql_injection": "SQL Injection",
                "xss": "XSS",
                "path_traversal": "Malware",
                "command_injection": "Malware",
                "scanner": "Scanner",
                "reconnaissance": "Scanner"
            }

            # Create event
            event = HoneypotEvent(
                timestamp=datetime.utcnow().isoformat() + "Z",
                honeypot_type="HTTP",
                attacker_ip=attacker_ip,
                attacker_port=attacker_port,
                target_port=self.port,
                payload=request[:500],
                user_agent=user_agent,
                request_path=path
            )
            event.attack_type = threat_type_map.get(attack_type, "Scanner")

            if self.callback:
                await self.callback(event)

            # Send fake response
            response = self.RESPONSES.get(path.split('?')[0], self.RESPONSES["/"])
            writer.write(response)
            await writer.drain()

        except asyncio.TimeoutError:
            pass
        except Exception as e:
            print(f"HTTP Honeypot error: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

    async def start(self):
        """Start the HTTP honeypot"""
        try:
            self.server = await asyncio.start_server(
                self.handle_client,
                '0.0.0.0',
                self.port
            )
            self.running = True
            print(f"[Honeypot] HTTP honeypot listening on port {self.port}")

            async with self.server:
                await self.server.serve_forever()
        except PermissionError:
            print(f"[Honeypot] Cannot bind to port {self.port} - need root or use port > 1024")
        except Exception as e:
            print(f"[Honeypot] HTTP honeypot error: {e}")

    async def stop(self):
        """Stop the honeypot"""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            self.running = False


class TelnetHoneypot:
    """Fake Telnet server for IoT botnet detection"""

    BANNER = b"\r\nLogin: "
    PASSWORD_PROMPT = b"Password: "

    # Common IoT default credentials that botnets try
    KNOWN_CREDENTIALS = [
        ("admin", "admin"), ("root", "root"), ("admin", "password"),
        ("root", "12345"), ("admin", "1234"), ("user", "user"),
        ("support", "support"), ("guest", "guest")
    ]

    def __init__(self, port: int = 2323, callback: Callable = None):
        self.port = port
        self.callback = callback
        self.server = None
        self.running = False

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle a Telnet connection"""
        peer = writer.get_extra_info('peername')
        attacker_ip = peer[0] if peer else "unknown"
        attacker_port = peer[1] if peer else 0

        try:
            # Send login prompt
            writer.write(self.BANNER)
            await writer.drain()

            # Read username
            username = await asyncio.wait_for(reader.readline(), timeout=30)
            username = username.decode('utf-8', errors='ignore').strip()

            # Send password prompt
            writer.write(self.PASSWORD_PROMPT)
            await writer.drain()

            # Read password
            password = await asyncio.wait_for(reader.readline(), timeout=30)
            password = password.decode('utf-8', errors='ignore').strip()

            # Check if it's a known botnet credential
            is_botnet = (username, password) in self.KNOWN_CREDENTIALS

            # Create event
            event = HoneypotEvent(
                timestamp=datetime.utcnow().isoformat() + "Z",
                honeypot_type="Telnet",
                attacker_ip=attacker_ip,
                attacker_port=attacker_port,
                target_port=self.port,
                payload=f"Credentials: {username}:{password}",
                credentials={"username": username, "password": password}
            )
            event.attack_type = "Botnet" if is_botnet else "Brute Force"

            if self.callback:
                await self.callback(event)

            # Always reject
            writer.write(b"\r\nLogin incorrect\r\n")
            await writer.drain()

        except asyncio.TimeoutError:
            pass
        except Exception as e:
            print(f"Telnet Honeypot error: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

    async def start(self):
        """Start the Telnet honeypot"""
        try:
            self.server = await asyncio.start_server(
                self.handle_client,
                '0.0.0.0',
                self.port
            )
            self.running = True
            print(f"[Honeypot] Telnet honeypot listening on port {self.port}")

            async with self.server:
                await self.server.serve_forever()
        except PermissionError:
            print(f"[Honeypot] Cannot bind to port {self.port}")
        except Exception as e:
            print(f"[Honeypot] Telnet honeypot error: {e}")

    async def stop(self):
        """Stop the honeypot"""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            self.running = False


class HoneypotManager:
    """Manages all honeypots"""

    def __init__(self, callback: Callable = None):
        self.callback = callback
        self.honeypots = {}
        self.stats = {
            "ssh_attempts": 0,
            "http_attempts": 0,
            "telnet_attempts": 0,
            "total_unique_ips": set()
        }

    async def event_handler(self, event: HoneypotEvent):
        """Handle events from honeypots"""
        # Update stats
        if event.honeypot_type == "SSH":
            self.stats["ssh_attempts"] += 1
        elif event.honeypot_type == "HTTP":
            self.stats["http_attempts"] += 1
        elif event.honeypot_type == "Telnet":
            self.stats["telnet_attempts"] += 1

        self.stats["total_unique_ips"].add(event.attacker_ip)

        # Forward to main callback
        if self.callback:
            await self.callback(event)

    async def start_all(self, ssh_port=2222, http_port=8080, telnet_port=2323):
        """Start all honeypots"""
        self.honeypots["ssh"] = SSHHoneypot(port=ssh_port, callback=self.event_handler)
        self.honeypots["http"] = HTTPHoneypot(port=http_port, callback=self.event_handler)
        self.honeypots["telnet"] = TelnetHoneypot(port=telnet_port, callback=self.event_handler)

        tasks = [
            asyncio.create_task(self.honeypots["ssh"].start()),
            asyncio.create_task(self.honeypots["http"].start()),
            asyncio.create_task(self.honeypots["telnet"].start()),
        ]

        return tasks

    async def stop_all(self):
        """Stop all honeypots"""
        for name, honeypot in self.honeypots.items():
            await honeypot.stop()
            print(f"[Honeypot] Stopped {name} honeypot")

    def get_stats(self):
        """Get honeypot statistics"""
        return {
            "ssh_attempts": self.stats["ssh_attempts"],
            "http_attempts": self.stats["http_attempts"],
            "telnet_attempts": self.stats["telnet_attempts"],
            "unique_attackers": len(self.stats["total_unique_ips"])
        }
