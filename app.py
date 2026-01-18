#!/usr/bin/env python3
"""
Real-time Internet Threat Map with Live Threat Intelligence Feeds
Integrates multiple public threat feeds for real attack data
"""

import asyncio
import json
import random
import time
import re
from datetime import datetime, timedelta
from pathlib import Path
from collections import deque
import aiohttp
from aiohttp import web
import aiohttp_cors

# ============================================================================
# THREAT INTELLIGENCE FEEDS (No API keys required)
# ============================================================================

THREAT_FEEDS = {
    # URLhaus - Malware distribution (most reliable)
    "urlhaus": {
        "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "type": "Malware",
        "refresh_minutes": 5,
    },
    # Feodo Tracker - Botnet C&C IPs (full list)
    "feodo_full": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "type": "Botnet",
        "refresh_minutes": 15,
    },
    # SSLBL - SSL Blacklist (malicious SSL certs)
    "sslbl": {
        "url": "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
        "type": "Botnet",
        "refresh_minutes": 30,
    },
    # Emerging Threats - Compromised IPs
    "emergingthreats": {
        "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "type": "Malware",
        "refresh_minutes": 60,
    },
    # Cinsscore - CI Army bad IPs
    "cinsscore": {
        "url": "https://cinsscore.com/list/ci-badguys.txt",
        "type": "Scanner",
        "refresh_minutes": 60,
    },
    # Spamhaus DROP (Don't Route Or Peer)
    "spamhaus_drop": {
        "url": "https://www.spamhaus.org/drop/drop.txt",
        "type": "Spam",
        "refresh_minutes": 120,
    },
}

# GeoIP service (free, no key needed)
GEOIP_API = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon,isp,org"
GEOIP_BATCH_API = "http://ip-api.com/batch?fields=status,query,country,countryCode,city,lat,lon,isp"

# Threat types with colors
THREAT_TYPES = {
    "DDoS": {"color": "#ff4444", "description": "Distributed Denial of Service"},
    "Malware": {"color": "#ff8800", "description": "Malware Distribution"},
    "Botnet": {"color": "#aa00ff", "description": "Botnet Command & Control"},
    "Brute Force": {"color": "#ffff00", "description": "Brute Force Attack"},
    "SQL Injection": {"color": "#00ff88", "description": "SQL Injection Attempt"},
    "XSS": {"color": "#00ffff", "description": "Cross-Site Scripting"},
    "Phishing": {"color": "#ff00ff", "description": "Phishing Campaign"},
    "Ransomware": {"color": "#ff0000", "description": "Ransomware Attack"},
    "APT": {"color": "#ffffff", "description": "Advanced Persistent Threat"},
    "Spam": {"color": "#888888", "description": "Spam/Abuse"},
    "Scanner": {"color": "#4488ff", "description": "Port Scanner"},
}

# Common target infrastructure (data centers, financial, government)
TARGET_INFRASTRUCTURE = [
    {"city": "Ashburn", "country": "USA", "lat": 39.0438, "lng": -77.4874, "type": "Cloud/DC"},
    {"city": "San Jose", "country": "USA", "lat": 37.3382, "lng": -121.8863, "type": "Tech"},
    {"city": "New York", "country": "USA", "lat": 40.7128, "lng": -74.0060, "type": "Financial"},
    {"city": "London", "country": "UK", "lat": 51.5074, "lng": -0.1278, "type": "Financial"},
    {"city": "Frankfurt", "country": "Germany", "lat": 50.1109, "lng": 8.6821, "type": "Cloud/DC"},
    {"city": "Amsterdam", "country": "Netherlands", "lat": 52.3676, "lng": 4.9041, "type": "Cloud/DC"},
    {"city": "Singapore", "country": "Singapore", "lat": 1.3521, "lng": 103.8198, "type": "Cloud/DC"},
    {"city": "Tokyo", "country": "Japan", "lat": 35.6762, "lng": 139.6503, "type": "Tech"},
    {"city": "Sydney", "country": "Australia", "lat": -33.8688, "lng": 151.2093, "type": "Cloud/DC"},
    {"city": "Toronto", "country": "Canada", "lat": 43.6532, "lng": -79.3832, "type": "Financial"},
    {"city": "Paris", "country": "France", "lat": 48.8566, "lng": 2.3522, "type": "Government"},
    {"city": "Washington DC", "country": "USA", "lat": 38.9072, "lng": -77.0369, "type": "Government"},
    {"city": "Seoul", "country": "South Korea", "lat": 37.5665, "lng": 126.9780, "type": "Tech"},
    {"city": "Mumbai", "country": "India", "lat": 19.0760, "lng": 72.8777, "type": "Financial"},
    {"city": "São Paulo", "country": "Brazil", "lat": -23.5505, "lng": -46.6333, "type": "Financial"},
    {"city": "Dubai", "country": "UAE", "lat": 25.2048, "lng": 55.2708, "type": "Financial"},
    {"city": "Hong Kong", "country": "China", "lat": 22.3193, "lng": 114.1694, "type": "Financial"},
    {"city": "Zurich", "country": "Switzerland", "lat": 47.3769, "lng": 8.5417, "type": "Financial"},
    {"city": "Chicago", "country": "USA", "lat": 41.8781, "lng": -87.6298, "type": "Financial"},
    {"city": "Los Angeles", "country": "USA", "lat": 34.0522, "lng": -118.2437, "type": "Tech"},
]


class ThreatIntelligence:
    """Manages real threat intelligence feeds"""

    def __init__(self):
        self.threat_ips = {}  # IP -> threat info
        self.geo_cache = {}   # IP -> geo info
        self.last_fetch = {}  # feed -> timestamp
        self.feed_stats = {name: {"count": 0, "last_update": None} for name in THREAT_FEEDS}
        self.recent_threats = deque(maxlen=10000)

    async def fetch_all_feeds(self, session):
        """Fetch all threat feeds"""
        tasks = []
        for name, feed in THREAT_FEEDS.items():
            # Check if refresh needed
            last = self.last_fetch.get(name, 0)
            if time.time() - last > feed["refresh_minutes"] * 60:
                tasks.append(self.fetch_feed(session, name, feed))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def fetch_feed(self, session, name, feed):
        """Fetch a single threat feed"""
        try:
            print(f"[*] Fetching {name} feed...", flush=True)
            async with session.get(feed["url"], timeout=aiohttp.ClientTimeout(total=30)) as resp:
                if resp.status == 200:
                    content = await resp.text()
                    count = self.parse_feed(name, feed, content)
                    self.last_fetch[name] = time.time()
                    self.feed_stats[name]["count"] = count
                    self.feed_stats[name]["last_update"] = datetime.utcnow().isoformat()
                    print(f"[+] {name}: loaded {count} threat IPs", flush=True)
        except Exception as e:
            print(f"[-] Error fetching {name}: {e}", flush=True)

    def parse_feed(self, name, feed, content):
        """Parse feed content based on type"""
        count = 0
        threat_type = feed["type"]

        if name == "urlhaus":
            # CSV format with IP addresses in URLs
            for line in content.split("\n"):
                if line.startswith("#") or not line.strip():
                    continue
                # Extract IP from URL field
                ip_match = re.search(r'http[s]?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                if ip_match:
                    ip = ip_match.group(1)
                    if self.is_valid_ip(ip):
                        # Extract threat type if available
                        malware_type = "Unknown"
                        if "Mozi" in line:
                            malware_type = "Mozi Botnet"
                        elif "Mirai" in line:
                            malware_type = "Mirai Botnet"
                        elif "emotet" in line.lower():
                            malware_type = "Emotet"
                        elif "trickbot" in line.lower():
                            malware_type = "TrickBot"
                        elif "cobalt" in line.lower():
                            malware_type = "CobaltStrike"

                        self.threat_ips[ip] = {
                            "type": "Malware",
                            "source": "URLhaus",
                            "malware": malware_type,
                            "port": 80,
                        }
                        count += 1

        elif name == "spamhaus_drop":
            # CIDR format: IP/prefix ; comment
            for line in content.split("\n"):
                if line.startswith(";") or not line.strip():
                    continue
                parts = line.split(";")
                if parts:
                    cidr = parts[0].strip()
                    # Take the base IP from CIDR
                    ip = cidr.split("/")[0] if "/" in cidr else cidr
                    if self.is_valid_ip(ip):
                        self.threat_ips[ip] = {
                            "type": "Spam",
                            "source": "Spamhaus DROP",
                            "port": 25,
                        }
                        count += 1

        else:
            # Plain text IP list (most common format)
            for line in content.split("\n"):
                line = line.strip()
                if not line or line.startswith("#") or line.startswith(";"):
                    continue
                # Handle various formats
                # Could be just IP, or IP with comment, or IP/CIDR
                parts = line.split()
                ip_candidate = parts[0].split("/")[0].split(";")[0].strip()

                if self.is_valid_ip(ip_candidate):
                    source_names = {
                        "feodo_full": "Feodo Tracker",
                        "sslbl": "SSL Blacklist",
                        "emergingthreats": "Emerging Threats",
                        "cinsscore": "CI Army",
                    }
                    self.threat_ips[ip_candidate] = {
                        "type": threat_type,
                        "source": source_names.get(name, name),
                        "port": self.get_default_port(threat_type),
                    }
                    count += 1

        return count

    def is_valid_ip(self, ip):
        """Check if string is a valid public IPv4"""
        try:
            parts = ip.split(".")
            if len(parts) != 4:
                return False
            nums = [int(p) for p in parts]
            if not all(0 <= n <= 255 for n in nums):
                return False
            # Exclude private/reserved ranges
            if nums[0] in (0, 10, 127, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 255):
                return False
            if nums[0] == 172 and 16 <= nums[1] <= 31:
                return False
            if nums[0] == 192 and nums[1] == 168:
                return False
            return True
        except:
            return False

    def get_default_port(self, threat_type):
        """Get default port for threat type"""
        ports = {
            "Brute Force": 22,
            "Phishing": 25,
            "SQL Injection": 80,
            "Malware": 80,
            "Botnet": 443,
            "DDoS": 80,
            "Spam": 25,
        }
        return ports.get(threat_type, 443)

    async def geolocate_ip(self, session, ip):
        """Get geolocation for an IP"""
        if ip in self.geo_cache:
            return self.geo_cache[ip]

        try:
            async with session.get(GEOIP_API.format(ip=ip), timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get("status") == "success":
                        geo = {
                            "city": data.get("city", "Unknown"),
                            "country": data.get("country", "Unknown"),
                            "lat": data.get("lat", 0),
                            "lng": data.get("lon", 0),
                            "isp": data.get("isp", "Unknown"),
                            "org": data.get("org", ""),
                        }
                        self.geo_cache[ip] = geo
                        return geo
        except Exception as e:
            pass

        # Fallback - estimate based on IP range
        return self.estimate_geo(ip)

    async def geolocate_batch(self, session, ips):
        """Geolocate multiple IPs in one request"""
        # Filter out already cached
        to_lookup = [ip for ip in ips if ip not in self.geo_cache]

        if not to_lookup:
            return

        # ip-api.com allows 100 IPs per batch
        for i in range(0, len(to_lookup), 100):
            batch = to_lookup[i:i+100]
            try:
                async with session.post(
                    GEOIP_BATCH_API,
                    json=batch,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status == 200:
                        results = await resp.json()
                        for result in results:
                            if result.get("status") == "success":
                                ip = result.get("query")
                                self.geo_cache[ip] = {
                                    "city": result.get("city", "Unknown"),
                                    "country": result.get("country", "Unknown"),
                                    "lat": result.get("lat", 0),
                                    "lng": result.get("lon", 0),
                                    "isp": result.get("isp", "Unknown"),
                                }
            except Exception as e:
                print(f"Batch geo error: {e}")

            # Rate limit: 15 requests per minute for batch
            await asyncio.sleep(4)

    def estimate_geo(self, ip):
        """Estimate geolocation from IP range"""
        try:
            first_octet = int(ip.split(".")[0])
            # Very rough estimates based on IANA allocations
            if first_octet in range(1, 56):
                return {"city": "Unknown", "country": "USA", "lat": 37.0, "lng": -95.0, "isp": "Unknown"}
            elif first_octet in range(56, 80):
                return {"city": "Unknown", "country": "Europe", "lat": 50.0, "lng": 10.0, "isp": "Unknown"}
            elif first_octet in range(80, 100):
                return {"city": "Unknown", "country": "Europe", "lat": 48.0, "lng": 2.0, "isp": "Unknown"}
            elif first_octet in range(100, 130):
                return {"city": "Unknown", "country": "Asia", "lat": 35.0, "lng": 105.0, "isp": "Unknown"}
            elif first_octet in range(130, 160):
                return {"city": "Unknown", "country": "Asia", "lat": 35.0, "lng": 139.0, "isp": "Unknown"}
            elif first_octet in range(160, 200):
                return {"city": "Unknown", "country": "Americas", "lat": 40.0, "lng": -100.0, "isp": "Unknown"}
            else:
                return {"city": "Unknown", "country": "Unknown", "lat": 0, "lng": 0, "isp": "Unknown"}
        except:
            return {"city": "Unknown", "country": "Unknown", "lat": 0, "lng": 0, "isp": "Unknown"}

    def get_random_threat(self):
        """Get a random threat IP from our database"""
        if not self.threat_ips:
            return None
        ip = random.choice(list(self.threat_ips.keys()))
        return ip, self.threat_ips[ip]

    def get_threat_count(self):
        """Get total threat IPs loaded"""
        return len(self.threat_ips)


# Global state
threat_intel = ThreatIntelligence()
connected_clients = set()
attack_history = []
stats = {
    "total_attacks": 0,
    "attacks_by_type": {t: 0 for t in THREAT_TYPES},
    "attacks_by_origin": {},
    "attacks_by_target": {},
    "start_time": datetime.utcnow().isoformat(),
    "threat_ips_loaded": 0,
    "feeds_status": {},
}
attack_id_counter = 0


async def generate_attack_from_real_data(session):
    """Generate an attack event using real threat intelligence"""
    global attack_id_counter

    threat = threat_intel.get_random_threat()
    if not threat:
        return None

    ip, info = threat
    attack_id_counter += 1

    # Get geolocation for attacker
    origin_geo = await threat_intel.geolocate_ip(session, ip)

    # Select a realistic target
    target = random.choice(TARGET_INFRASTRUCTURE)

    # Generate target IP (simulated)
    target_ip = f"{random.randint(10,200)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

    threat_type = info.get("type", "Malware")
    color = THREAT_TYPES.get(threat_type, {}).get("color", "#ff8800")

    # Determine severity
    severity = "medium"
    if threat_type in ("Ransomware", "APT", "Botnet"):
        severity = "critical" if random.random() > 0.7 else "high"
    elif threat_type in ("DDoS", "Malware", "SQL Injection"):
        severity = "high" if random.random() > 0.5 else "medium"

    attack = {
        "id": attack_id_counter,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "type": threat_type,
        "color": color,
        "description": THREAT_TYPES.get(threat_type, {}).get("description", ""),
        "origin": {
            "city": origin_geo.get("city", "Unknown"),
            "country": origin_geo.get("country", "Unknown"),
            "lat": origin_geo.get("lat", 0),
            "lng": origin_geo.get("lng", 0),
            "ip": ip,
            "isp": origin_geo.get("isp", "Unknown"),
        },
        "target": {
            "city": target["city"],
            "country": target["country"],
            "lat": target["lat"],
            "lng": target["lng"],
            "ip": target_ip,
            "port": info.get("port", 443),
            "infrastructure": target.get("type", "Unknown"),
        },
        "severity": severity,
        "source": info.get("source", "Unknown"),
        "malware": info.get("malware", None),
        "real_threat": True,  # Flag indicating this is from real intelligence
    }

    return attack


async def websocket_handler(request):
    """Handle WebSocket connections"""
    ws = web.WebSocketResponse()
    await ws.prepare(request)

    connected_clients.add(ws)
    print(f"Client connected. Total: {len(connected_clients)}")

    # Send initial data
    await ws.send_json({
        "type": "init",
        "stats": stats,
        "recent_attacks": attack_history[-50:],
        "threat_types": THREAT_TYPES,
        "feeds_status": threat_intel.feed_stats,
    })

    try:
        async for msg in ws:
            if msg.type == aiohttp.WSMsgType.TEXT:
                data = json.loads(msg.data)
                if data.get("action") == "ping":
                    await ws.send_json({"type": "pong"})
                elif data.get("action") == "get_stats":
                    await ws.send_json({
                        "type": "stats_update",
                        "stats": stats,
                        "feeds_status": threat_intel.feed_stats,
                    })
            elif msg.type == aiohttp.WSMsgType.ERROR:
                print(f"WebSocket error: {ws.exception()}")
    finally:
        connected_clients.discard(ws)
        print(f"Client disconnected. Total: {len(connected_clients)}")

    return ws


async def broadcast_attack(attack):
    """Broadcast attack to all connected clients"""
    if not connected_clients:
        return

    message = json.dumps({"type": "attack", "data": attack})

    disconnected = set()
    for ws in connected_clients:
        try:
            await ws.send_str(message)
        except Exception:
            disconnected.add(ws)

    connected_clients.difference_update(disconnected)


async def feed_updater(app):
    """Background task to update threat feeds periodically"""
    # Disable SSL verification for threat feeds (read-only public data)
    import ssl
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    connector = aiohttp.TCPConnector(ssl=ssl_context)
    session = aiohttp.ClientSession(connector=connector)
    app['feed_session'] = session

    try:
        while True:
            await threat_intel.fetch_all_feeds(session)
            stats["threat_ips_loaded"] = threat_intel.get_threat_count()
            stats["feeds_status"] = threat_intel.feed_stats

            # Pre-geolocate some IPs
            sample_ips = random.sample(
                list(threat_intel.threat_ips.keys()),
                min(50, len(threat_intel.threat_ips))
            ) if threat_intel.threat_ips else []

            if sample_ips:
                await threat_intel.geolocate_batch(session, sample_ips)

            # Wait before next update cycle
            await asyncio.sleep(60)
    finally:
        await session.close()


async def attack_generator(app):
    """Background task that generates attacks from real threat data"""
    global stats, attack_history

    # Wait for initial feed load
    await asyncio.sleep(5)

    # Session for GeoIP lookups (also needs SSL disabled)
    import ssl
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    connector = aiohttp.TCPConnector(ssl=ssl_context)
    session = aiohttp.ClientSession(connector=connector)
    app['attack_session'] = session

    try:
        while True:
            if threat_intel.get_threat_count() > 0:
                # Generate 1-3 attacks per cycle
                num_attacks = random.randint(1, 3)

                for _ in range(num_attacks):
                    attack = await generate_attack_from_real_data(session)

                    if attack:
                        # Update stats
                        stats["total_attacks"] += 1
                        stats["attacks_by_type"][attack["type"]] = stats["attacks_by_type"].get(attack["type"], 0) + 1

                        origin = attack["origin"]["city"]
                        target = attack["target"]["city"]
                        stats["attacks_by_origin"][origin] = stats["attacks_by_origin"].get(origin, 0) + 1
                        stats["attacks_by_target"][target] = stats["attacks_by_target"].get(target, 0) + 1

                        # Keep history limited
                        attack_history.append(attack)
                        if len(attack_history) > 1000:
                            attack_history = attack_history[-500:]

                        # Broadcast to clients
                        await broadcast_attack(attack)

            # Rate limit: avoid hitting GeoIP API too hard
            await asyncio.sleep(random.uniform(0.5, 2.0))
    finally:
        await session.close()


async def stats_handler(request):
    """Return current statistics"""
    return web.json_response({
        **stats,
        "feeds_status": threat_intel.feed_stats,
        "geo_cache_size": len(threat_intel.geo_cache),
    })


async def feeds_handler(request):
    """Return threat feed status"""
    return web.json_response({
        "feeds": threat_intel.feed_stats,
        "total_threat_ips": threat_intel.get_threat_count(),
        "geo_cached": len(threat_intel.geo_cache),
    })


async def index_handler(request):
    """Serve the main page"""
    html_path = Path(__file__).parent / "templates" / "index.html"
    return web.FileResponse(html_path)


async def start_background_tasks(app):
    """Start background tasks"""
    app['feed_updater'] = asyncio.create_task(feed_updater(app))
    app['attack_generator'] = asyncio.create_task(attack_generator(app))


async def cleanup_background_tasks(app):
    """Cleanup background tasks"""
    app['feed_updater'].cancel()
    app['attack_generator'].cancel()

    try:
        await app['feed_updater']
    except asyncio.CancelledError:
        pass

    try:
        await app['attack_generator']
    except asyncio.CancelledError:
        pass

    if 'feed_session' in app:
        await app['feed_session'].close()
    if 'attack_session' in app:
        await app['attack_session'].close()


def create_app():
    """Create and configure the application"""
    app = web.Application()

    # Setup CORS
    cors = aiohttp_cors.setup(app, defaults={
        "*": aiohttp_cors.ResourceOptions(
            allow_credentials=True,
            expose_headers="*",
            allow_headers="*",
        )
    })

    # Routes
    app.router.add_get("/", index_handler)
    app.router.add_get("/ws", websocket_handler)
    app.router.add_get("/api/stats", stats_handler)
    app.router.add_get("/api/feeds", feeds_handler)
    app.router.add_static("/static", Path(__file__).parent / "static")

    # Add CORS to routes
    for route in list(app.router.routes()):
        cors.add(route)

    # Background tasks
    app.on_startup.append(start_background_tasks)
    app.on_cleanup.append(cleanup_background_tasks)

    return app


if __name__ == "__main__":
    print("=" * 60)
    print("  REAL-TIME THREAT MAP - Live Threat Intelligence")
    print("=" * 60)
    print("\nData Sources:")
    for name, feed in THREAT_FEEDS.items():
        print(f"  - {name}: {feed['type']}")
    print("\nStarting server on http://localhost:8888")
    print("=" * 60)

    app = create_app()
    web.run_app(app, host="0.0.0.0", port=8888)
