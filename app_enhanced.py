#!/usr/bin/env python3
"""
Enhanced Real-time Internet Threat Map
With database persistence, honeypots, alerts, enrichment, and more
"""

import asyncio
import json
import random
import time
import re
import ssl
from datetime import datetime, timedelta, timezone
from pathlib import Path
from collections import deque
import aiohttp
from aiohttp import web
import aiohttp_cors

# Import our modules
from database import (
    save_attack, get_attacks, get_time_series, get_top_attackers,
    get_top_countries, get_attack_type_stats, get_blocklist,
    get_ip_reputation, get_threat_actors, get_stats_summary,
    get_alert_rules, create_alert_rule
)
from honeypot import HoneypotManager, HoneypotEvent
from alerts import AlertManager, Alert
from enrichment import IPEnricher

# ============================================================================
# CONFIGURATION
# ============================================================================

THREAT_FEEDS = {
    "urlhaus": {
        "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "type": "Malware",
        "refresh_minutes": 5,
    },
    "feodo_full": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "type": "Botnet",
        "refresh_minutes": 15,
    },
    "sslbl": {
        "url": "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
        "type": "Botnet",
        "refresh_minutes": 30,
    },
    "emergingthreats": {
        "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "type": "Malware",
        "refresh_minutes": 60,
    },
    "cinsscore": {
        "url": "https://cinsscore.com/list/ci-badguys.txt",
        "type": "Scanner",
        "refresh_minutes": 60,
    },
    "spamhaus_drop": {
        "url": "https://www.spamhaus.org/drop/drop.txt",
        "type": "Spam",
        "refresh_minutes": 120,
    },
}

GEOIP_API = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon,isp,org,as"
GEOIP_BATCH_API = "http://ip-api.com/batch?fields=status,query,country,countryCode,city,lat,lon,isp,as"

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
]

# ============================================================================
# THREAT INTELLIGENCE
# ============================================================================

class ThreatIntelligence:
    def __init__(self):
        self.threat_ips = {}
        self.geo_cache = {}
        self.last_fetch = {}
        self.feed_stats = {name: {"count": 0, "last_update": None} for name in THREAT_FEEDS}

    async def fetch_all_feeds(self, session):
        tasks = []
        for name, feed in THREAT_FEEDS.items():
            last = self.last_fetch.get(name, 0)
            if time.time() - last > feed["refresh_minutes"] * 60:
                tasks.append(self.fetch_feed(session, name, feed))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def fetch_feed(self, session, name, feed):
        try:
            print(f"[*] Fetching {name} feed...", flush=True)
            async with session.get(feed["url"], timeout=aiohttp.ClientTimeout(total=30)) as resp:
                if resp.status == 200:
                    content = await resp.text()
                    count = self.parse_feed(name, feed, content)
                    self.last_fetch[name] = time.time()
                    self.feed_stats[name]["count"] = count
                    self.feed_stats[name]["last_update"] = datetime.now(timezone.utc).isoformat()
                    print(f"[+] {name}: loaded {count} threat IPs", flush=True)
        except Exception as e:
            print(f"[-] Error fetching {name}: {e}", flush=True)

    def parse_feed(self, name, feed, content):
        count = 0
        threat_type = feed["type"]

        if name == "urlhaus":
            for line in content.split("\n"):
                if line.startswith("#") or not line.strip():
                    continue
                ip_match = re.search(r'http[s]?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                if ip_match:
                    ip = ip_match.group(1)
                    if self.is_valid_ip(ip):
                        malware_type = "Unknown"
                        if "Mozi" in line: malware_type = "Mozi Botnet"
                        elif "Mirai" in line: malware_type = "Mirai Botnet"
                        elif "emotet" in line.lower(): malware_type = "Emotet"
                        elif "trickbot" in line.lower(): malware_type = "TrickBot"
                        elif "cobalt" in line.lower(): malware_type = "CobaltStrike"

                        self.threat_ips[ip] = {
                            "type": "Malware",
                            "source": "URLhaus",
                            "malware": malware_type,
                            "port": 80,
                        }
                        count += 1

        elif name == "spamhaus_drop":
            for line in content.split("\n"):
                if line.startswith(";") or not line.strip():
                    continue
                parts = line.split(";")
                if parts:
                    cidr = parts[0].strip()
                    ip = cidr.split("/")[0] if "/" in cidr else cidr
                    if self.is_valid_ip(ip):
                        self.threat_ips[ip] = {"type": "Spam", "source": "Spamhaus DROP", "port": 25}
                        count += 1
        else:
            for line in content.split("\n"):
                line = line.strip()
                if not line or line.startswith("#") or line.startswith(";"):
                    continue
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
        try:
            parts = ip.split(".")
            if len(parts) != 4:
                return False
            nums = [int(p) for p in parts]
            if not all(0 <= n <= 255 for n in nums):
                return False
            if nums[0] in (0, 10, 127, 224, 255):
                return False
            if nums[0] == 172 and 16 <= nums[1] <= 31:
                return False
            if nums[0] == 192 and nums[1] == 168:
                return False
            return True
        except:
            return False

    def get_default_port(self, threat_type):
        return {"Brute Force": 22, "Phishing": 25, "SQL Injection": 80, "Malware": 80, "Botnet": 443, "Spam": 25}.get(threat_type, 443)

    async def geolocate_ip(self, session, ip):
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
                            "asn": data.get("as", ""),
                        }
                        self.geo_cache[ip] = geo
                        return geo
        except:
            pass
        return {"city": "Unknown", "country": "Unknown", "lat": 0, "lng": 0, "isp": "Unknown", "asn": ""}

    def get_random_threat(self):
        if not self.threat_ips:
            return None
        ip = random.choice(list(self.threat_ips.keys()))
        return ip, self.threat_ips[ip]

    def get_threat_count(self):
        return len(self.threat_ips)


# ============================================================================
# GLOBAL STATE
# ============================================================================

threat_intel = ThreatIntelligence()
connected_clients = set()
attack_history = []
alert_manager = AlertManager()
ip_enricher = IPEnricher()
honeypot_manager = None

stats = {
    "total_attacks": 0,
    "attacks_by_type": {t: 0 for t in THREAT_TYPES},
    "attacks_by_origin": {},
    "attacks_by_target": {},
    "start_time": datetime.now(timezone.utc).isoformat(),
    "threat_ips_loaded": 0,
    "feeds_status": {},
}
attack_id_counter = 0


# ============================================================================
# ATTACK GENERATION
# ============================================================================

async def generate_attack_from_real_data(session):
    global attack_id_counter

    threat = threat_intel.get_random_threat()
    if not threat:
        return None

    ip, info = threat
    attack_id_counter += 1

    origin_geo = await threat_intel.geolocate_ip(session, ip)
    target = random.choice(TARGET_INFRASTRUCTURE)
    target_ip = f"{random.randint(10,200)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

    threat_type = info.get("type", "Malware")
    color = THREAT_TYPES.get(threat_type, {}).get("color", "#ff8800")

    severity = "medium"
    if threat_type in ("Ransomware", "APT", "Botnet"):
        severity = "critical" if random.random() > 0.7 else "high"
    elif threat_type in ("DDoS", "Malware", "SQL Injection"):
        severity = "high" if random.random() > 0.5 else "medium"

    attack = {
        "id": attack_id_counter,
        "timestamp": datetime.now(timezone.utc).isoformat(),
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
            "asn": origin_geo.get("asn", ""),
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
        "real_threat": True,
    }

    return attack


async def process_honeypot_event(event: HoneypotEvent):
    """Convert honeypot event to attack format"""
    global attack_id_counter
    attack_id_counter += 1

    # Get geolocation for attacker
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    connector = aiohttp.TCPConnector(ssl=ssl_context)

    async with aiohttp.ClientSession(connector=connector) as session:
        origin_geo = await threat_intel.geolocate_ip(session, event.attacker_ip)

    attack_type = getattr(event, 'attack_type', 'Brute Force')
    if event.honeypot_type == "HTTP":
        attack_type = getattr(event, 'attack_type', 'Scanner')

    attack = {
        "id": attack_id_counter,
        "timestamp": event.timestamp,
        "type": attack_type,
        "color": THREAT_TYPES.get(attack_type, {}).get("color", "#ffff00"),
        "description": f"Real attack captured by {event.honeypot_type} honeypot",
        "origin": {
            "city": origin_geo.get("city", "Unknown"),
            "country": origin_geo.get("country", "Unknown"),
            "lat": origin_geo.get("lat", 0),
            "lng": origin_geo.get("lng", 0),
            "ip": event.attacker_ip,
            "isp": origin_geo.get("isp", "Unknown"),
        },
        "target": {
            "city": "Local",
            "country": "Local",
            "lat": 0,
            "lng": 0,
            "ip": "honeypot",
            "port": event.target_port,
        },
        "severity": "high",
        "source": "honeypot",
        "honeypot_type": event.honeypot_type,
        "payload": event.payload[:100] if event.payload else None,
        "real_threat": True,
        "is_honeypot": True,
    }

    # Process as regular attack
    await process_attack(attack)


async def process_attack(attack):
    """Process and broadcast an attack"""
    global stats, attack_history

    # Update stats
    stats["total_attacks"] += 1
    stats["attacks_by_type"][attack["type"]] = stats["attacks_by_type"].get(attack["type"], 0) + 1

    origin = attack["origin"]["city"]
    target = attack["target"]["city"]
    stats["attacks_by_origin"][origin] = stats["attacks_by_origin"].get(origin, 0) + 1
    stats["attacks_by_target"][target] = stats["attacks_by_target"].get(target, 0) + 1

    # Save to database
    try:
        save_attack(attack)
    except Exception as e:
        print(f"DB save error: {e}")

    # Check alerts
    triggered_alerts = await alert_manager.check_attack(attack)

    # Add to history
    attack_history.append(attack)
    if len(attack_history) > 1000:
        attack_history = attack_history[-500:]

    # Broadcast to clients
    await broadcast_attack(attack, triggered_alerts)


# ============================================================================
# WEBSOCKET HANDLERS
# ============================================================================

async def websocket_handler(request):
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
        "alert_rules": alert_manager.get_rules(),
        "db_stats": get_stats_summary(),
    })

    try:
        async for msg in ws:
            if msg.type == aiohttp.WSMsgType.TEXT:
                data = json.loads(msg.data)
                await handle_ws_message(ws, data)
            elif msg.type == aiohttp.WSMsgType.ERROR:
                print(f"WebSocket error: {ws.exception()}")
    finally:
        connected_clients.discard(ws)
        print(f"Client disconnected. Total: {len(connected_clients)}")

    return ws


async def handle_ws_message(ws, data):
    """Handle WebSocket messages from clients"""
    action = data.get("action")

    if action == "ping":
        await ws.send_json({"type": "pong"})

    elif action == "get_stats":
        await ws.send_json({
            "type": "stats_update",
            "stats": stats,
            "feeds_status": threat_intel.feed_stats,
            "db_stats": get_stats_summary(),
        })

    elif action == "get_time_series":
        hours = data.get("hours", 24)
        series = get_time_series(hours=hours)
        await ws.send_json({"type": "time_series", "data": series})

    elif action == "get_top_attackers":
        limit = data.get("limit", 10)
        attackers = get_top_attackers(limit=limit)
        await ws.send_json({"type": "top_attackers", "data": attackers})

    elif action == "search_attacks":
        filters = data.get("filters", {})
        limit = data.get("limit", 100)
        attacks = get_attacks(limit=limit, filters=filters)
        await ws.send_json({"type": "search_results", "data": attacks})

    elif action == "get_ip_info":
        ip = data.get("ip")
        if ip:
            enrichment = await ip_enricher.enrich(ip)
            await ws.send_json({
                "type": "ip_info",
                "data": ip_enricher.get_enrichment_summary(enrichment)
            })

    elif action == "enable_alert":
        rule_id = data.get("rule_id")
        enabled = data.get("enabled", True)
        alert_manager.enable_rule(rule_id, enabled)
        await ws.send_json({"type": "alert_rules", "data": alert_manager.get_rules()})


async def broadcast_attack(attack, alerts=None):
    """Broadcast attack to all connected clients"""
    if not connected_clients:
        return

    message = {
        "type": "attack",
        "data": attack
    }

    if alerts:
        message["alerts"] = [
            {"rule_name": a.rule_name, "message": a.message, "severity": a.severity}
            for a in alerts
        ]

    message_str = json.dumps(message)

    disconnected = set()
    for ws in connected_clients:
        try:
            await ws.send_str(message_str)
        except Exception:
            disconnected.add(ws)

    connected_clients.difference_update(disconnected)


async def broadcast_alert(alert: Alert):
    """Broadcast alert to all clients"""
    message = json.dumps({
        "type": "alert",
        "data": {
            "rule_name": alert.rule_name,
            "message": alert.message,
            "severity": alert.severity,
            "timestamp": alert.timestamp
        }
    })

    for ws in connected_clients:
        try:
            await ws.send_str(message)
        except:
            pass


# ============================================================================
# REST API HANDLERS
# ============================================================================

async def index_handler(request):
    html_path = Path(__file__).parent / "templates" / "index_enhanced.html"
    if not html_path.exists():
        html_path = Path(__file__).parent / "templates" / "index.html"
    return web.FileResponse(html_path)


async def stats_handler(request):
    return web.json_response({
        **stats,
        "feeds_status": threat_intel.feed_stats,
        "geo_cache_size": len(threat_intel.geo_cache),
        "db_stats": get_stats_summary(),
    })


async def feeds_handler(request):
    return web.json_response({
        "feeds": threat_intel.feed_stats,
        "total_threat_ips": threat_intel.get_threat_count(),
    })


async def attacks_handler(request):
    limit = int(request.query.get("limit", 100))
    offset = int(request.query.get("offset", 0))

    filters = {}
    if request.query.get("type"):
        filters["attack_type"] = request.query.get("type")
    if request.query.get("severity"):
        filters["severity"] = request.query.get("severity")
    if request.query.get("country"):
        filters["origin_country"] = request.query.get("country")
    if request.query.get("ip"):
        filters["origin_ip"] = request.query.get("ip")

    attacks = get_attacks(limit=limit, offset=offset, filters=filters if filters else None)
    return web.json_response(attacks)


async def time_series_handler(request):
    hours = int(request.query.get("hours", 24))
    attack_type = request.query.get("type")
    data = get_time_series(hours=hours, attack_type=attack_type)
    return web.json_response(data)


async def top_attackers_handler(request):
    limit = int(request.query.get("limit", 10))
    data = get_top_attackers(limit=limit)
    return web.json_response(data)


async def top_countries_handler(request):
    limit = int(request.query.get("limit", 10))
    data = get_top_countries(limit=limit)
    return web.json_response(data)


async def blocklist_handler(request):
    format = request.query.get("format", "json")
    data = get_blocklist(format=format)

    if format == "json":
        return web.json_response(data)
    else:
        return web.Response(text=data, content_type="text/plain")


async def ip_lookup_handler(request):
    ip = request.match_info.get("ip")
    if not ip:
        return web.json_response({"error": "IP required"}, status=400)

    enrichment = await ip_enricher.enrich(ip)
    return web.json_response(ip_enricher.get_enrichment_summary(enrichment))


async def threat_actors_handler(request):
    actors = get_threat_actors()
    return web.json_response(actors)


async def alerts_handler(request):
    return web.json_response({
        "rules": alert_manager.get_rules(),
        "history": alert_manager.get_alert_history(limit=100)
    })


async def honeypot_stats_handler(request):
    if honeypot_manager:
        return web.json_response(honeypot_manager.get_stats())
    return web.json_response({"enabled": False})


# ============================================================================
# BACKGROUND TASKS
# ============================================================================

async def feed_updater(app):
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
            await asyncio.sleep(60)
    finally:
        await session.close()


async def attack_generator(app):
    global stats, attack_history

    await asyncio.sleep(5)

    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    connector = aiohttp.TCPConnector(ssl=ssl_context)
    session = aiohttp.ClientSession(connector=connector)
    app['attack_session'] = session

    try:
        while True:
            if threat_intel.get_threat_count() > 0:
                num_attacks = random.randint(1, 3)
                for _ in range(num_attacks):
                    attack = await generate_attack_from_real_data(session)
                    if attack:
                        await process_attack(attack)

            await asyncio.sleep(random.uniform(0.5, 2.0))
    finally:
        await session.close()


async def start_honeypots(app):
    global honeypot_manager

    honeypot_manager = HoneypotManager(callback=process_honeypot_event)
    alert_manager.add_callback(broadcast_alert)

    # Load Tor exit nodes for enrichment
    await ip_enricher.load_tor_exit_nodes()

    # Start honeypots (use high ports to avoid permission issues)
    tasks = await honeypot_manager.start_all(
        ssh_port=2222,
        http_port=8080,
        telnet_port=2323
    )

    app['honeypot_tasks'] = tasks


async def start_background_tasks(app):
    app['feed_updater'] = asyncio.create_task(feed_updater(app))
    app['attack_generator'] = asyncio.create_task(attack_generator(app))
    asyncio.create_task(start_honeypots(app))


async def cleanup_background_tasks(app):
    app['feed_updater'].cancel()
    app['attack_generator'].cancel()

    if honeypot_manager:
        await honeypot_manager.stop_all()

    await ip_enricher.close()
    await alert_manager.close()

    for task_name in ['feed_updater', 'attack_generator']:
        try:
            await app[task_name]
        except asyncio.CancelledError:
            pass

    for session_name in ['feed_session', 'attack_session']:
        if session_name in app:
            await app[session_name].close()


# ============================================================================
# APP FACTORY
# ============================================================================

def create_app():
    app = web.Application()

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

    # API routes
    app.router.add_get("/api/stats", stats_handler)
    app.router.add_get("/api/feeds", feeds_handler)
    app.router.add_get("/api/attacks", attacks_handler)
    app.router.add_get("/api/time-series", time_series_handler)
    app.router.add_get("/api/top-attackers", top_attackers_handler)
    app.router.add_get("/api/top-countries", top_countries_handler)
    app.router.add_get("/api/blocklist", blocklist_handler)
    app.router.add_get("/api/ip/{ip}", ip_lookup_handler)
    app.router.add_get("/api/threat-actors", threat_actors_handler)
    app.router.add_get("/api/alerts", alerts_handler)
    app.router.add_get("/api/honeypot", honeypot_stats_handler)

    app.router.add_static("/static", Path(__file__).parent / "static")

    for route in list(app.router.routes()):
        cors.add(route)

    app.on_startup.append(start_background_tasks)
    app.on_cleanup.append(cleanup_background_tasks)

    return app


if __name__ == "__main__":
    print("=" * 60)
    print("  ENHANCED THREAT MAP - Full Feature Set")
    print("=" * 60)
    print("\nFeatures enabled:")
    print("  - Real-time threat intelligence feeds")
    print("  - SQLite database persistence")
    print("  - Honeypot integration (SSH/HTTP/Telnet)")
    print("  - Alert system with notifications")
    print("  - IP enrichment (GeoIP, ASN, rDNS)")
    print("  - Blocklist export")
    print("  - Time-series analytics")
    print("  - REST API")
    print("\nStarting server on http://localhost:8888")
    print("=" * 60)

    app = create_app()
    web.run_app(app, host="0.0.0.0", port=8888)
