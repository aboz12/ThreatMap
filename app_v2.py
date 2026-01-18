"""
ThreatMap v2.0 - Full Feature Integration
All 12 advanced features integrated into one platform
"""

import asyncio
import aiohttp
from aiohttp import web
import json
import random
import ssl
from datetime import datetime, timedelta
from pathlib import Path

# Import all modules
from database import init_db, save_attack, get_attacks, get_time_series, get_blocklist, get_top_attackers, get_top_countries
from honeypot import HoneypotManager, HoneypotEvent
from alerts import AlertManager, Alert
from enrichment import IPEnricher
from ml_detection import AnomalyDetector, ThreatPredictor
from mitre_attack import MitreMapper
from geofencing import GeoFenceManager
from query_engine import QueryEngine
from siem_export import SIEMExporter
from auth import AuthManager
from simulator import AttackSimulator, HistoricalPlayback, SCENARIOS
from custom_feeds import CustomFeedManager
from reports import ReportGenerator
from multi_sensor import SensorManager, SensorCorrelator

# ============================================================
# Configuration
# ============================================================

HOST = "0.0.0.0"
PORT = 8888

# Threat feeds
THREAT_FEEDS = {
    "urlhaus": "https://urlhaus.abuse.ch/downloads/text_online/",
    "feodo_full": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "sslbl": "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
    "emergingthreats": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    "cinsscore": "https://cinsscore.com/list/ci-badguys.txt",
    "spamhaus_drop": "https://www.spamhaus.org/drop/drop.txt",
}

# GeoIP API
GEOIP_API = "http://ip-api.com/json/{ip}?fields=status,country,city,lat,lon,isp"

# ============================================================
# Global State
# ============================================================

app = web.Application()
websocket_clients = set()
threat_ips = {}
attack_history = []

# Initialize all managers
alert_manager = AlertManager()
enricher = IPEnricher()
anomaly_detector = AnomalyDetector()
threat_predictor = ThreatPredictor()
mitre_mapper = MitreMapper()
geofence_manager = GeoFenceManager()
query_engine = QueryEngine()
siem_exporter = SIEMExporter()
auth_manager = AuthManager()
simulator = AttackSimulator()
playback = HistoricalPlayback()
custom_feeds = CustomFeedManager()
report_generator = ReportGenerator()
sensor_manager = SensorManager()
sensor_correlator = SensorCorrelator()
honeypot_manager = None

# ============================================================
# Handlers
# ============================================================

async def index_handler(request):
    """Serve main page"""
    template_path = Path(__file__).parent / "templates" / "index_v2.html"
    if template_path.exists():
        return web.FileResponse(template_path)
    # Fallback to enhanced template
    template_path = Path(__file__).parent / "templates" / "index_enhanced.html"
    return web.FileResponse(template_path)


async def websocket_handler(request):
    """WebSocket handler for real-time updates"""
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    websocket_clients.add(ws)

    try:
        async for msg in ws:
            if msg.type == web.WSMsgType.TEXT:
                data = json.loads(msg.data)
                action = data.get("action")

                if action == "ping":
                    await ws.send_json({"action": "pong"})

                elif action == "get_stats":
                    await ws.send_json({
                        "action": "stats",
                        "data": get_current_stats()
                    })

                elif action == "query":
                    result = query_engine.execute(data.get("query", ""), attack_history)
                    await ws.send_json({"action": "query_result", "data": result})

                elif action == "start_simulation":
                    scenario = data.get("scenario", "demo")
                    await simulator.start_scenario(scenario)
                    await ws.send_json({"action": "simulation_started", "scenario": scenario})

                elif action == "stop_simulation":
                    await simulator.stop()
                    await ws.send_json({"action": "simulation_stopped"})

    except Exception as e:
        print(f"WebSocket error: {e}")
    finally:
        websocket_clients.discard(ws)

    return ws


def get_current_stats():
    """Get current statistics"""
    type_counts = {}
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    country_counts = {}

    for attack in attack_history[-1000:]:
        t = attack.get("type", "Unknown")
        type_counts[t] = type_counts.get(t, 0) + 1

        s = attack.get("severity", "medium")
        severity_counts[s] = severity_counts.get(s, 0) + 1

        c = attack.get("origin", {}).get("country", "Unknown")
        country_counts[c] = country_counts.get(c, 0) + 1

    return {
        "total_attacks": len(attack_history),
        "attacks_by_type": type_counts,
        "attacks_by_severity": severity_counts,
        "attacks_by_country": dict(sorted(country_counts.items(), key=lambda x: x[1], reverse=True)[:20]),
        "threat_ips_loaded": len(threat_ips),
        "anomalies_detected": len(anomaly_detector.anomalies),
        "active_alerts": len(alert_manager.alert_history)
    }


# ============================================================
# API Endpoints
# ============================================================

async def api_stats(request):
    return web.json_response(get_current_stats())


async def api_attacks(request):
    limit = int(request.query.get("limit", 100))
    offset = int(request.query.get("offset", 0))
    return web.json_response(attack_history[-(limit+offset):][-limit:])


async def api_time_series(request):
    return web.json_response(get_time_series())


async def api_blocklist(request):
    format = request.query.get("format", "json")
    return web.Response(
        text=get_blocklist(format),
        content_type="text/plain" if format != "json" else "application/json"
    )


async def api_ip_lookup(request):
    ip = request.match_info.get("ip")
    enrichment = await enricher.enrich(ip)
    return web.json_response(enricher.get_enrichment_summary(enrichment))


async def api_alerts(request):
    return web.json_response({
        "rules": alert_manager.get_rules(),
        "history": alert_manager.get_alert_history()
    })


async def api_honeypot(request):
    if honeypot_manager:
        return web.json_response(honeypot_manager.get_stats())
    return web.json_response({})


async def api_threat_actors(request):
    from database import get_threat_actors
    return web.json_response(get_threat_actors())


# New v2 API endpoints

async def api_anomalies(request):
    """Get detected anomalies"""
    return web.json_response({
        "anomalies": anomaly_detector.get_anomalies(),
        "statistics": anomaly_detector.get_statistics(),
        "campaigns": anomaly_detector.detect_campaigns()
    })


async def api_mitre(request):
    """Get MITRE ATT&CK mapping"""
    return web.json_response({
        "kill_chain": mitre_mapper.get_kill_chain_view(),
        "techniques": mitre_mapper.get_all_techniques(),
        "statistics": mitre_mapper.get_statistics()
    })


async def api_mitre_technique(request):
    """Get specific technique details"""
    technique_id = request.match_info.get("id")
    details = mitre_mapper.get_technique_details(technique_id)
    if details:
        return web.json_response(details)
    return web.json_response({"error": "Technique not found"}, status=404)


async def api_geofences(request):
    """Get geofences"""
    return web.json_response({
        "fences": geofence_manager.get_fences(),
        "blocked_countries": geofence_manager.get_blocked_countries(),
        "statistics": geofence_manager.get_statistics()
    })


async def api_query(request):
    """Execute threat hunting query"""
    data = await request.json()
    query = data.get("query", "")
    result = query_engine.execute(query, attack_history)
    return web.json_response(result)


async def api_saved_queries(request):
    """Get saved queries"""
    return web.json_response(query_engine.get_saved_queries())


async def api_simulations(request):
    """Get available simulations"""
    return web.json_response({
        "scenarios": simulator.get_scenarios(),
        "status": simulator.get_status()
    })


async def api_start_simulation(request):
    """Start a simulation"""
    data = await request.json()
    scenario = data.get("scenario", "demo")
    success = await simulator.start_scenario(scenario)
    return web.json_response({"success": success, "scenario": scenario})


async def api_stop_simulation(request):
    """Stop simulation"""
    await simulator.stop()
    return web.json_response({"success": True})


async def api_custom_feeds(request):
    """Get custom feeds"""
    return web.json_response({
        "feeds": custom_feeds.get_feeds(),
        "statistics": custom_feeds.get_statistics()
    })


async def api_generate_report(request):
    """Generate a report"""
    data = await request.json()
    format = data.get("format", "html")
    period = data.get("period", "Last 24 Hours")

    report = report_generator.generate_report(
        attacks=attack_history[-1000:],
        stats=get_current_stats(),
        format=format,
        period=period
    )

    if format == "html":
        return web.Response(text=report["content"], content_type="text/html")
    elif format == "csv":
        return web.Response(
            text=report["content"],
            content_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=threat_report.csv"}
        )
    else:
        return web.json_response(report)


async def api_sensors(request):
    """Get sensors"""
    return web.json_response({
        "sensors": sensor_manager.get_sensors(),
        "statistics": sensor_manager.get_aggregated_stats()
    })


async def api_predictions(request):
    """Get threat predictions"""
    return web.json_response(threat_predictor.predict_next_hour())


async def api_auth_login(request):
    """Login endpoint"""
    data = await request.json()
    session = auth_manager.login(
        data.get("username", ""),
        data.get("password", ""),
        request.remote
    )
    if session:
        return web.json_response({
            "success": True,
            "session_id": session.session_id,
            "role": session.role,
            "expires_at": session.expires_at
        })
    return web.json_response({"success": False, "error": "Invalid credentials"}, status=401)


async def api_auth_logout(request):
    """Logout endpoint"""
    session_id = request.headers.get("Authorization", "").replace("Bearer ", "")
    auth_manager.logout(session_id)
    return web.json_response({"success": True})


# ============================================================
# Background Tasks
# ============================================================

async def broadcast_attack(attack: dict):
    """Broadcast attack to all WebSocket clients"""
    message = json.dumps({"action": "attack", "data": attack})
    dead_clients = set()

    for ws in websocket_clients:
        try:
            await ws.send_str(message)
        except:
            dead_clients.add(ws)

    websocket_clients.difference_update(dead_clients)


async def process_attack(attack: dict):
    """Process an attack through all systems"""
    global attack_history

    # Save to history
    attack_history.append(attack)
    if len(attack_history) > 10000:
        attack_history = attack_history[-5000:]

    # Save to database
    try:
        save_attack(attack)
    except:
        pass

    # ML analysis
    anomaly = anomaly_detector.add_attack(attack)
    threat_predictor.add_attack(attack)

    # MITRE mapping
    mitre_mapping = mitre_mapper.map_attack(attack)
    attack["mitre"] = mitre_mapping

    # Geofencing check
    fence_event = geofence_manager.check_attack(attack)
    if fence_event:
        attack["geofence_triggered"] = fence_event["fence_name"]

    # Alert check
    alerts = await alert_manager.check_attack(attack)

    # Multi-sensor correlation
    sensor_correlator.add_attack(attack)

    # Broadcast
    await broadcast_attack(attack)

    # SIEM export
    await siem_exporter.export_attack(attack)


async def handle_honeypot_event(event: HoneypotEvent):
    """Handle honeypot capture"""
    attack = {
        "id": f"hp_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{random.randint(1000, 9999)}",
        "timestamp": event.timestamp,
        "type": getattr(event, "attack_type", "Scanner"),
        "severity": "high",
        "source": "honeypot",
        "honeypot_type": event.honeypot_type,
        "origin": {
            "ip": event.attacker_ip,
            "port": event.attacker_port,
            "city": "Unknown",
            "country": "Unknown",
            "lat": 0,
            "lng": 0
        },
        "target": {
            "ip": "honeypot",
            "port": event.target_port,
            "city": "Local",
            "country": "Local",
            "lat": 0,
            "lng": 0
        },
        "payload": event.payload[:200] if event.payload else None,
        "credentials": event.credentials
    }

    # Enrich with GeoIP
    try:
        geo = await get_geoip(event.attacker_ip)
        if geo:
            attack["origin"].update(geo)
    except:
        pass

    await process_attack(attack)


async def get_geoip(ip: str) -> dict:
    """Get GeoIP data"""
    if ip in app.get("geo_cache", {}):
        return app["geo_cache"][ip]

    try:
        async with app["attack_session"].get(
            GEOIP_API.format(ip=ip),
            timeout=aiohttp.ClientTimeout(total=5)
        ) as resp:
            if resp.status == 200:
                data = await resp.json()
                if data.get("status") == "success":
                    result = {
                        "city": data.get("city", "Unknown"),
                        "country": data.get("country", "Unknown"),
                        "lat": data.get("lat", 0),
                        "lng": data.get("lon", 0),
                        "isp": data.get("isp", "Unknown")
                    }
                    app.setdefault("geo_cache", {})[ip] = result
                    return result
    except:
        pass

    return None


async def feed_updater(app):
    """Update threat feeds periodically"""
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    connector = aiohttp.TCPConnector(ssl=ssl_context)
    session = aiohttp.ClientSession(connector=connector)
    app["feed_session"] = session

    while True:
        for feed_name, url in THREAT_FEEDS.items():
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=60)) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        count = 0
                        for line in content.split("\n"):
                            line = line.strip()
                            if line and not line.startswith("#") and not line.startswith(";"):
                                ip = line.split()[0].split("/")[0]
                                if ip and ip[0].isdigit():
                                    threat_ips[ip] = feed_name
                                    count += 1
                        print(f"[+] {feed_name}: loaded {count} threat IPs")
            except Exception as e:
                print(f"[-] {feed_name}: {e}")

        await asyncio.sleep(3600)  # Update hourly


async def attack_generator(app):
    """Generate attacks from threat IPs"""
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    connector = aiohttp.TCPConnector(ssl=ssl_context)
    session = aiohttp.ClientSession(connector=connector)
    app["attack_session"] = session

    # Wait for feeds to load
    await asyncio.sleep(10)

    targets = [
        {"city": "New York", "country": "United States", "lat": 40.7128, "lng": -74.0060},
        {"city": "London", "country": "United Kingdom", "lat": 51.5074, "lng": -0.1278},
        {"city": "Tokyo", "country": "Japan", "lat": 35.6762, "lng": 139.6503},
        {"city": "Frankfurt", "country": "Germany", "lat": 50.1109, "lng": 8.6821},
    ]

    feed_to_type = {
        "urlhaus": "Malware",
        "feodo_full": "Botnet",
        "sslbl": "Malware",
        "emergingthreats": "Scanner",
        "cinsscore": "Scanner",
        "spamhaus_drop": "Spam"
    }

    while True:
        if threat_ips and not simulator.running:
            ip, feed = random.choice(list(threat_ips.items()))

            geo = await get_geoip(ip)
            if not geo:
                geo = {"city": "Unknown", "country": "Unknown", "lat": random.uniform(-60, 70), "lng": random.uniform(-180, 180)}

            target = random.choice(targets)
            attack_type = feed_to_type.get(feed, "Scanner")
            severity = random.choices(["critical", "high", "medium", "low"], weights=[5, 15, 50, 30])[0]

            attack = {
                "id": f"feed_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{random.randint(1000, 9999)}",
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "type": attack_type,
                "severity": severity,
                "source": feed,
                "origin": {
                    "ip": ip,
                    "city": geo.get("city", "Unknown"),
                    "country": geo.get("country", "Unknown"),
                    "lat": geo.get("lat", 0),
                    "lng": geo.get("lng", 0),
                    "isp": geo.get("isp", "Unknown")
                },
                "target": {
                    "ip": f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
                    "city": target["city"],
                    "country": target["country"],
                    "lat": target["lat"],
                    "lng": target["lng"],
                    "port": random.choice([22, 80, 443, 3389, 445, 1433, 3306])
                }
            }

            await process_attack(attack)

        await asyncio.sleep(random.uniform(0.5, 3))


async def simulation_callback(attack: dict):
    """Handle simulated attacks"""
    await process_attack(attack)


# ============================================================
# Application Setup
# ============================================================

async def on_startup(app):
    """Initialize on startup"""
    print("=" * 60)
    print("  THREATMAP v2.0 - Full Feature Platform")
    print("=" * 60)
    print()
    print("Features enabled:")
    print("  - Real-time threat intelligence feeds")
    print("  - ML anomaly detection")
    print("  - MITRE ATT&CK mapping")
    print("  - Geofencing & country blocking")
    print("  - Threat hunting queries")
    print("  - SIEM integration")
    print("  - Attack simulation mode")
    print("  - Historical playback")
    print("  - Custom threat feeds")
    print("  - Multi-sensor support")
    print("  - User authentication")
    print("  - Report generation")
    print("  - Honeypot integration")
    print("  - PWA support")
    print()
    print(f"Starting server on http://localhost:{PORT}")
    print("=" * 60)

    # Initialize database
    init_db()

    # Load Tor exit nodes
    await enricher.load_tor_exit_nodes()

    # Set up simulator callback
    simulator.callback = simulation_callback

    # Start background tasks
    asyncio.create_task(feed_updater(app))
    asyncio.create_task(attack_generator(app))

    # Start honeypots
    global honeypot_manager
    honeypot_manager = HoneypotManager(callback=handle_honeypot_event)
    app["honeypot_tasks"] = await honeypot_manager.start_all(ssh_port=2222, http_port=8080, telnet_port=2323)


async def on_cleanup(app):
    """Cleanup on shutdown"""
    if "feed_session" in app:
        await app["feed_session"].close()
    if "attack_session" in app:
        await app["attack_session"].close()
    await enricher.close()
    await siem_exporter.close()
    await custom_feeds.close()
    await sensor_manager.close()
    if honeypot_manager:
        await honeypot_manager.stop_all()


def setup_routes(app):
    """Set up routes"""
    # Main
    app.router.add_get("/", index_handler)
    app.router.add_get("/ws", websocket_handler)

    # Static files
    static_path = Path(__file__).parent / "static"
    if static_path.exists():
        app.router.add_static("/static", static_path)

    # Original API
    app.router.add_get("/api/stats", api_stats)
    app.router.add_get("/api/attacks", api_attacks)
    app.router.add_get("/api/time-series", api_time_series)
    app.router.add_get("/api/blocklist", api_blocklist)
    app.router.add_get("/api/ip/{ip}", api_ip_lookup)
    app.router.add_get("/api/alerts", api_alerts)
    app.router.add_get("/api/honeypot", api_honeypot)
    app.router.add_get("/api/threat-actors", api_threat_actors)

    # v2 API
    app.router.add_get("/api/anomalies", api_anomalies)
    app.router.add_get("/api/mitre", api_mitre)
    app.router.add_get("/api/mitre/{id}", api_mitre_technique)
    app.router.add_get("/api/geofences", api_geofences)
    app.router.add_post("/api/query", api_query)
    app.router.add_get("/api/queries", api_saved_queries)
    app.router.add_get("/api/simulations", api_simulations)
    app.router.add_post("/api/simulations/start", api_start_simulation)
    app.router.add_post("/api/simulations/stop", api_stop_simulation)
    app.router.add_get("/api/feeds", api_custom_feeds)
    app.router.add_post("/api/reports", api_generate_report)
    app.router.add_get("/api/sensors", api_sensors)
    app.router.add_get("/api/predictions", api_predictions)
    app.router.add_post("/api/auth/login", api_auth_login)
    app.router.add_post("/api/auth/logout", api_auth_logout)


# ============================================================
# Main
# ============================================================

if __name__ == "__main__":
    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)
    setup_routes(app)
    web.run_app(app, host=HOST, port=PORT)
