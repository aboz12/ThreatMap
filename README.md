# ThreatMap

Real-time Internet threat visualization with 3D globe, threat intelligence feeds, honeypots, and alerting.

![Python](https://img.shields.io/badge/Python-3.9+-blue)
![License](https://img.shields.io/badge/License-MIT-green)

## Features

- **Real-time Visualization** - 3D globe (globe.gl) and 2D map (Leaflet) showing live attacks
- **Threat Intelligence Feeds** - Aggregates data from 6 public feeds (35,000+ threat IPs)
- **Honeypots** - SSH, HTTP, and Telnet honeypots capture real attacks
- **Alert System** - Configurable rules with webhooks, Slack/Discord support
- **IP Enrichment** - ASN lookup, reverse DNS, Tor/VPN/datacenter detection
- **Blocklist Export** - Export in JSON, plain text, iptables, pf, or nginx format
- **Threat Actor Profiles** - Known APT groups and botnets
- **REST API** - Full API for integration
- **Database Persistence** - SQLite storage for attacks, reputation, and analytics

## Quick Start

### Local

```bash
# Install dependencies
pip install -r requirements.txt

# Run the enhanced version
python app_enhanced.py

# Open browser
open http://localhost:8888
```

### Docker

```bash
docker-compose up -d
```

## Threat Intelligence Feeds

| Feed | Type | IPs |
|------|------|-----|
| URLhaus | Malware URLs | ~18,000 |
| CINS Score | Scanners | ~15,000 |
| Spamhaus DROP | Spam | ~1,400 |
| Emerging Threats | Various | ~500 |
| Feodo Tracker | Botnet C&C | ~5 |
| SSLBL | SSL Blacklist | Variable |

## Honeypots

| Service | Default Port | Captures |
|---------|--------------|----------|
| SSH | 2222 | Brute force attempts |
| HTTP | 8080 | SQL injection, XSS, path traversal |
| Telnet | 2323 | IoT botnet credentials |

## API Endpoints

```
GET /api/stats           - Attack statistics
GET /api/attacks         - Recent attacks with filtering
GET /api/time-series     - Time-series data for charts
GET /api/blocklist       - Export blocklist (?format=json|plain|iptables|pf|nginx)
GET /api/ip/{ip}         - IP enrichment lookup
GET /api/alerts          - Alert rules and history
GET /api/honeypot        - Honeypot statistics
GET /api/threat-actors   - Known threat actor profiles
GET /api/top-attackers   - Top attacking IPs
GET /api/top-countries   - Top attacking countries
```

## WebSocket

Connect to `/ws` for real-time attack stream:

```javascript
const ws = new WebSocket('ws://localhost:8888/ws');
ws.onmessage = (event) => {
  const attack = JSON.parse(event.data);
  console.log('Attack:', attack);
};
```

## Alert Rules

Default rules:
- Critical severity attacks
- Ransomware detected
- APT attacks
- High attack rate (100+/minute)
- Honeypot captures

## Configuration

Environment variables:
- `ABUSEIPDB_API_KEY` - Optional AbuseIPDB API key for enhanced reputation

## Project Structure

```
ThreatMap/
├── app.py                 # Basic threat map
├── app_enhanced.py        # Full-featured version
├── database.py            # SQLite persistence
├── honeypot.py            # SSH/HTTP/Telnet honeypots
├── alerts.py              # Alert system
├── enrichment.py          # IP enrichment
├── templates/
│   ├── index.html         # Basic UI
│   └── index_enhanced.html # Enhanced UI
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

## License

MIT
