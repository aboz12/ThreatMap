"""
IP Enrichment Module for Threat Map
Provides WHOIS, ASN, reverse DNS, and reputation data
"""

import asyncio
import aiohttp
import socket
import json
from datetime import datetime, timedelta
from typing import Dict, Optional
from dataclasses import dataclass


@dataclass
class IPEnrichment:
    """Enriched IP information"""
    ip: str
    city: str = "Unknown"
    country: str = "Unknown"
    lat: float = 0.0
    lng: float = 0.0
    isp: str = "Unknown"
    org: str = "Unknown"
    asn: str = None
    asn_name: str = None
    reverse_dns: str = None
    abuse_contact: str = None
    threat_score: int = 0
    is_tor: bool = False
    is_vpn: bool = False
    is_proxy: bool = False
    is_datacenter: bool = False
    tags: list = None


class IPEnricher:
    """Enriches IP addresses with additional context"""

    # Known datacenter/cloud ASN prefixes
    DATACENTER_ASNS = {
        "AS14618", "AS16509", "AS15169",  # AWS, Google
        "AS8075", "AS13335",  # Microsoft, Cloudflare
        "AS14061", "AS63949",  # DigitalOcean, Linode
        "AS20473", "AS46606",  # Vultr, Unified Layer
    }

    # Known VPN provider ASNs
    VPN_ASNS = {
        "AS9009", "AS60068", "AS62904",  # Various VPN providers
        "AS212238", "AS207960", "AS210644",
    }

    def __init__(self):
        self.cache: Dict[str, IPEnrichment] = {}
        self.cache_ttl = timedelta(hours=24)
        self.session: Optional[aiohttp.ClientSession] = None
        self.tor_exit_nodes = set()

    async def init_session(self):
        """Initialize HTTP session"""
        if not self.session:
            import ssl
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            connector = aiohttp.TCPConnector(ssl=ssl_context)
            self.session = aiohttp.ClientSession(connector=connector)

    async def close(self):
        """Close HTTP session"""
        if self.session:
            await self.session.close()

    async def enrich(self, ip: str, basic_geo: dict = None) -> IPEnrichment:
        """Enrich an IP address with additional data"""
        # Check cache
        if ip in self.cache:
            return self.cache[ip]

        await self.init_session()

        enrichment = IPEnrichment(ip=ip)

        # Start with basic geo if provided
        if basic_geo:
            enrichment.city = basic_geo.get("city", "Unknown")
            enrichment.country = basic_geo.get("country", "Unknown")
            enrichment.lat = basic_geo.get("lat", 0.0)
            enrichment.lng = basic_geo.get("lng", 0.0)
            enrichment.isp = basic_geo.get("isp", "Unknown")

        # Run enrichment tasks in parallel
        tasks = [
            self._get_asn_info(ip),
            self._get_reverse_dns(ip),
            self._check_reputation(ip),
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # ASN info
        if isinstance(results[0], dict):
            enrichment.asn = results[0].get("asn")
            enrichment.asn_name = results[0].get("asn_name")
            enrichment.org = results[0].get("org", enrichment.org)

            # Check if datacenter/VPN
            if enrichment.asn:
                if enrichment.asn in self.DATACENTER_ASNS:
                    enrichment.is_datacenter = True
                if enrichment.asn in self.VPN_ASNS:
                    enrichment.is_vpn = True

        # Reverse DNS
        if isinstance(results[1], str):
            enrichment.reverse_dns = results[1]

        # Reputation
        if isinstance(results[2], dict):
            enrichment.threat_score = results[2].get("score", 0)
            enrichment.is_tor = results[2].get("is_tor", False)
            enrichment.is_proxy = results[2].get("is_proxy", False)
            enrichment.tags = results[2].get("tags", [])

        # Cache result
        self.cache[ip] = enrichment

        return enrichment

    async def _get_asn_info(self, ip: str) -> dict:
        """Get ASN information for an IP"""
        try:
            # Use ip-api.com for ASN info
            url = f"http://ip-api.com/json/{ip}?fields=as,org,isp"
            async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    as_info = data.get("as", "")
                    # Parse AS number from "AS12345 Organization Name"
                    parts = as_info.split(" ", 1)
                    return {
                        "asn": parts[0] if parts else None,
                        "asn_name": parts[1] if len(parts) > 1 else None,
                        "org": data.get("org"),
                        "isp": data.get("isp")
                    }
        except Exception as e:
            pass
        return {}

    async def _get_reverse_dns(self, ip: str) -> Optional[str]:
        """Get reverse DNS for an IP"""
        try:
            loop = asyncio.get_event_loop()
            result = await asyncio.wait_for(
                loop.run_in_executor(None, socket.gethostbyaddr, ip),
                timeout=2
            )
            return result[0]
        except (socket.herror, socket.gaierror, asyncio.TimeoutError):
            pass
        return None

    async def _check_reputation(self, ip: str) -> dict:
        """Check IP reputation from various sources"""
        result = {
            "score": 0,
            "is_tor": False,
            "is_proxy": False,
            "tags": []
        }

        # Check against Tor exit nodes
        if ip in self.tor_exit_nodes:
            result["is_tor"] = True
            result["score"] += 50
            result["tags"].append("tor_exit")

        # Simple heuristics based on reverse DNS
        try:
            loop = asyncio.get_event_loop()
            hostname = await asyncio.wait_for(
                loop.run_in_executor(None, socket.gethostbyaddr, ip),
                timeout=2
            )
            hostname = hostname[0].lower()

            # Check for VPN/proxy indicators
            vpn_keywords = ["vpn", "proxy", "tor", "exit", "relay", "anon"]
            for keyword in vpn_keywords:
                if keyword in hostname:
                    result["is_proxy"] = True
                    result["score"] += 30
                    result["tags"].append("vpn_proxy")
                    break

            # Check for dynamic/residential
            dynamic_keywords = ["dynamic", "dhcp", "dsl", "cable", "pool"]
            for keyword in dynamic_keywords:
                if keyword in hostname:
                    result["tags"].append("dynamic")
                    break

        except (socket.herror, socket.gaierror, asyncio.TimeoutError):
            pass

        return result

    async def load_tor_exit_nodes(self):
        """Load Tor exit node list"""
        try:
            await self.init_session()
            url = "https://check.torproject.org/torbulkexitlist"
            async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                if resp.status == 200:
                    content = await resp.text()
                    self.tor_exit_nodes = set(
                        line.strip() for line in content.split("\n")
                        if line.strip() and not line.startswith("#")
                    )
                    print(f"[Enrichment] Loaded {len(self.tor_exit_nodes)} Tor exit nodes")
        except Exception as e:
            print(f"[Enrichment] Failed to load Tor exit nodes: {e}")

    def get_enrichment_summary(self, enrichment: IPEnrichment) -> dict:
        """Get a summary dict suitable for JSON"""
        return {
            "ip": enrichment.ip,
            "geo": {
                "city": enrichment.city,
                "country": enrichment.country,
                "lat": enrichment.lat,
                "lng": enrichment.lng
            },
            "network": {
                "isp": enrichment.isp,
                "org": enrichment.org,
                "asn": enrichment.asn,
                "asn_name": enrichment.asn_name,
                "reverse_dns": enrichment.reverse_dns
            },
            "reputation": {
                "threat_score": enrichment.threat_score,
                "is_tor": enrichment.is_tor,
                "is_vpn": enrichment.is_vpn,
                "is_proxy": enrichment.is_proxy,
                "is_datacenter": enrichment.is_datacenter,
                "tags": enrichment.tags or []
            }
        }


# WHOIS lookup (simplified)
async def whois_lookup(ip: str) -> dict:
    """Perform WHOIS lookup for an IP"""
    try:
        # Use RDAP (modern WHOIS replacement)
        async with aiohttp.ClientSession() as session:
            url = f"https://rdap.arin.net/registry/ip/{ip}"
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return {
                        "name": data.get("name"),
                        "handle": data.get("handle"),
                        "start_address": data.get("startAddress"),
                        "end_address": data.get("endAddress"),
                        "type": data.get("type"),
                        "country": data.get("country"),
                        "events": [
                            {"action": e.get("eventAction"), "date": e.get("eventDate")}
                            for e in data.get("events", [])
                        ],
                        "entities": [
                            {"role": ent.get("roles", []), "handle": ent.get("handle")}
                            for ent in data.get("entities", [])
                        ]
                    }
    except Exception as e:
        pass
    return {}


# AbuseIPDB lookup (requires API key)
async def abuseipdb_check(ip: str, api_key: str) -> dict:
    """Check IP against AbuseIPDB"""
    if not api_key:
        return {}

    try:
        async with aiohttp.ClientSession() as session:
            url = f"https://api.abuseipdb.com/api/v2/check"
            headers = {
                "Key": api_key,
                "Accept": "application/json"
            }
            params = {
                "ipAddress": ip,
                "maxAgeInDays": 90
            }
            async with session.get(url, headers=headers, params=params, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data.get("data", {})
    except Exception as e:
        pass
    return {}
