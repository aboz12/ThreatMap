"""
Custom Threat Feed Management for Threat Map
Import and manage custom IOC lists, MISP feeds, OTX, etc.
"""

import asyncio
import aiohttp
import json
import csv
import io
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Set
from dataclasses import dataclass, field


@dataclass
class CustomFeed:
    """Custom threat feed configuration"""
    id: str
    name: str
    feed_type: str  # url, file, misp, otx
    enabled: bool = True
    url: str = ""
    format: str = "plain"  # plain, csv, json, stix
    update_interval_hours: int = 24

    # For CSV format
    ip_column: int = 0
    type_column: Optional[int] = None
    has_header: bool = True

    # Authentication
    api_key: str = ""
    auth_header: str = ""

    # Stats
    last_update: Optional[str] = None
    ioc_count: int = 0
    last_error: Optional[str] = None


@dataclass
class IOC:
    """Indicator of Compromise"""
    value: str
    ioc_type: str  # ip, domain, hash, url
    feed_id: str
    threat_type: str = "Unknown"
    confidence: int = 50
    first_seen: str = ""
    last_seen: str = ""
    tags: List[str] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)


class CustomFeedManager:
    """Manages custom threat feeds"""

    def __init__(self):
        self.feeds: Dict[str, CustomFeed] = {}
        self.iocs: Dict[str, IOC] = {}  # value -> IOC
        self.ip_set: Set[str] = set()
        self.domain_set: Set[str] = set()
        self.hash_set: Set[str] = set()
        self.session: Optional[aiohttp.ClientSession] = None

        # Initialize with some example feeds
        self._init_default_feeds()

    def _init_default_feeds(self):
        """Initialize default custom feeds"""
        # Example: Abuse.ch Feodo Tracker
        self.add_feed(CustomFeed(
            id="feodo_custom",
            name="Feodo Tracker (Custom)",
            feed_type="url",
            enabled=False,  # Disabled by default
            url="https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
            format="plain",
            update_interval_hours=1
        ))

        # Example: FireHOL Level 1
        self.add_feed(CustomFeed(
            id="firehol_l1",
            name="FireHOL Level 1",
            feed_type="url",
            enabled=False,
            url="https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
            format="plain",
            update_interval_hours=6
        ))

    async def init_session(self):
        """Initialize HTTP session"""
        if not self.session:
            self.session = aiohttp.ClientSession()

    async def close(self):
        """Close HTTP session"""
        if self.session:
            await self.session.close()

    def add_feed(self, feed: CustomFeed) -> str:
        """Add a custom feed"""
        self.feeds[feed.id] = feed
        return feed.id

    def remove_feed(self, feed_id: str) -> bool:
        """Remove a feed and its IOCs"""
        if feed_id not in self.feeds:
            return False

        # Remove IOCs from this feed
        self.iocs = {k: v for k, v in self.iocs.items() if v.feed_id != feed_id}
        self._rebuild_sets()

        del self.feeds[feed_id]
        return True

    def enable_feed(self, feed_id: str, enabled: bool = True) -> bool:
        """Enable or disable a feed"""
        if feed_id in self.feeds:
            self.feeds[feed_id].enabled = enabled
            return True
        return False

    async def update_feed(self, feed_id: str) -> dict:
        """Update a single feed"""
        if feed_id not in self.feeds:
            return {"success": False, "error": "Feed not found"}

        feed = self.feeds[feed_id]

        try:
            await self.init_session()

            if feed.feed_type == "url":
                iocs = await self._fetch_url_feed(feed)
            elif feed.feed_type == "misp":
                iocs = await self._fetch_misp_feed(feed)
            elif feed.feed_type == "otx":
                iocs = await self._fetch_otx_feed(feed)
            else:
                return {"success": False, "error": f"Unknown feed type: {feed.feed_type}"}

            # Remove old IOCs from this feed
            self.iocs = {k: v for k, v in self.iocs.items() if v.feed_id != feed_id}

            # Add new IOCs
            for ioc in iocs:
                self.iocs[ioc.value] = ioc

            self._rebuild_sets()

            feed.last_update = datetime.utcnow().isoformat() + "Z"
            feed.ioc_count = len(iocs)
            feed.last_error = None

            return {
                "success": True,
                "feed_id": feed_id,
                "ioc_count": len(iocs)
            }

        except Exception as e:
            feed.last_error = str(e)
            return {"success": False, "error": str(e)}

    async def update_all_feeds(self) -> Dict[str, dict]:
        """Update all enabled feeds"""
        results = {}

        for feed_id, feed in self.feeds.items():
            if feed.enabled:
                results[feed_id] = await self.update_feed(feed_id)

        return results

    async def _fetch_url_feed(self, feed: CustomFeed) -> List[IOC]:
        """Fetch IOCs from URL feed"""
        headers = {}
        if feed.api_key and feed.auth_header:
            headers[feed.auth_header] = feed.api_key

        async with self.session.get(feed.url, headers=headers, timeout=aiohttp.ClientTimeout(total=60)) as resp:
            if resp.status != 200:
                raise Exception(f"HTTP {resp.status}")

            content = await resp.text()

        if feed.format == "plain":
            return self._parse_plain(content, feed)
        elif feed.format == "csv":
            return self._parse_csv(content, feed)
        elif feed.format == "json":
            return self._parse_json(content, feed)
        elif feed.format == "stix":
            return self._parse_stix(content, feed)

        return []

    def _parse_plain(self, content: str, feed: CustomFeed) -> List[IOC]:
        """Parse plain text IOC list (one per line)"""
        iocs = []
        now = datetime.utcnow().isoformat() + "Z"

        for line in content.split("\n"):
            line = line.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue

            # Detect IOC type
            ioc_type = self._detect_ioc_type(line)

            iocs.append(IOC(
                value=line,
                ioc_type=ioc_type,
                feed_id=feed.id,
                threat_type="Malicious",
                confidence=70,
                first_seen=now,
                last_seen=now
            ))

        return iocs

    def _parse_csv(self, content: str, feed: CustomFeed) -> List[IOC]:
        """Parse CSV IOC list"""
        iocs = []
        now = datetime.utcnow().isoformat() + "Z"

        reader = csv.reader(io.StringIO(content))

        if feed.has_header:
            next(reader, None)

        for row in reader:
            if not row or len(row) <= feed.ip_column:
                continue

            value = row[feed.ip_column].strip()
            if not value:
                continue

            threat_type = "Malicious"
            if feed.type_column is not None and len(row) > feed.type_column:
                threat_type = row[feed.type_column].strip()

            ioc_type = self._detect_ioc_type(value)

            iocs.append(IOC(
                value=value,
                ioc_type=ioc_type,
                feed_id=feed.id,
                threat_type=threat_type,
                confidence=70,
                first_seen=now,
                last_seen=now
            ))

        return iocs

    def _parse_json(self, content: str, feed: CustomFeed) -> List[IOC]:
        """Parse JSON IOC list"""
        iocs = []
        now = datetime.utcnow().isoformat() + "Z"

        data = json.loads(content)

        # Handle different JSON structures
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            items = data.get("iocs", data.get("indicators", data.get("data", [])))
        else:
            return []

        for item in items:
            if isinstance(item, str):
                value = item
                ioc_type = self._detect_ioc_type(value)
                threat_type = "Malicious"
            elif isinstance(item, dict):
                value = item.get("ip", item.get("indicator", item.get("value", "")))
                ioc_type = item.get("type", self._detect_ioc_type(value))
                threat_type = item.get("threat_type", item.get("category", "Malicious"))
            else:
                continue

            if value:
                iocs.append(IOC(
                    value=value,
                    ioc_type=ioc_type,
                    feed_id=feed.id,
                    threat_type=threat_type,
                    confidence=70,
                    first_seen=now,
                    last_seen=now
                ))

        return iocs

    def _parse_stix(self, content: str, feed: CustomFeed) -> List[IOC]:
        """Parse STIX 2.1 bundle"""
        iocs = []
        now = datetime.utcnow().isoformat() + "Z"

        try:
            bundle = json.loads(content)
            objects = bundle.get("objects", [])

            for obj in objects:
                if obj.get("type") == "indicator":
                    pattern = obj.get("pattern", "")
                    # Simple pattern extraction
                    if "ipv4-addr:value" in pattern:
                        import re
                        match = re.search(r"'([0-9.]+)'", pattern)
                        if match:
                            iocs.append(IOC(
                                value=match.group(1),
                                ioc_type="ip",
                                feed_id=feed.id,
                                threat_type=obj.get("name", "Malicious"),
                                confidence=70,
                                first_seen=obj.get("created", now),
                                last_seen=obj.get("modified", now),
                                tags=obj.get("labels", [])
                            ))
        except:
            pass

        return iocs

    async def _fetch_misp_feed(self, feed: CustomFeed) -> List[IOC]:
        """Fetch from MISP instance"""
        headers = {
            "Authorization": feed.api_key,
            "Accept": "application/json",
            "Content-Type": "application/json"
        }

        # Get recent events
        url = f"{feed.url}/attributes/restSearch"
        payload = {
            "returnFormat": "json",
            "type": ["ip-src", "ip-dst", "domain", "md5", "sha256"],
            "last": "7d"
        }

        async with self.session.post(url, headers=headers, json=payload, timeout=aiohttp.ClientTimeout(total=60)) as resp:
            if resp.status != 200:
                raise Exception(f"MISP error: {resp.status}")

            data = await resp.json()

        iocs = []
        now = datetime.utcnow().isoformat() + "Z"

        for attr in data.get("response", {}).get("Attribute", []):
            ioc_type = "ip" if attr.get("type", "").startswith("ip") else attr.get("type", "unknown")

            iocs.append(IOC(
                value=attr.get("value", ""),
                ioc_type=ioc_type,
                feed_id=feed.id,
                threat_type=attr.get("category", "Malicious"),
                confidence=int(attr.get("confidence", 70)),
                first_seen=attr.get("timestamp", now),
                last_seen=now,
                tags=attr.get("Tag", []),
                metadata={"event_id": attr.get("event_id")}
            ))

        return iocs

    async def _fetch_otx_feed(self, feed: CustomFeed) -> List[IOC]:
        """Fetch from AlienVault OTX"""
        headers = {"X-OTX-API-KEY": feed.api_key}

        # Get subscribed pulses
        url = f"{feed.url}/api/v1/pulses/subscribed"

        async with self.session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=60)) as resp:
            if resp.status != 200:
                raise Exception(f"OTX error: {resp.status}")

            data = await resp.json()

        iocs = []
        now = datetime.utcnow().isoformat() + "Z"

        for pulse in data.get("results", []):
            for indicator in pulse.get("indicators", []):
                ioc_type_map = {
                    "IPv4": "ip",
                    "domain": "domain",
                    "FileHash-MD5": "hash",
                    "FileHash-SHA256": "hash",
                    "URL": "url"
                }

                ioc_type = ioc_type_map.get(indicator.get("type"), "unknown")

                iocs.append(IOC(
                    value=indicator.get("indicator", ""),
                    ioc_type=ioc_type,
                    feed_id=feed.id,
                    threat_type=pulse.get("name", "Malicious"),
                    confidence=70,
                    first_seen=indicator.get("created", now),
                    last_seen=now,
                    tags=pulse.get("tags", []),
                    metadata={"pulse_id": pulse.get("id")}
                ))

        return iocs

    def _detect_ioc_type(self, value: str) -> str:
        """Detect IOC type from value"""
        import re

        # IP address
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', value):
            return "ip"

        # CIDR
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$', value):
            return "cidr"

        # Domain
        if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$', value):
            return "domain"

        # MD5
        if re.match(r'^[a-fA-F0-9]{32}$', value):
            return "hash"

        # SHA256
        if re.match(r'^[a-fA-F0-9]{64}$', value):
            return "hash"

        # URL
        if value.startswith(("http://", "https://")):
            return "url"

        return "unknown"

    def _rebuild_sets(self):
        """Rebuild lookup sets from IOCs"""
        self.ip_set = set()
        self.domain_set = set()
        self.hash_set = set()

        for ioc in self.iocs.values():
            if ioc.ioc_type == "ip":
                self.ip_set.add(ioc.value)
            elif ioc.ioc_type == "domain":
                self.domain_set.add(ioc.value)
            elif ioc.ioc_type == "hash":
                self.hash_set.add(ioc.value)

    def check_ip(self, ip: str) -> Optional[IOC]:
        """Check if IP is in any feed"""
        return self.iocs.get(ip)

    def check_domain(self, domain: str) -> Optional[IOC]:
        """Check if domain is in any feed"""
        return self.iocs.get(domain)

    def add_manual_ioc(self, value: str, ioc_type: str = None, threat_type: str = "Manual", tags: List[str] = None) -> IOC:
        """Manually add an IOC"""
        if ioc_type is None:
            ioc_type = self._detect_ioc_type(value)

        now = datetime.utcnow().isoformat() + "Z"

        ioc = IOC(
            value=value,
            ioc_type=ioc_type,
            feed_id="manual",
            threat_type=threat_type,
            confidence=100,
            first_seen=now,
            last_seen=now,
            tags=tags or []
        )

        self.iocs[value] = ioc
        self._rebuild_sets()

        return ioc

    def remove_ioc(self, value: str) -> bool:
        """Remove an IOC"""
        if value in self.iocs:
            del self.iocs[value]
            self._rebuild_sets()
            return True
        return False

    def get_feeds(self) -> List[dict]:
        """Get all feeds"""
        return [
            {
                "id": f.id,
                "name": f.name,
                "feed_type": f.feed_type,
                "enabled": f.enabled,
                "url": f.url[:50] + "..." if len(f.url) > 50 else f.url,
                "format": f.format,
                "update_interval_hours": f.update_interval_hours,
                "last_update": f.last_update,
                "ioc_count": f.ioc_count,
                "last_error": f.last_error
            }
            for f in self.feeds.values()
        ]

    def get_iocs(self, feed_id: str = None, ioc_type: str = None, limit: int = 1000) -> List[dict]:
        """Get IOCs with optional filtering"""
        results = []

        for ioc in self.iocs.values():
            if feed_id and ioc.feed_id != feed_id:
                continue
            if ioc_type and ioc.ioc_type != ioc_type:
                continue

            results.append({
                "value": ioc.value,
                "ioc_type": ioc.ioc_type,
                "feed_id": ioc.feed_id,
                "threat_type": ioc.threat_type,
                "confidence": ioc.confidence,
                "first_seen": ioc.first_seen,
                "tags": ioc.tags
            })

            if len(results) >= limit:
                break

        return results

    def get_statistics(self) -> dict:
        """Get custom feeds statistics"""
        return {
            "total_feeds": len(self.feeds),
            "enabled_feeds": len([f for f in self.feeds.values() if f.enabled]),
            "total_iocs": len(self.iocs),
            "iocs_by_type": {
                "ip": len(self.ip_set),
                "domain": len(self.domain_set),
                "hash": len(self.hash_set)
            },
            "iocs_by_feed": {
                f.name: f.ioc_count for f in self.feeds.values()
            }
        }
