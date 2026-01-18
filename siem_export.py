"""
SIEM Integration and Export for Threat Map
Supports Syslog (CEF/LEEF), Splunk, Elastic, STIX/TAXII
"""

import json
import socket
import asyncio
import aiohttp
from datetime import datetime
from typing import List, Dict, Optional, Any
from dataclasses import dataclass


@dataclass
class SIEMConfig:
    """SIEM export configuration"""
    id: str
    name: str
    siem_type: str  # syslog, splunk, elastic, stix
    enabled: bool = True

    # Syslog settings
    syslog_host: str = "localhost"
    syslog_port: int = 514
    syslog_protocol: str = "udp"  # udp, tcp
    syslog_format: str = "cef"  # cef, leef, json

    # Splunk HEC settings
    splunk_url: str = ""
    splunk_token: str = ""
    splunk_index: str = "main"
    splunk_source: str = "threatmap"

    # Elastic settings
    elastic_url: str = ""
    elastic_index: str = "threatmap"
    elastic_api_key: str = ""

    # Stats
    events_sent: int = 0
    last_sent: Optional[str] = None
    last_error: Optional[str] = None


class SIEMExporter:
    """Exports attack events to various SIEM systems"""

    def __init__(self):
        self.configs: Dict[str, SIEMConfig] = {}
        self.event_queue: List[dict] = []
        self.http_session: Optional[aiohttp.ClientSession] = None

    async def init_session(self):
        """Initialize HTTP session"""
        if not self.http_session:
            self.http_session = aiohttp.ClientSession()

    async def close(self):
        """Close HTTP session"""
        if self.http_session:
            await self.http_session.close()

    def add_config(self, config: SIEMConfig) -> str:
        """Add SIEM configuration"""
        self.configs[config.id] = config
        return config.id

    def remove_config(self, config_id: str) -> bool:
        """Remove SIEM configuration"""
        if config_id in self.configs:
            del self.configs[config_id]
            return True
        return False

    def enable_config(self, config_id: str, enabled: bool = True) -> bool:
        """Enable or disable SIEM config"""
        if config_id in self.configs:
            self.configs[config_id].enabled = enabled
            return True
        return False

    async def export_attack(self, attack: dict) -> Dict[str, bool]:
        """Export attack to all configured SIEMs"""
        results = {}

        for config_id, config in self.configs.items():
            if not config.enabled:
                continue

            try:
                if config.siem_type == "syslog":
                    await self._send_syslog(config, attack)
                elif config.siem_type == "splunk":
                    await self._send_splunk(config, attack)
                elif config.siem_type == "elastic":
                    await self._send_elastic(config, attack)

                config.events_sent += 1
                config.last_sent = datetime.utcnow().isoformat() + "Z"
                results[config_id] = True

            except Exception as e:
                config.last_error = str(e)
                results[config_id] = False

        return results

    async def _send_syslog(self, config: SIEMConfig, attack: dict):
        """Send attack to Syslog"""
        if config.syslog_format == "cef":
            message = self._format_cef(attack)
        elif config.syslog_format == "leef":
            message = self._format_leef(attack)
        else:
            message = json.dumps(attack)

        # Add syslog header
        priority = 14  # facility=1 (user), severity=6 (info)
        timestamp = datetime.utcnow().strftime("%b %d %H:%M:%S")
        hostname = "threatmap"
        syslog_msg = f"<{priority}>{timestamp} {hostname} {message}"

        if config.syslog_protocol == "udp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(syslog_msg.encode(), (config.syslog_host, config.syslog_port))
            sock.close()
        else:  # TCP
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((config.syslog_host, config.syslog_port))
            sock.send(syslog_msg.encode() + b"\n")
            sock.close()

    def _format_cef(self, attack: dict) -> str:
        """Format attack as CEF (Common Event Format)"""
        severity_map = {"critical": 10, "high": 7, "medium": 5, "low": 2}
        severity = severity_map.get(attack.get("severity", "medium"), 5)

        origin = attack.get("origin", {})
        target = attack.get("target", {})

        # CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
        cef = f"CEF:0|ThreatMap|ThreatMap|1.0|{attack.get('type', 'Unknown')}|"
        cef += f"{attack.get('type', 'Unknown')} Attack|{severity}|"

        # Extensions
        ext = []
        ext.append(f"src={origin.get('ip', 'unknown')}")
        ext.append(f"dst={target.get('ip', 'unknown')}")
        ext.append(f"spt={origin.get('port', 0)}")
        ext.append(f"dpt={target.get('port', 0)}")
        ext.append(f"cs1={origin.get('country', 'Unknown')}")
        ext.append(f"cs1Label=SourceCountry")
        ext.append(f"cs2={attack.get('source', 'feed')}")
        ext.append(f"cs2Label=DataSource")
        ext.append(f"rt={attack.get('timestamp', '')}")

        cef += " ".join(ext)
        return cef

    def _format_leef(self, attack: dict) -> str:
        """Format attack as LEEF (Log Event Extended Format)"""
        origin = attack.get("origin", {})
        target = attack.get("target", {})

        # LEEF:Version|Vendor|Product|Version|EventID|
        leef = f"LEEF:1.0|ThreatMap|ThreatMap|1.0|{attack.get('type', 'Unknown')}|"

        # Attributes (tab-separated)
        attrs = []
        attrs.append(f"src={origin.get('ip', 'unknown')}")
        attrs.append(f"dst={target.get('ip', 'unknown')}")
        attrs.append(f"srcPort={origin.get('port', 0)}")
        attrs.append(f"dstPort={target.get('port', 0)}")
        attrs.append(f"proto=TCP")
        attrs.append(f"sev={attack.get('severity', 'medium')}")
        attrs.append(f"cat={attack.get('type', 'Unknown')}")
        attrs.append(f"srcCountry={origin.get('country', 'Unknown')}")

        leef += "\t".join(attrs)
        return leef

    async def _send_splunk(self, config: SIEMConfig, attack: dict):
        """Send attack to Splunk HEC"""
        await self.init_session()

        url = f"{config.splunk_url}/services/collector/event"
        headers = {
            "Authorization": f"Splunk {config.splunk_token}",
            "Content-Type": "application/json"
        }

        payload = {
            "event": attack,
            "source": config.splunk_source,
            "sourcetype": "_json",
            "index": config.splunk_index,
            "time": datetime.utcnow().timestamp()
        }

        async with self.http_session.post(url, headers=headers, json=payload) as resp:
            if resp.status >= 400:
                raise Exception(f"Splunk HEC error: {resp.status}")

    async def _send_elastic(self, config: SIEMConfig, attack: dict):
        """Send attack to Elasticsearch"""
        await self.init_session()

        url = f"{config.elastic_url}/{config.elastic_index}/_doc"
        headers = {"Content-Type": "application/json"}

        if config.elastic_api_key:
            headers["Authorization"] = f"ApiKey {config.elastic_api_key}"

        # Add Elastic metadata
        doc = {
            "@timestamp": attack.get("timestamp", datetime.utcnow().isoformat() + "Z"),
            **attack
        }

        async with self.http_session.post(url, headers=headers, json=doc) as resp:
            if resp.status >= 400:
                raise Exception(f"Elastic error: {resp.status}")

    def generate_stix_bundle(self, attacks: List[dict]) -> dict:
        """Generate STIX 2.1 bundle from attacks"""
        objects = []

        for attack in attacks:
            origin = attack.get("origin", {})

            # Create indicator
            indicator = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{attack.get('id', 'unknown')}",
                "created": attack.get("timestamp", datetime.utcnow().isoformat() + "Z"),
                "modified": attack.get("timestamp", datetime.utcnow().isoformat() + "Z"),
                "name": f"{attack.get('type', 'Unknown')} from {origin.get('ip', 'unknown')}",
                "description": f"Attack detected: {attack.get('type')} from {origin.get('country', 'Unknown')}",
                "indicator_types": ["malicious-activity"],
                "pattern": f"[ipv4-addr:value = '{origin.get('ip', '0.0.0.0')}']",
                "pattern_type": "stix",
                "valid_from": attack.get("timestamp", datetime.utcnow().isoformat() + "Z"),
                "labels": [attack.get("type", "unknown").lower().replace(" ", "-")]
            }
            objects.append(indicator)

            # Create observed-data
            observed = {
                "type": "observed-data",
                "spec_version": "2.1",
                "id": f"observed-data--{attack.get('id', 'unknown')}",
                "created": attack.get("timestamp", datetime.utcnow().isoformat() + "Z"),
                "modified": attack.get("timestamp", datetime.utcnow().isoformat() + "Z"),
                "first_observed": attack.get("timestamp", datetime.utcnow().isoformat() + "Z"),
                "last_observed": attack.get("timestamp", datetime.utcnow().isoformat() + "Z"),
                "number_observed": 1,
                "object_refs": [f"ipv4-addr--{origin.get('ip', '0.0.0.0').replace('.', '-')}"]
            }
            objects.append(observed)

        return {
            "type": "bundle",
            "id": f"bundle--threatmap-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            "objects": objects
        }

    def get_configs(self) -> List[dict]:
        """Get all SIEM configurations"""
        return [
            {
                "id": c.id,
                "name": c.name,
                "siem_type": c.siem_type,
                "enabled": c.enabled,
                "events_sent": c.events_sent,
                "last_sent": c.last_sent,
                "last_error": c.last_error
            }
            for c in self.configs.values()
        ]

    def get_statistics(self) -> dict:
        """Get SIEM export statistics"""
        total_sent = sum(c.events_sent for c in self.configs.values())
        active = len([c for c in self.configs.values() if c.enabled])

        return {
            "total_configs": len(self.configs),
            "active_configs": active,
            "total_events_sent": total_sent,
            "by_type": {
                siem_type: len([c for c in self.configs.values() if c.siem_type == siem_type])
                for siem_type in ["syslog", "splunk", "elastic", "stix"]
            }
        }
