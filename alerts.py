"""
Alert System for Threat Map
Sends notifications via webhooks, email, sound, etc.
"""

import asyncio
import aiohttp
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, asdict
import os


@dataclass
class AlertRule:
    """Defines an alert rule"""
    id: int
    name: str
    enabled: bool
    rule_type: str  # severity, attack_type, country, rate, ip
    conditions: dict
    actions: list  # webhook, sound, log
    cooldown_minutes: int = 5
    last_triggered: Optional[datetime] = None


@dataclass
class Alert:
    """An alert instance"""
    rule_id: int
    rule_name: str
    timestamp: str
    severity: str
    message: str
    attack_data: dict


class AlertManager:
    """Manages alert rules and dispatches notifications"""

    def __init__(self):
        self.rules: List[AlertRule] = []
        self.alert_history: List[Alert] = []
        self.rate_counters: Dict[str, List[datetime]] = {}
        self.callbacks: List[Callable] = []
        self.webhook_session: Optional[aiohttp.ClientSession] = None

        # Default rules
        self._init_default_rules()

    def _init_default_rules(self):
        """Initialize default alert rules"""
        self.rules = [
            AlertRule(
                id=1,
                name="Critical Severity Attack",
                enabled=True,
                rule_type="severity",
                conditions={"severity": "critical"},
                actions=["sound", "log", "broadcast"],
                cooldown_minutes=1
            ),
            AlertRule(
                id=2,
                name="Ransomware Detected",
                enabled=True,
                rule_type="attack_type",
                conditions={"attack_type": "Ransomware"},
                actions=["sound", "log", "broadcast"],
                cooldown_minutes=5
            ),
            AlertRule(
                id=3,
                name="APT Attack",
                enabled=True,
                rule_type="attack_type",
                conditions={"attack_type": "APT"},
                actions=["sound", "log", "broadcast"],
                cooldown_minutes=5
            ),
            AlertRule(
                id=4,
                name="High Attack Rate",
                enabled=True,
                rule_type="rate",
                conditions={"threshold": 100, "window_seconds": 60},
                actions=["log", "broadcast"],
                cooldown_minutes=5
            ),
            AlertRule(
                id=5,
                name="Honeypot Attack",
                enabled=True,
                rule_type="source",
                conditions={"source": "honeypot"},
                actions=["sound", "log", "broadcast"],
                cooldown_minutes=0  # Always alert for honeypot
            ),
        ]

    def add_callback(self, callback: Callable):
        """Add a callback for when alerts fire"""
        self.callbacks.append(callback)

    def add_rule(self, rule: AlertRule):
        """Add a new alert rule"""
        rule.id = len(self.rules) + 1
        self.rules.append(rule)
        return rule.id

    def remove_rule(self, rule_id: int):
        """Remove an alert rule"""
        self.rules = [r for r in self.rules if r.id != rule_id]

    def enable_rule(self, rule_id: int, enabled: bool = True):
        """Enable or disable a rule"""
        for rule in self.rules:
            if rule.id == rule_id:
                rule.enabled = enabled
                return True
        return False

    async def check_attack(self, attack: dict) -> List[Alert]:
        """Check an attack against all rules and return triggered alerts"""
        triggered_alerts = []

        # Update rate counter
        attack_type = attack.get("type", "unknown")
        now = datetime.utcnow()
        if attack_type not in self.rate_counters:
            self.rate_counters[attack_type] = []
        self.rate_counters[attack_type].append(now)

        # Clean old entries (keep last 5 minutes)
        cutoff = now - timedelta(minutes=5)
        self.rate_counters[attack_type] = [
            t for t in self.rate_counters[attack_type] if t > cutoff
        ]

        for rule in self.rules:
            if not rule.enabled:
                continue

            # Check cooldown
            if rule.last_triggered:
                cooldown_end = rule.last_triggered + timedelta(minutes=rule.cooldown_minutes)
                if now < cooldown_end:
                    continue

            # Check conditions
            triggered = False
            message = ""

            if rule.rule_type == "severity":
                if attack.get("severity") == rule.conditions.get("severity"):
                    triggered = True
                    message = f"{rule.conditions['severity'].upper()} severity attack detected"

            elif rule.rule_type == "attack_type":
                if attack.get("type") == rule.conditions.get("attack_type"):
                    triggered = True
                    message = f"{rule.conditions['attack_type']} attack detected"

            elif rule.rule_type == "country":
                origin_country = attack.get("origin", {}).get("country")
                if origin_country in rule.conditions.get("countries", []):
                    triggered = True
                    message = f"Attack from monitored country: {origin_country}"

            elif rule.rule_type == "rate":
                threshold = rule.conditions.get("threshold", 100)
                window = rule.conditions.get("window_seconds", 60)
                window_start = now - timedelta(seconds=window)

                # Count all attacks in window
                total_count = sum(
                    len([t for t in times if t > window_start])
                    for times in self.rate_counters.values()
                )

                if total_count >= threshold:
                    triggered = True
                    message = f"High attack rate: {total_count} attacks in {window}s"

            elif rule.rule_type == "source":
                if attack.get("source") == rule.conditions.get("source"):
                    triggered = True
                    message = f"Attack from {rule.conditions['source']}"

            elif rule.rule_type == "ip":
                origin_ip = attack.get("origin", {}).get("ip")
                if origin_ip in rule.conditions.get("ips", []):
                    triggered = True
                    message = f"Attack from watched IP: {origin_ip}"

            if triggered:
                rule.last_triggered = now
                alert = Alert(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    timestamp=now.isoformat() + "Z",
                    severity=attack.get("severity", "medium"),
                    message=message,
                    attack_data=attack
                )
                triggered_alerts.append(alert)
                self.alert_history.append(alert)

                # Execute actions
                await self._execute_actions(rule, alert)

        # Keep history limited
        if len(self.alert_history) > 1000:
            self.alert_history = self.alert_history[-500:]

        return triggered_alerts

    async def _execute_actions(self, rule: AlertRule, alert: Alert):
        """Execute alert actions"""
        for action in rule.actions:
            if action == "log":
                print(f"[ALERT] {alert.rule_name}: {alert.message}")

            elif action == "sound":
                # Sound is handled by the frontend
                pass

            elif action == "broadcast":
                # Notify all callbacks (for WebSocket broadcast)
                for callback in self.callbacks:
                    try:
                        if asyncio.iscoroutinefunction(callback):
                            await callback(alert)
                        else:
                            callback(alert)
                    except Exception as e:
                        print(f"Alert callback error: {e}")

            elif action == "webhook":
                webhook_url = rule.conditions.get("webhook_url")
                if webhook_url:
                    await self._send_webhook(webhook_url, alert)

    async def _send_webhook(self, url: str, alert: Alert):
        """Send alert to webhook"""
        if not self.webhook_session:
            import ssl
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            connector = aiohttp.TCPConnector(ssl=ssl_context)
            self.webhook_session = aiohttp.ClientSession(connector=connector)

        try:
            payload = {
                "alert": alert.rule_name,
                "message": alert.message,
                "severity": alert.severity,
                "timestamp": alert.timestamp,
                "attack": {
                    "type": alert.attack_data.get("type"),
                    "origin": alert.attack_data.get("origin", {}),
                    "target": alert.attack_data.get("target", {})
                }
            }

            async with self.webhook_session.post(
                url,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                if resp.status >= 400:
                    print(f"Webhook failed: {resp.status}")

        except Exception as e:
            print(f"Webhook error: {e}")

    def get_rules(self) -> List[dict]:
        """Get all rules as dicts"""
        return [
            {
                "id": r.id,
                "name": r.name,
                "enabled": r.enabled,
                "rule_type": r.rule_type,
                "conditions": r.conditions,
                "actions": r.actions,
                "cooldown_minutes": r.cooldown_minutes,
                "last_triggered": r.last_triggered.isoformat() if r.last_triggered else None
            }
            for r in self.rules
        ]

    def get_alert_history(self, limit: int = 100) -> List[dict]:
        """Get recent alert history"""
        return [
            {
                "rule_id": a.rule_id,
                "rule_name": a.rule_name,
                "timestamp": a.timestamp,
                "severity": a.severity,
                "message": a.message
            }
            for a in self.alert_history[-limit:]
        ]

    async def close(self):
        """Cleanup resources"""
        if self.webhook_session:
            await self.webhook_session.close()


# Slack webhook helper
async def send_slack_alert(webhook_url: str, alert: Alert):
    """Send alert to Slack"""
    severity_colors = {
        "critical": "#ff0000",
        "high": "#ff8800",
        "medium": "#ffff00",
        "low": "#00ff00"
    }

    payload = {
        "attachments": [{
            "color": severity_colors.get(alert.severity, "#888888"),
            "title": f"🚨 {alert.rule_name}",
            "text": alert.message,
            "fields": [
                {
                    "title": "Attack Type",
                    "value": alert.attack_data.get("type", "Unknown"),
                    "short": True
                },
                {
                    "title": "Severity",
                    "value": alert.severity.upper(),
                    "short": True
                },
                {
                    "title": "Origin",
                    "value": f"{alert.attack_data.get('origin', {}).get('city', 'Unknown')}, {alert.attack_data.get('origin', {}).get('country', 'Unknown')}",
                    "short": True
                },
                {
                    "title": "Attacker IP",
                    "value": alert.attack_data.get("origin", {}).get("ip", "Unknown"),
                    "short": True
                }
            ],
            "footer": "ThreatMap Alert System",
            "ts": int(datetime.utcnow().timestamp())
        }]
    }

    async with aiohttp.ClientSession() as session:
        await session.post(webhook_url, json=payload)


# Discord webhook helper
async def send_discord_alert(webhook_url: str, alert: Alert):
    """Send alert to Discord"""
    severity_colors = {
        "critical": 0xff0000,
        "high": 0xff8800,
        "medium": 0xffff00,
        "low": 0x00ff00
    }

    payload = {
        "embeds": [{
            "title": f"🚨 {alert.rule_name}",
            "description": alert.message,
            "color": severity_colors.get(alert.severity, 0x888888),
            "fields": [
                {"name": "Attack Type", "value": alert.attack_data.get("type", "Unknown"), "inline": True},
                {"name": "Severity", "value": alert.severity.upper(), "inline": True},
                {"name": "Origin", "value": f"{alert.attack_data.get('origin', {}).get('ip', 'Unknown')}", "inline": True}
            ],
            "footer": {"text": "ThreatMap Alert System"},
            "timestamp": alert.timestamp
        }]
    }

    async with aiohttp.ClientSession() as session:
        await session.post(webhook_url, json=payload)
