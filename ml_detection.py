"""
Machine Learning Anomaly Detection for Threat Map
Uses statistical methods and clustering to detect anomalies
"""

import math
from collections import defaultdict
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
import json


@dataclass
class AnomalyScore:
    """Anomaly detection result"""
    ip: str
    score: float  # 0-100, higher = more anomalous
    reasons: List[str]
    timestamp: str
    attack_data: dict


@dataclass
class AttackPattern:
    """Learned attack pattern"""
    hour_distribution: Dict[int, float] = field(default_factory=dict)
    type_distribution: Dict[str, float] = field(default_factory=dict)
    country_distribution: Dict[str, float] = field(default_factory=dict)
    avg_rate_per_minute: float = 0.0
    std_rate_per_minute: float = 1.0


class AnomalyDetector:
    """
    Detects anomalous attacks using statistical analysis.
    No external ML libraries required - uses pure Python.
    """

    def __init__(self):
        self.attack_history: List[dict] = []
        self.ip_history: Dict[str, List[dict]] = defaultdict(list)
        self.learned_pattern = AttackPattern()
        self.anomalies: List[AnomalyScore] = []
        self.learning_window = timedelta(hours=24)
        self.min_samples = 100

        # Clustering for campaign detection
        self.clusters: Dict[str, List[str]] = {}  # cluster_id -> list of IPs

    def add_attack(self, attack: dict) -> Optional[AnomalyScore]:
        """Add attack and check for anomalies"""
        self.attack_history.append(attack)

        ip = attack.get("origin", {}).get("ip", "unknown")
        self.ip_history[ip].append(attack)

        # Keep history bounded
        if len(self.attack_history) > 10000:
            self.attack_history = self.attack_history[-5000:]

        # Learn patterns periodically
        if len(self.attack_history) % 100 == 0:
            self._learn_patterns()

        # Check for anomaly
        if len(self.attack_history) >= self.min_samples:
            anomaly = self._detect_anomaly(attack)
            if anomaly and anomaly.score > 70:
                self.anomalies.append(anomaly)
                return anomaly

        return None

    def _learn_patterns(self):
        """Learn normal attack patterns from history"""
        if len(self.attack_history) < self.min_samples:
            return

        # Hour distribution
        hour_counts = defaultdict(int)
        type_counts = defaultdict(int)
        country_counts = defaultdict(int)

        for attack in self.attack_history:
            try:
                ts = attack.get("timestamp", "")
                if ts:
                    hour = datetime.fromisoformat(ts.replace("Z", "+00:00")).hour
                    hour_counts[hour] += 1
            except:
                pass

            attack_type = attack.get("type", "Unknown")
            type_counts[attack_type] += 1

            country = attack.get("origin", {}).get("country", "Unknown")
            country_counts[country] += 1

        total = len(self.attack_history)

        self.learned_pattern.hour_distribution = {
            h: c / total for h, c in hour_counts.items()
        }
        self.learned_pattern.type_distribution = {
            t: c / total for t, c in type_counts.items()
        }
        self.learned_pattern.country_distribution = {
            c: count / total for c, count in country_counts.items()
        }

        # Calculate rate statistics
        rates = self._calculate_rates()
        if rates:
            self.learned_pattern.avg_rate_per_minute = sum(rates) / len(rates)
            variance = sum((r - self.learned_pattern.avg_rate_per_minute) ** 2 for r in rates) / len(rates)
            self.learned_pattern.std_rate_per_minute = math.sqrt(variance) if variance > 0 else 1.0

    def _calculate_rates(self) -> List[float]:
        """Calculate attack rates per minute"""
        if len(self.attack_history) < 2:
            return []

        rates = []
        minute_counts = defaultdict(int)

        for attack in self.attack_history:
            try:
                ts = attack.get("timestamp", "")
                if ts:
                    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    minute_key = dt.strftime("%Y-%m-%d %H:%M")
                    minute_counts[minute_key] += 1
            except:
                pass

        return list(minute_counts.values())

    def _detect_anomaly(self, attack: dict) -> Optional[AnomalyScore]:
        """Detect if an attack is anomalous"""
        score = 0.0
        reasons = []

        ip = attack.get("origin", {}).get("ip", "unknown")
        attack_type = attack.get("type", "Unknown")
        country = attack.get("origin", {}).get("country", "Unknown")

        # 1. Check if attack type is rare
        type_freq = self.learned_pattern.type_distribution.get(attack_type, 0)
        if type_freq < 0.01:  # Less than 1% of attacks
            score += 30
            reasons.append(f"Rare attack type: {attack_type} ({type_freq*100:.1f}%)")

        # 2. Check if country is rare
        country_freq = self.learned_pattern.country_distribution.get(country, 0)
        if country_freq < 0.01:
            score += 20
            reasons.append(f"Rare source country: {country}")

        # 3. Check for burst from single IP
        ip_attacks = self.ip_history.get(ip, [])
        recent_attacks = [
            a for a in ip_attacks
            if self._is_recent(a.get("timestamp", ""), minutes=5)
        ]
        if len(recent_attacks) > 10:
            score += 25
            reasons.append(f"Burst activity: {len(recent_attacks)} attacks in 5 min")

        # 4. Check for unusual time
        try:
            ts = attack.get("timestamp", "")
            if ts:
                hour = datetime.fromisoformat(ts.replace("Z", "+00:00")).hour
                hour_freq = self.learned_pattern.hour_distribution.get(hour, 0)
                if hour_freq < 0.02:
                    score += 15
                    reasons.append(f"Unusual hour: {hour}:00 ({hour_freq*100:.1f}%)")
        except:
            pass

        # 5. Check for new attacker
        if len(ip_attacks) == 1:
            score += 10
            reasons.append("First attack from this IP")

        # 6. Check severity
        if attack.get("severity") == "critical":
            score += 20
            reasons.append("Critical severity")

        if score > 0:
            return AnomalyScore(
                ip=ip,
                score=min(score, 100),
                reasons=reasons,
                timestamp=attack.get("timestamp", datetime.utcnow().isoformat() + "Z"),
                attack_data=attack
            )

        return None

    def _is_recent(self, timestamp: str, minutes: int) -> bool:
        """Check if timestamp is within recent minutes"""
        try:
            dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            now = datetime.now(dt.tzinfo) if dt.tzinfo else datetime.utcnow()
            return (now - dt) < timedelta(minutes=minutes)
        except:
            return False

    def detect_campaigns(self) -> List[dict]:
        """Detect coordinated attack campaigns using clustering"""
        campaigns = []

        # Group attacks by time windows
        time_windows = defaultdict(list)
        for attack in self.attack_history[-1000:]:
            try:
                ts = attack.get("timestamp", "")
                if ts:
                    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    window = dt.strftime("%Y-%m-%d %H:%M")[:15] + "0"  # 10-min windows
                    time_windows[window].append(attack)
            except:
                pass

        # Find coordinated attacks (same type, multiple IPs, short window)
        for window, attacks in time_windows.items():
            if len(attacks) < 5:
                continue

            # Group by attack type
            type_groups = defaultdict(list)
            for attack in attacks:
                type_groups[attack.get("type", "Unknown")].append(attack)

            for attack_type, type_attacks in type_groups.items():
                unique_ips = set(a.get("origin", {}).get("ip") for a in type_attacks)
                if len(unique_ips) >= 3 and len(type_attacks) >= 5:
                    campaigns.append({
                        "id": f"campaign_{window}_{attack_type}",
                        "type": attack_type,
                        "start_time": window,
                        "attack_count": len(type_attacks),
                        "unique_sources": len(unique_ips),
                        "source_ips": list(unique_ips)[:10],
                        "confidence": min(len(unique_ips) * 10 + len(type_attacks) * 5, 100)
                    })

        return campaigns

    def get_risk_score(self, ip: str) -> dict:
        """Calculate risk score for an IP"""
        attacks = self.ip_history.get(ip, [])

        if not attacks:
            return {"ip": ip, "risk_score": 0, "factors": []}

        score = 0
        factors = []

        # Attack count
        if len(attacks) > 50:
            score += 30
            factors.append(f"High attack volume: {len(attacks)}")
        elif len(attacks) > 10:
            score += 15
            factors.append(f"Moderate attack volume: {len(attacks)}")

        # Attack diversity
        types = set(a.get("type") for a in attacks)
        if len(types) > 3:
            score += 20
            factors.append(f"Multiple attack types: {', '.join(types)}")

        # Recent activity
        recent = [a for a in attacks if self._is_recent(a.get("timestamp", ""), minutes=60)]
        if len(recent) > 5:
            score += 25
            factors.append(f"Recent activity: {len(recent)} in last hour")

        # Severity
        critical = [a for a in attacks if a.get("severity") == "critical"]
        if critical:
            score += 25
            factors.append(f"Critical attacks: {len(critical)}")

        return {
            "ip": ip,
            "risk_score": min(score, 100),
            "factors": factors,
            "total_attacks": len(attacks),
            "attack_types": list(types),
            "first_seen": attacks[0].get("timestamp") if attacks else None,
            "last_seen": attacks[-1].get("timestamp") if attacks else None
        }

    def get_anomalies(self, limit: int = 50) -> List[dict]:
        """Get recent anomalies"""
        return [
            {
                "ip": a.ip,
                "score": a.score,
                "reasons": a.reasons,
                "timestamp": a.timestamp,
                "attack_type": a.attack_data.get("type")
            }
            for a in self.anomalies[-limit:]
        ]

    def get_statistics(self) -> dict:
        """Get ML detection statistics"""
        return {
            "total_attacks_analyzed": len(self.attack_history),
            "unique_ips": len(self.ip_history),
            "anomalies_detected": len(self.anomalies),
            "learned_patterns": {
                "top_attack_types": dict(sorted(
                    self.learned_pattern.type_distribution.items(),
                    key=lambda x: x[1], reverse=True
                )[:5]),
                "top_countries": dict(sorted(
                    self.learned_pattern.country_distribution.items(),
                    key=lambda x: x[1], reverse=True
                )[:5]),
                "avg_rate_per_minute": round(self.learned_pattern.avg_rate_per_minute, 2)
            }
        }


class ThreatPredictor:
    """Predicts likely attack sources and times"""

    def __init__(self):
        self.attack_history: List[dict] = []

    def add_attack(self, attack: dict):
        self.attack_history.append(attack)
        if len(self.attack_history) > 5000:
            self.attack_history = self.attack_history[-2500:]

    def predict_next_hour(self) -> dict:
        """Predict attack likelihood for next hour"""
        if len(self.attack_history) < 100:
            return {"error": "Insufficient data"}

        # Analyze patterns
        hour_counts = defaultdict(int)
        type_counts = defaultdict(int)
        country_counts = defaultdict(int)

        for attack in self.attack_history:
            try:
                ts = attack.get("timestamp", "")
                if ts:
                    hour = datetime.fromisoformat(ts.replace("Z", "+00:00")).hour
                    hour_counts[hour] += 1
            except:
                pass

            type_counts[attack.get("type", "Unknown")] += 1
            country_counts[attack.get("origin", {}).get("country", "Unknown")] += 1

        current_hour = datetime.utcnow().hour
        next_hour = (current_hour + 1) % 24

        # Calculate expected rate
        total = len(self.attack_history)
        expected_rate = hour_counts.get(next_hour, 0) / max(1, total) * total

        return {
            "next_hour": next_hour,
            "expected_attacks": round(expected_rate),
            "likely_types": sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:3],
            "likely_sources": sorted(country_counts.items(), key=lambda x: x[1], reverse=True)[:3],
            "confidence": min(len(self.attack_history) / 1000 * 100, 95)
        }
