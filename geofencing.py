"""
Geofencing and Country Blocking for Threat Map
Allows defining geographic regions for monitoring and blocking
"""

import math
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from datetime import datetime


@dataclass
class GeoFence:
    """A geographic fence/region"""
    id: str
    name: str
    fence_type: str  # circle, polygon, country
    enabled: bool = True
    action: str = "alert"  # alert, block, log

    # For circle type
    center_lat: float = 0.0
    center_lng: float = 0.0
    radius_km: float = 100.0

    # For polygon type
    polygon_points: List[Tuple[float, float]] = field(default_factory=list)

    # For country type
    countries: List[str] = field(default_factory=list)

    # Statistics
    triggered_count: int = 0
    last_triggered: Optional[str] = None


# Country coordinates (centroids) for country-based geofencing
COUNTRY_COORDS: Dict[str, Tuple[float, float]] = {
    "United States": (37.0902, -95.7129),
    "China": (35.8617, 104.1954),
    "Russia": (61.5240, 105.3188),
    "Germany": (51.1657, 10.4515),
    "United Kingdom": (55.3781, -3.4360),
    "France": (46.2276, 2.2137),
    "Japan": (36.2048, 138.2529),
    "Brazil": (-14.2350, -51.9253),
    "India": (20.5937, 78.9629),
    "Canada": (56.1304, -106.3468),
    "Australia": (-25.2744, 133.7751),
    "Netherlands": (52.1326, 5.2913),
    "South Korea": (35.9078, 127.7669),
    "Singapore": (1.3521, 103.8198),
    "Ukraine": (48.3794, 31.1656),
    "Poland": (51.9194, 19.1451),
    "Romania": (45.9432, 24.9668),
    "Vietnam": (14.0583, 108.2772),
    "Indonesia": (-0.7893, 113.9213),
    "Iran": (32.4279, 53.6880),
    "North Korea": (40.3399, 127.5101),
    "Pakistan": (30.3753, 69.3451),
    "Bangladesh": (23.6850, 90.3563),
    "Nigeria": (9.0820, 8.6753),
    "Egypt": (26.8206, 30.8025),
    "Turkey": (38.9637, 35.2433),
    "Mexico": (23.6345, -102.5528),
    "Argentina": (-38.4161, -63.6167),
    "South Africa": (-30.5595, 22.9375),
}

# Known high-risk countries for threat monitoring
HIGH_RISK_COUNTRIES = [
    "Russia", "China", "North Korea", "Iran"
]


class GeoFenceManager:
    """Manages geographic fences and country blocking"""

    def __init__(self):
        self.fences: Dict[str, GeoFence] = {}
        self.blocked_countries: set = set()
        self.monitored_countries: set = set()
        self.triggered_events: List[dict] = []

        # Initialize default fences
        self._init_default_fences()

    def _init_default_fences(self):
        """Create default geofences"""
        # High-risk country monitoring
        self.add_fence(GeoFence(
            id="high_risk_countries",
            name="High Risk Countries",
            fence_type="country",
            enabled=True,
            action="alert",
            countries=HIGH_RISK_COUNTRIES
        ))

        # Example circle around a datacenter
        self.add_fence(GeoFence(
            id="us_east_dc",
            name="US East Coast Datacenter",
            fence_type="circle",
            enabled=False,
            action="log",
            center_lat=39.0438,
            center_lng=-77.4874,
            radius_km=50
        ))

    def add_fence(self, fence: GeoFence) -> str:
        """Add a new geofence"""
        self.fences[fence.id] = fence

        if fence.fence_type == "country":
            for country in fence.countries:
                if fence.action == "block":
                    self.blocked_countries.add(country)
                else:
                    self.monitored_countries.add(country)

        return fence.id

    def remove_fence(self, fence_id: str) -> bool:
        """Remove a geofence"""
        if fence_id in self.fences:
            fence = self.fences[fence_id]
            if fence.fence_type == "country":
                for country in fence.countries:
                    self.blocked_countries.discard(country)
                    self.monitored_countries.discard(country)
            del self.fences[fence_id]
            return True
        return False

    def enable_fence(self, fence_id: str, enabled: bool = True) -> bool:
        """Enable or disable a geofence"""
        if fence_id in self.fences:
            self.fences[fence_id].enabled = enabled
            return True
        return False

    def check_attack(self, attack: dict) -> Optional[dict]:
        """Check if an attack triggers any geofence"""
        origin = attack.get("origin", {})
        lat = origin.get("lat", 0)
        lng = origin.get("lng", 0)
        country = origin.get("country", "Unknown")

        for fence_id, fence in self.fences.items():
            if not fence.enabled:
                continue

            triggered = False

            if fence.fence_type == "country":
                if country in fence.countries:
                    triggered = True

            elif fence.fence_type == "circle":
                distance = self._haversine(lat, lng, fence.center_lat, fence.center_lng)
                if distance <= fence.radius_km:
                    triggered = True

            elif fence.fence_type == "polygon":
                if self._point_in_polygon(lat, lng, fence.polygon_points):
                    triggered = True

            if triggered:
                fence.triggered_count += 1
                fence.last_triggered = datetime.utcnow().isoformat() + "Z"

                event = {
                    "fence_id": fence_id,
                    "fence_name": fence.name,
                    "action": fence.action,
                    "attack": attack,
                    "timestamp": fence.last_triggered
                }
                self.triggered_events.append(event)

                # Keep events bounded
                if len(self.triggered_events) > 1000:
                    self.triggered_events = self.triggered_events[-500:]

                return event

        return None

    def _haversine(self, lat1: float, lng1: float, lat2: float, lng2: float) -> float:
        """Calculate distance between two points in km"""
        R = 6371  # Earth's radius in km

        lat1_rad = math.radians(lat1)
        lat2_rad = math.radians(lat2)
        delta_lat = math.radians(lat2 - lat1)
        delta_lng = math.radians(lng2 - lng1)

        a = math.sin(delta_lat/2)**2 + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(delta_lng/2)**2
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))

        return R * c

    def _point_in_polygon(self, lat: float, lng: float, polygon: List[Tuple[float, float]]) -> bool:
        """Check if point is inside polygon using ray casting"""
        if len(polygon) < 3:
            return False

        n = len(polygon)
        inside = False

        j = n - 1
        for i in range(n):
            if ((polygon[i][0] > lat) != (polygon[j][0] > lat)) and \
               (lng < (polygon[j][1] - polygon[i][1]) * (lat - polygon[i][0]) / (polygon[j][0] - polygon[i][0]) + polygon[i][1]):
                inside = not inside
            j = i

        return inside

    def is_blocked(self, attack: dict) -> bool:
        """Check if attack should be blocked"""
        country = attack.get("origin", {}).get("country", "Unknown")
        return country in self.blocked_countries

    def get_fences(self) -> List[dict]:
        """Get all geofences"""
        return [
            {
                "id": f.id,
                "name": f.name,
                "fence_type": f.fence_type,
                "enabled": f.enabled,
                "action": f.action,
                "center_lat": f.center_lat if f.fence_type == "circle" else None,
                "center_lng": f.center_lng if f.fence_type == "circle" else None,
                "radius_km": f.radius_km if f.fence_type == "circle" else None,
                "polygon_points": f.polygon_points if f.fence_type == "polygon" else None,
                "countries": f.countries if f.fence_type == "country" else None,
                "triggered_count": f.triggered_count,
                "last_triggered": f.last_triggered
            }
            for f in self.fences.values()
        ]

    def get_blocked_countries(self) -> List[str]:
        """Get list of blocked countries"""
        return list(self.blocked_countries)

    def get_monitored_countries(self) -> List[str]:
        """Get list of monitored countries"""
        return list(self.monitored_countries)

    def get_events(self, limit: int = 100) -> List[dict]:
        """Get recent geofence trigger events"""
        return self.triggered_events[-limit:]

    def generate_firewall_rules(self, format: str = "iptables") -> str:
        """Generate firewall rules for blocked countries"""
        # This would need a GeoIP database for IP ranges
        # For now, return placeholder rules

        if format == "iptables":
            rules = ["# Geofence blocking rules for iptables"]
            rules.append("# Requires xtables-addons geoip module")
            for country in self.blocked_countries:
                # Convert country name to ISO code (simplified)
                code = self._country_to_code(country)
                if code:
                    rules.append(f"iptables -A INPUT -m geoip --src-cc {code} -j DROP")
            return "\n".join(rules)

        elif format == "pf":
            rules = ["# Geofence blocking rules for PF"]
            codes = [self._country_to_code(c) for c in self.blocked_countries if self._country_to_code(c)]
            if codes:
                rules.append(f"table <blocked_countries> persist")
                rules.append(f"block in quick from <blocked_countries>")
            return "\n".join(rules)

        return "# Unknown format"

    def _country_to_code(self, country: str) -> Optional[str]:
        """Convert country name to ISO code"""
        codes = {
            "Russia": "RU", "China": "CN", "North Korea": "KP",
            "Iran": "IR", "United States": "US", "Germany": "DE",
            "United Kingdom": "GB", "France": "FR", "Japan": "JP",
            "Brazil": "BR", "India": "IN", "Canada": "CA",
            "Australia": "AU", "Netherlands": "NL", "South Korea": "KR",
            "Singapore": "SG", "Ukraine": "UA", "Poland": "PL",
            "Romania": "RO", "Vietnam": "VN", "Indonesia": "ID",
            "Pakistan": "PK", "Bangladesh": "BD", "Nigeria": "NG",
            "Egypt": "EG", "Turkey": "TR", "Mexico": "MX",
            "Argentina": "AR", "South Africa": "ZA"
        }
        return codes.get(country)

    def get_statistics(self) -> dict:
        """Get geofencing statistics"""
        return {
            "total_fences": len(self.fences),
            "active_fences": len([f for f in self.fences.values() if f.enabled]),
            "blocked_countries": len(self.blocked_countries),
            "monitored_countries": len(self.monitored_countries),
            "total_triggers": sum(f.triggered_count for f in self.fences.values()),
            "recent_events": len(self.triggered_events)
        }
