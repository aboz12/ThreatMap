"""
Multi-Sensor Support for Threat Map
Aggregate data from multiple ThreatMap instances and sensors
"""

import asyncio
import aiohttp
import json
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Callable
from dataclasses import dataclass, field


@dataclass
class Sensor:
    """Remote sensor/ThreatMap instance"""
    id: str
    name: str
    url: str
    api_key: str = ""
    enabled: bool = True
    location: str = ""
    latitude: float = 0.0
    longitude: float = 0.0

    # Status
    status: str = "unknown"  # online, offline, error
    last_seen: Optional[str] = None
    last_error: Optional[str] = None

    # Stats
    attacks_received: int = 0
    uptime_percent: float = 100.0


@dataclass
class SensorData:
    """Data received from a sensor"""
    sensor_id: str
    sensor_name: str
    attacks: List[dict]
    stats: dict
    timestamp: str


class SensorManager:
    """Manages multiple sensors/ThreatMap instances"""

    def __init__(self, callback: Callable = None):
        self.sensors: Dict[str, Sensor] = {}
        self.callback = callback
        self.aggregated_attacks: List[dict] = []
        self.session: Optional[aiohttp.ClientSession] = None
        self.polling_task: Optional[asyncio.Task] = None
        self.polling_interval = 30  # seconds

    async def init_session(self):
        """Initialize HTTP session"""
        if not self.session:
            self.session = aiohttp.ClientSession()

    async def close(self):
        """Close resources"""
        if self.polling_task:
            self.polling_task.cancel()
        if self.session:
            await self.session.close()

    def add_sensor(self, sensor: Sensor) -> str:
        """Add a sensor"""
        self.sensors[sensor.id] = sensor
        return sensor.id

    def remove_sensor(self, sensor_id: str) -> bool:
        """Remove a sensor"""
        if sensor_id in self.sensors:
            del self.sensors[sensor_id]
            return True
        return False

    def enable_sensor(self, sensor_id: str, enabled: bool = True) -> bool:
        """Enable or disable a sensor"""
        if sensor_id in self.sensors:
            self.sensors[sensor_id].enabled = enabled
            return True
        return False

    async def poll_sensor(self, sensor_id: str) -> Optional[SensorData]:
        """Poll a single sensor for data"""
        if sensor_id not in self.sensors:
            return None

        sensor = self.sensors[sensor_id]
        if not sensor.enabled:
            return None

        await self.init_session()

        try:
            headers = {}
            if sensor.api_key:
                headers["Authorization"] = f"Bearer {sensor.api_key}"

            # Get stats
            async with self.session.get(
                f"{sensor.url}/api/stats",
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                if resp.status != 200:
                    raise Exception(f"HTTP {resp.status}")
                stats = await resp.json()

            # Get recent attacks
            async with self.session.get(
                f"{sensor.url}/api/attacks?limit=100",
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                if resp.status != 200:
                    raise Exception(f"HTTP {resp.status}")
                attacks = await resp.json()

            # Update sensor status
            sensor.status = "online"
            sensor.last_seen = datetime.utcnow().isoformat() + "Z"
            sensor.last_error = None

            # Tag attacks with sensor info
            for attack in attacks:
                attack["sensor_id"] = sensor_id
                attack["sensor_name"] = sensor.name
                attack["sensor_location"] = sensor.location

            sensor.attacks_received += len(attacks)

            return SensorData(
                sensor_id=sensor_id,
                sensor_name=sensor.name,
                attacks=attacks,
                stats=stats,
                timestamp=datetime.utcnow().isoformat() + "Z"
            )

        except Exception as e:
            sensor.status = "error"
            sensor.last_error = str(e)
            return None

    async def poll_all_sensors(self) -> Dict[str, SensorData]:
        """Poll all enabled sensors"""
        results = {}

        tasks = []
        for sensor_id in self.sensors:
            if self.sensors[sensor_id].enabled:
                tasks.append(self.poll_sensor(sensor_id))

        sensor_data_list = await asyncio.gather(*tasks, return_exceptions=True)

        for data in sensor_data_list:
            if isinstance(data, SensorData):
                results[data.sensor_id] = data

                # Forward new attacks to callback
                if self.callback:
                    for attack in data.attacks:
                        if asyncio.iscoroutinefunction(self.callback):
                            await self.callback(attack)
                        else:
                            self.callback(attack)

        return results

    async def start_polling(self, interval: int = 30):
        """Start continuous polling"""
        self.polling_interval = interval
        self.polling_task = asyncio.create_task(self._polling_loop())

    async def stop_polling(self):
        """Stop polling"""
        if self.polling_task:
            self.polling_task.cancel()
            try:
                await self.polling_task
            except asyncio.CancelledError:
                pass

    async def _polling_loop(self):
        """Continuous polling loop"""
        while True:
            try:
                await self.poll_all_sensors()
            except Exception as e:
                print(f"Polling error: {e}")

            await asyncio.sleep(self.polling_interval)

    async def check_sensor_health(self, sensor_id: str) -> dict:
        """Check health of a sensor"""
        if sensor_id not in self.sensors:
            return {"error": "Sensor not found"}

        sensor = self.sensors[sensor_id]
        await self.init_session()

        try:
            headers = {}
            if sensor.api_key:
                headers["Authorization"] = f"Bearer {sensor.api_key}"

            start = datetime.utcnow()

            async with self.session.get(
                f"{sensor.url}/api/stats",
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=5)
            ) as resp:
                latency = (datetime.utcnow() - start).total_seconds() * 1000

                return {
                    "sensor_id": sensor_id,
                    "status": "healthy" if resp.status == 200 else "unhealthy",
                    "http_status": resp.status,
                    "latency_ms": round(latency, 2),
                    "timestamp": datetime.utcnow().isoformat() + "Z"
                }

        except Exception as e:
            return {
                "sensor_id": sensor_id,
                "status": "unreachable",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }

    def get_sensors(self) -> List[dict]:
        """Get all sensors"""
        return [
            {
                "id": s.id,
                "name": s.name,
                "url": s.url,
                "enabled": s.enabled,
                "location": s.location,
                "latitude": s.latitude,
                "longitude": s.longitude,
                "status": s.status,
                "last_seen": s.last_seen,
                "last_error": s.last_error,
                "attacks_received": s.attacks_received
            }
            for s in self.sensors.values()
        ]

    def get_sensor(self, sensor_id: str) -> Optional[dict]:
        """Get single sensor details"""
        if sensor_id not in self.sensors:
            return None

        s = self.sensors[sensor_id]
        return {
            "id": s.id,
            "name": s.name,
            "url": s.url,
            "enabled": s.enabled,
            "location": s.location,
            "latitude": s.latitude,
            "longitude": s.longitude,
            "status": s.status,
            "last_seen": s.last_seen,
            "last_error": s.last_error,
            "attacks_received": s.attacks_received,
            "uptime_percent": s.uptime_percent
        }

    def get_aggregated_stats(self) -> dict:
        """Get aggregated statistics across all sensors"""
        total_attacks = sum(s.attacks_received for s in self.sensors.values())
        online_sensors = len([s for s in self.sensors.values() if s.status == "online"])
        total_sensors = len(self.sensors)

        return {
            "total_sensors": total_sensors,
            "online_sensors": online_sensors,
            "offline_sensors": total_sensors - online_sensors,
            "total_attacks_aggregated": total_attacks,
            "sensors_by_status": {
                "online": online_sensors,
                "offline": len([s for s in self.sensors.values() if s.status == "offline"]),
                "error": len([s for s in self.sensors.values() if s.status == "error"]),
                "unknown": len([s for s in self.sensors.values() if s.status == "unknown"])
            }
        }

    def get_sensor_map_data(self) -> List[dict]:
        """Get sensor locations for map display"""
        return [
            {
                "id": s.id,
                "name": s.name,
                "lat": s.latitude,
                "lng": s.longitude,
                "location": s.location,
                "status": s.status,
                "attacks": s.attacks_received
            }
            for s in self.sensors.values()
            if s.latitude != 0 or s.longitude != 0
        ]


class SensorCorrelator:
    """Correlates attacks across multiple sensors"""

    def __init__(self):
        self.attack_index: Dict[str, List[dict]] = {}  # IP -> attacks

    def add_attack(self, attack: dict):
        """Index an attack for correlation"""
        ip = attack.get("origin", {}).get("ip")
        if ip:
            if ip not in self.attack_index:
                self.attack_index[ip] = []
            self.attack_index[ip].append(attack)

            # Keep bounded
            if len(self.attack_index[ip]) > 100:
                self.attack_index[ip] = self.attack_index[ip][-50:]

    def find_correlations(self, time_window_minutes: int = 60) -> List[dict]:
        """Find correlated attacks (same IP hitting multiple sensors)"""
        correlations = []
        cutoff = datetime.utcnow() - timedelta(minutes=time_window_minutes)

        for ip, attacks in self.attack_index.items():
            # Filter to recent attacks
            recent = []
            for a in attacks:
                try:
                    ts = datetime.fromisoformat(a.get("timestamp", "").replace("Z", "+00:00"))
                    if ts.replace(tzinfo=None) > cutoff:
                        recent.append(a)
                except:
                    pass

            if len(recent) < 2:
                continue

            # Check for multiple sensors
            sensors = set(a.get("sensor_id") for a in recent if a.get("sensor_id"))

            if len(sensors) >= 2:
                correlations.append({
                    "ip": ip,
                    "attack_count": len(recent),
                    "sensors_hit": list(sensors),
                    "attack_types": list(set(a.get("type") for a in recent)),
                    "first_seen": min(a.get("timestamp", "") for a in recent),
                    "last_seen": max(a.get("timestamp", "") for a in recent),
                    "confidence": min(100, len(sensors) * 30 + len(recent) * 5)
                })

        return sorted(correlations, key=lambda x: x["confidence"], reverse=True)

    def get_attack_campaign(self, ip: str) -> Optional[dict]:
        """Get campaign details for an IP"""
        if ip not in self.attack_index:
            return None

        attacks = self.attack_index[ip]
        sensors = set(a.get("sensor_id") for a in attacks if a.get("sensor_id"))
        types = set(a.get("type") for a in attacks)

        return {
            "ip": ip,
            "total_attacks": len(attacks),
            "sensors": list(sensors),
            "attack_types": list(types),
            "timeline": [
                {"timestamp": a.get("timestamp"), "type": a.get("type"), "sensor": a.get("sensor_id")}
                for a in sorted(attacks, key=lambda x: x.get("timestamp", ""))
            ]
        }
