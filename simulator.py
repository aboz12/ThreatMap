"""
Attack Simulation Mode for Threat Map
Replay historical campaigns and generate demo scenarios
"""

import random
import asyncio
from datetime import datetime, timedelta
from typing import List, Dict, Callable, Optional
from dataclasses import dataclass


@dataclass
class SimulationScenario:
    """A simulation scenario"""
    id: str
    name: str
    description: str
    attack_count: int
    duration_seconds: int
    attack_types: List[str]
    source_countries: List[str]
    severity_distribution: Dict[str, float]


# Pre-built scenarios based on real-world campaigns
SCENARIOS: Dict[str, SimulationScenario] = {
    "wannacry": SimulationScenario(
        id="wannacry",
        name="WannaCry Ransomware (2017)",
        description="Simulates the WannaCry ransomware spread pattern - rapid global propagation targeting SMB vulnerabilities",
        attack_count=500,
        duration_seconds=300,
        attack_types=["Ransomware", "Malware"],
        source_countries=["North Korea", "China", "Russia", "United States", "Germany", "France", "United Kingdom"],
        severity_distribution={"critical": 0.7, "high": 0.2, "medium": 0.1}
    ),
    "mirai_botnet": SimulationScenario(
        id="mirai_botnet",
        name="Mirai Botnet DDoS",
        description="Simulates Mirai-style IoT botnet DDoS attack with global zombie network",
        attack_count=1000,
        duration_seconds=180,
        attack_types=["DDoS", "Botnet"],
        source_countries=["Vietnam", "Brazil", "India", "China", "Indonesia", "Turkey", "Russia"],
        severity_distribution={"critical": 0.3, "high": 0.4, "medium": 0.3}
    ),
    "apt_campaign": SimulationScenario(
        id="apt_campaign",
        name="APT Espionage Campaign",
        description="Simulates a slow, targeted APT campaign with reconnaissance, initial access, and lateral movement",
        attack_count=50,
        duration_seconds=600,
        attack_types=["APT", "Scanner", "Brute Force", "Malware"],
        source_countries=["Russia", "China", "North Korea"],
        severity_distribution={"critical": 0.4, "high": 0.4, "medium": 0.2}
    ),
    "cryptomining": SimulationScenario(
        id="cryptomining",
        name="Cryptomining Campaign",
        description="Simulates widespread cryptomining malware deployment",
        attack_count=300,
        duration_seconds=240,
        attack_types=["Malware", "Brute Force"],
        source_countries=["Russia", "Romania", "Netherlands", "Germany", "United States"],
        severity_distribution={"critical": 0.1, "high": 0.3, "medium": 0.6}
    ),
    "phishing_wave": SimulationScenario(
        id="phishing_wave",
        name="Phishing Campaign Wave",
        description="Simulates a large-scale phishing campaign targeting organizations",
        attack_count=200,
        duration_seconds=120,
        attack_types=["Phishing", "Spam"],
        source_countries=["Nigeria", "Russia", "Netherlands", "United States", "China"],
        severity_distribution={"critical": 0.1, "high": 0.3, "medium": 0.4, "low": 0.2}
    ),
    "sql_injection": SimulationScenario(
        id="sql_injection",
        name="SQL Injection Campaign",
        description="Simulates automated SQL injection attacks against web applications",
        attack_count=150,
        duration_seconds=180,
        attack_types=["SQL Injection", "Scanner"],
        source_countries=["China", "Russia", "United States", "Netherlands", "Germany"],
        severity_distribution={"critical": 0.3, "high": 0.5, "medium": 0.2}
    ),
    "nation_state": SimulationScenario(
        id="nation_state",
        name="Nation-State Attack",
        description="Simulates a sophisticated nation-state cyber operation",
        attack_count=30,
        duration_seconds=900,
        attack_types=["APT", "Malware", "Ransomware"],
        source_countries=["North Korea", "Russia", "China", "Iran"],
        severity_distribution={"critical": 0.8, "high": 0.2}
    ),
    "demo": SimulationScenario(
        id="demo",
        name="Demo Mode",
        description="Continuous demonstration with varied attack types",
        attack_count=100,
        duration_seconds=60,
        attack_types=["DDoS", "Malware", "Brute Force", "SQL Injection", "XSS", "Phishing", "Scanner"],
        source_countries=["United States", "China", "Russia", "Germany", "Brazil", "India", "United Kingdom", "France"],
        severity_distribution={"critical": 0.1, "high": 0.3, "medium": 0.4, "low": 0.2}
    ),
}

# Geographic data for realistic simulation
COUNTRY_COORDS = {
    "United States": [(37.0902, -95.7129), (40.7128, -74.0060), (34.0522, -118.2437), (41.8781, -87.6298)],
    "China": [(39.9042, 116.4074), (31.2304, 121.4737), (22.5431, 114.0579), (30.5728, 104.0668)],
    "Russia": [(55.7558, 37.6173), (59.9311, 30.3609), (55.0084, 82.9357), (56.8389, 60.6057)],
    "Germany": [(52.5200, 13.4050), (48.1351, 11.5820), (50.1109, 8.6821), (53.5511, 9.9937)],
    "United Kingdom": [(51.5074, -0.1278), (53.4808, -2.2426), (55.9533, -3.1883), (51.4545, -2.5879)],
    "France": [(48.8566, 2.3522), (45.7640, 4.8357), (43.2965, 5.3698), (43.6047, 1.4442)],
    "Brazil": [(-23.5505, -46.6333), (-22.9068, -43.1729), (-19.9167, -43.9345), (-30.0346, -51.2177)],
    "India": [(28.6139, 77.2090), (19.0760, 72.8777), (13.0827, 80.2707), (22.5726, 88.3639)],
    "Japan": [(35.6762, 139.6503), (34.6937, 135.5023), (35.1815, 136.9066), (43.0618, 141.3545)],
    "North Korea": [(39.0392, 125.7625), (40.3399, 127.5101), (38.7519, 125.7817)],
    "Vietnam": [(21.0285, 105.8542), (10.8231, 106.6297), (16.0544, 108.2022)],
    "Indonesia": [(-6.2088, 106.8456), (-7.2575, 112.7521), (-6.9175, 107.6191)],
    "Netherlands": [(52.3676, 4.9041), (51.9225, 4.4792), (52.0907, 5.1214)],
    "Romania": [(44.4268, 26.1025), (46.7712, 23.6236), (45.7489, 21.2087)],
    "Nigeria": [(6.5244, 3.3792), (9.0579, 7.4951), (11.9964, 8.5167)],
    "Iran": [(35.6892, 51.3890), (32.6546, 51.6680), (29.5918, 52.5836)],
    "Turkey": [(41.0082, 28.9784), (39.9334, 32.8597), (38.4192, 27.1287)],
}

TARGET_CITIES = [
    {"city": "New York", "country": "United States", "lat": 40.7128, "lng": -74.0060},
    {"city": "London", "country": "United Kingdom", "lat": 51.5074, "lng": -0.1278},
    {"city": "Tokyo", "country": "Japan", "lat": 35.6762, "lng": 139.6503},
    {"city": "Frankfurt", "country": "Germany", "lat": 50.1109, "lng": 8.6821},
    {"city": "Singapore", "country": "Singapore", "lat": 1.3521, "lng": 103.8198},
    {"city": "Sydney", "country": "Australia", "lat": -33.8688, "lng": 151.2093},
    {"city": "Amsterdam", "country": "Netherlands", "lat": 52.3676, "lng": 4.9041},
]


class AttackSimulator:
    """Generates simulated attacks for demonstration and testing"""

    def __init__(self, callback: Callable = None):
        self.callback = callback
        self.running = False
        self.current_scenario: Optional[str] = None
        self.attacks_generated = 0
        self.task: Optional[asyncio.Task] = None

    async def start_scenario(self, scenario_id: str) -> bool:
        """Start a simulation scenario"""
        if scenario_id not in SCENARIOS:
            return False

        if self.running:
            await self.stop()

        self.current_scenario = scenario_id
        self.running = True
        self.attacks_generated = 0

        scenario = SCENARIOS[scenario_id]
        self.task = asyncio.create_task(self._run_scenario(scenario))

        return True

    async def stop(self):
        """Stop current simulation"""
        self.running = False
        if self.task:
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                pass
        self.current_scenario = None

    async def _run_scenario(self, scenario: SimulationScenario):
        """Run a simulation scenario"""
        interval = scenario.duration_seconds / scenario.attack_count

        for i in range(scenario.attack_count):
            if not self.running:
                break

            attack = self._generate_attack(scenario)
            self.attacks_generated += 1

            if self.callback:
                if asyncio.iscoroutinefunction(self.callback):
                    await self.callback(attack)
                else:
                    self.callback(attack)

            # Vary the interval slightly for realism
            jitter = random.uniform(0.5, 1.5)
            await asyncio.sleep(interval * jitter)

        self.running = False
        self.current_scenario = None

    def _generate_attack(self, scenario: SimulationScenario) -> dict:
        """Generate a single attack based on scenario"""
        # Select attack type
        attack_type = random.choice(scenario.attack_types)

        # Select severity based on distribution
        rand = random.random()
        cumulative = 0
        severity = "medium"
        for sev, prob in scenario.severity_distribution.items():
            cumulative += prob
            if rand <= cumulative:
                severity = sev
                break

        # Select source country and coordinates
        source_country = random.choice(scenario.source_countries)
        if source_country in COUNTRY_COORDS:
            source_coord = random.choice(COUNTRY_COORDS[source_country])
        else:
            source_coord = (random.uniform(-60, 70), random.uniform(-180, 180))

        # Add some randomness to coordinates
        lat = source_coord[0] + random.uniform(-2, 2)
        lng = source_coord[1] + random.uniform(-2, 2)

        # Select target
        target = random.choice(TARGET_CITIES)

        # Generate realistic IP
        ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

        return {
            "id": f"sim_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{random.randint(1000, 9999)}",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "type": attack_type,
            "severity": severity,
            "source": "simulation",
            "scenario": scenario.id,
            "origin": {
                "ip": ip,
                "city": source_country.split()[0],  # Simplified
                "country": source_country,
                "lat": lat,
                "lng": lng
            },
            "target": {
                "ip": f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
                "city": target["city"],
                "country": target["country"],
                "lat": target["lat"],
                "lng": target["lng"],
                "port": random.choice([22, 80, 443, 3389, 445, 1433, 3306, 5432, 8080])
            }
        }

    def generate_single_attack(self, attack_type: str = None, source_country: str = None, severity: str = None) -> dict:
        """Generate a single custom attack"""
        if attack_type is None:
            attack_type = random.choice(["DDoS", "Malware", "Brute Force", "SQL Injection", "Scanner"])

        if source_country is None:
            source_country = random.choice(list(COUNTRY_COORDS.keys()))

        if severity is None:
            severity = random.choice(["critical", "high", "medium", "low"])

        scenario = SimulationScenario(
            id="custom",
            name="Custom",
            description="",
            attack_count=1,
            duration_seconds=1,
            attack_types=[attack_type],
            source_countries=[source_country],
            severity_distribution={severity: 1.0}
        )

        return self._generate_attack(scenario)

    def get_scenarios(self) -> List[dict]:
        """Get all available scenarios"""
        return [
            {
                "id": s.id,
                "name": s.name,
                "description": s.description,
                "attack_count": s.attack_count,
                "duration_seconds": s.duration_seconds,
                "attack_types": s.attack_types
            }
            for s in SCENARIOS.values()
        ]

    def get_status(self) -> dict:
        """Get current simulation status"""
        return {
            "running": self.running,
            "current_scenario": self.current_scenario,
            "attacks_generated": self.attacks_generated,
            "scenario_details": SCENARIOS[self.current_scenario].__dict__ if self.current_scenario else None
        }


class HistoricalPlayback:
    """Replay historical attack data"""

    def __init__(self, callback: Callable = None):
        self.callback = callback
        self.running = False
        self.paused = False
        self.speed = 1.0
        self.position = 0
        self.attacks: List[dict] = []
        self.task: Optional[asyncio.Task] = None

    async def load_attacks(self, attacks: List[dict]):
        """Load attacks for playback"""
        # Sort by timestamp
        self.attacks = sorted(attacks, key=lambda x: x.get("timestamp", ""))
        self.position = 0

    async def start(self, speed: float = 1.0):
        """Start playback"""
        if not self.attacks:
            return False

        self.speed = speed
        self.running = True
        self.paused = False

        self.task = asyncio.create_task(self._playback_loop())
        return True

    async def pause(self):
        """Pause playback"""
        self.paused = True

    async def resume(self):
        """Resume playback"""
        self.paused = False

    async def stop(self):
        """Stop playback"""
        self.running = False
        if self.task:
            self.task.cancel()

    async def seek(self, position: int):
        """Seek to position in attack list"""
        if 0 <= position < len(self.attacks):
            self.position = position

    async def set_speed(self, speed: float):
        """Set playback speed (0.1x to 10x)"""
        self.speed = max(0.1, min(10.0, speed))

    async def _playback_loop(self):
        """Main playback loop"""
        while self.running and self.position < len(self.attacks):
            if self.paused:
                await asyncio.sleep(0.1)
                continue

            attack = self.attacks[self.position]

            # Update timestamp to current time
            attack_copy = attack.copy()
            attack_copy["timestamp"] = datetime.utcnow().isoformat() + "Z"
            attack_copy["source"] = "playback"

            if self.callback:
                if asyncio.iscoroutinefunction(self.callback):
                    await self.callback(attack_copy)
                else:
                    self.callback(attack_copy)

            self.position += 1

            # Calculate delay to next attack
            if self.position < len(self.attacks):
                try:
                    current_ts = datetime.fromisoformat(attack.get("timestamp", "").replace("Z", "+00:00"))
                    next_ts = datetime.fromisoformat(self.attacks[self.position].get("timestamp", "").replace("Z", "+00:00"))
                    delay = (next_ts - current_ts).total_seconds() / self.speed
                    delay = max(0.01, min(5.0, delay))  # Clamp delay
                except:
                    delay = 0.5 / self.speed

                await asyncio.sleep(delay)

        self.running = False

    def get_status(self) -> dict:
        """Get playback status"""
        return {
            "running": self.running,
            "paused": self.paused,
            "speed": self.speed,
            "position": self.position,
            "total_attacks": len(self.attacks),
            "progress_percent": (self.position / len(self.attacks) * 100) if self.attacks else 0
        }
