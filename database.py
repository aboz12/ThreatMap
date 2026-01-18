"""
SQLite Database for Threat Map
Stores attack history, statistics, and configuration
"""

import sqlite3
import json
from datetime import datetime, timedelta
from pathlib import Path
from contextlib import contextmanager

DB_PATH = Path(__file__).parent / "data" / "threatmap.db"


def init_db():
    """Initialize the database schema"""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    with get_connection() as conn:
        cursor = conn.cursor()

        # Attacks table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS attacks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                attack_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                origin_ip TEXT NOT NULL,
                origin_city TEXT,
                origin_country TEXT,
                origin_lat REAL,
                origin_lng REAL,
                origin_isp TEXT,
                origin_asn TEXT,
                target_ip TEXT,
                target_city TEXT,
                target_country TEXT,
                target_lat REAL,
                target_lng REAL,
                target_port INTEGER,
                source TEXT,
                malware TEXT,
                raw_data TEXT
            )
        """)

        # Create indexes for fast queries
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON attacks(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_attack_type ON attacks(attack_type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_origin_ip ON attacks(origin_ip)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_origin_country ON attacks(origin_country)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_severity ON attacks(severity)")

        # Statistics table (hourly aggregates)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS hourly_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hour DATETIME NOT NULL,
                attack_type TEXT NOT NULL,
                count INTEGER DEFAULT 0,
                UNIQUE(hour, attack_type)
            )
        """)

        # IP reputation cache
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ip_reputation (
                ip TEXT PRIMARY KEY,
                city TEXT,
                country TEXT,
                lat REAL,
                lng REAL,
                isp TEXT,
                org TEXT,
                asn TEXT,
                reverse_dns TEXT,
                whois_data TEXT,
                threat_score INTEGER DEFAULT 0,
                attack_count INTEGER DEFAULT 0,
                first_seen DATETIME,
                last_seen DATETIME,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Threat actors table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS threat_actors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                aliases TEXT,
                description TEXT,
                country TEXT,
                attack_types TEXT,
                indicators TEXT,
                first_seen DATETIME,
                last_seen DATETIME,
                attack_count INTEGER DEFAULT 0
            )
        """)

        # Alerts configuration
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alert_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                enabled INTEGER DEFAULT 1,
                rule_type TEXT NOT NULL,
                conditions TEXT NOT NULL,
                actions TEXT NOT NULL,
                cooldown_minutes INTEGER DEFAULT 5,
                last_triggered DATETIME,
                trigger_count INTEGER DEFAULT 0
            )
        """)

        # Alert history
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alert_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id INTEGER,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                attack_id INTEGER,
                message TEXT,
                delivered INTEGER DEFAULT 0,
                FOREIGN KEY (rule_id) REFERENCES alert_rules(id)
            )
        """)

        # Blocklists
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS blocklist (
                ip TEXT PRIMARY KEY,
                added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                reason TEXT,
                attack_count INTEGER DEFAULT 1,
                expires_at DATETIME
            )
        """)

        conn.commit()

    # Insert default threat actors
    _seed_threat_actors()


@contextmanager
def get_connection():
    """Get a database connection with context manager"""
    conn = sqlite3.connect(str(DB_PATH), timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def save_attack(attack: dict):
    """Save an attack to the database"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO attacks (
                timestamp, attack_type, severity,
                origin_ip, origin_city, origin_country, origin_lat, origin_lng, origin_isp, origin_asn,
                target_ip, target_city, target_country, target_lat, target_lng, target_port,
                source, malware, raw_data
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            attack.get("timestamp"),
            attack.get("type"),
            attack.get("severity"),
            attack["origin"]["ip"],
            attack["origin"].get("city"),
            attack["origin"].get("country"),
            attack["origin"].get("lat"),
            attack["origin"].get("lng"),
            attack["origin"].get("isp"),
            attack["origin"].get("asn"),
            attack["target"]["ip"],
            attack["target"].get("city"),
            attack["target"].get("country"),
            attack["target"].get("lat"),
            attack["target"].get("lng"),
            attack["target"].get("port"),
            attack.get("source"),
            attack.get("malware"),
            json.dumps(attack)
        ))

        # Update IP reputation
        cursor.execute("""
            INSERT INTO ip_reputation (ip, city, country, lat, lng, isp, attack_count, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            ON CONFLICT(ip) DO UPDATE SET
                attack_count = attack_count + 1,
                last_seen = CURRENT_TIMESTAMP
        """, (
            attack["origin"]["ip"],
            attack["origin"].get("city"),
            attack["origin"].get("country"),
            attack["origin"].get("lat"),
            attack["origin"].get("lng"),
            attack["origin"].get("isp")
        ))

        # Update hourly stats
        hour = datetime.fromisoformat(attack["timestamp"].replace("Z", "")).strftime("%Y-%m-%d %H:00:00")
        cursor.execute("""
            INSERT INTO hourly_stats (hour, attack_type, count)
            VALUES (?, ?, 1)
            ON CONFLICT(hour, attack_type) DO UPDATE SET count = count + 1
        """, (hour, attack.get("type")))

        # Add to blocklist if high severity
        if attack.get("severity") in ("critical", "high"):
            cursor.execute("""
                INSERT INTO blocklist (ip, reason, attack_count)
                VALUES (?, ?, 1)
                ON CONFLICT(ip) DO UPDATE SET attack_count = attack_count + 1
            """, (attack["origin"]["ip"], f"{attack.get('type')} attack"))

        conn.commit()
        return cursor.lastrowid


def get_attacks(limit=100, offset=0, filters=None):
    """Get attacks with optional filters"""
    with get_connection() as conn:
        cursor = conn.cursor()

        query = "SELECT * FROM attacks WHERE 1=1"
        params = []

        if filters:
            if filters.get("attack_type"):
                query += " AND attack_type = ?"
                params.append(filters["attack_type"])
            if filters.get("severity"):
                query += " AND severity = ?"
                params.append(filters["severity"])
            if filters.get("origin_country"):
                query += " AND origin_country = ?"
                params.append(filters["origin_country"])
            if filters.get("origin_ip"):
                query += " AND origin_ip LIKE ?"
                params.append(f"%{filters['origin_ip']}%")
            if filters.get("start_time"):
                query += " AND timestamp >= ?"
                params.append(filters["start_time"])
            if filters.get("end_time"):
                query += " AND timestamp <= ?"
                params.append(filters["end_time"])

        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]


def get_time_series(hours=24, attack_type=None):
    """Get attack counts by hour for charts"""
    with get_connection() as conn:
        cursor = conn.cursor()

        start_time = (datetime.utcnow() - timedelta(hours=hours)).strftime("%Y-%m-%d %H:00:00")

        if attack_type:
            cursor.execute("""
                SELECT hour, attack_type, count
                FROM hourly_stats
                WHERE hour >= ? AND attack_type = ?
                ORDER BY hour
            """, (start_time, attack_type))
        else:
            cursor.execute("""
                SELECT hour, attack_type, SUM(count) as count
                FROM hourly_stats
                WHERE hour >= ?
                GROUP BY hour, attack_type
                ORDER BY hour
            """, (start_time,))

        return [dict(row) for row in cursor.fetchall()]


def get_top_attackers(limit=10):
    """Get top attacking IPs"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT ip, city, country, isp, attack_count, first_seen, last_seen
            FROM ip_reputation
            ORDER BY attack_count DESC
            LIMIT ?
        """, (limit,))
        return [dict(row) for row in cursor.fetchall()]


def get_top_countries(limit=10):
    """Get top attacking countries"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT origin_country as country, COUNT(*) as count
            FROM attacks
            WHERE origin_country IS NOT NULL
            GROUP BY origin_country
            ORDER BY count DESC
            LIMIT ?
        """, (limit,))
        return [dict(row) for row in cursor.fetchall()]


def get_attack_type_stats():
    """Get attack counts by type"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT attack_type, COUNT(*) as count
            FROM attacks
            GROUP BY attack_type
            ORDER BY count DESC
        """)
        return [dict(row) for row in cursor.fetchall()]


def get_blocklist(format="json"):
    """Get the blocklist in various formats"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT ip, reason, attack_count, added_at
            FROM blocklist
            ORDER BY attack_count DESC
        """)
        rows = [dict(row) for row in cursor.fetchall()]

        if format == "json":
            return rows
        elif format == "plain":
            return "\n".join(row["ip"] for row in rows)
        elif format == "iptables":
            return "\n".join(f"iptables -A INPUT -s {row['ip']} -j DROP" for row in rows)
        elif format == "pf":
            ips = " ".join(row["ip"] for row in rows)
            return f"table <blocklist> {{ {ips} }}\nblock in quick from <blocklist>"
        elif format == "nginx":
            return "\n".join(f"deny {row['ip']};" for row in rows)
        else:
            return rows


def get_ip_reputation(ip: str):
    """Get reputation data for an IP"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM ip_reputation WHERE ip = ?", (ip,))
        row = cursor.fetchone()
        return dict(row) if row else None


def update_ip_enrichment(ip: str, data: dict):
    """Update IP with enrichment data (WHOIS, ASN, etc.)"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE ip_reputation SET
                asn = COALESCE(?, asn),
                reverse_dns = COALESCE(?, reverse_dns),
                whois_data = COALESCE(?, whois_data),
                threat_score = COALESCE(?, threat_score),
                updated_at = CURRENT_TIMESTAMP
            WHERE ip = ?
        """, (
            data.get("asn"),
            data.get("reverse_dns"),
            json.dumps(data.get("whois")) if data.get("whois") else None,
            data.get("threat_score"),
            ip
        ))
        conn.commit()


def get_threat_actors():
    """Get all threat actor profiles"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM threat_actors ORDER BY attack_count DESC")
        return [dict(row) for row in cursor.fetchall()]


def _seed_threat_actors():
    """Seed initial threat actor data"""
    actors = [
        {
            "name": "Lazarus Group",
            "aliases": "Hidden Cobra, Guardians of Peace, APT38",
            "description": "North Korean state-sponsored threat group known for financial theft and espionage",
            "country": "North Korea",
            "attack_types": "APT, Ransomware, Financial"
        },
        {
            "name": "APT29",
            "aliases": "Cozy Bear, The Dukes",
            "description": "Russian intelligence-linked group targeting government and diplomatic entities",
            "country": "Russia",
            "attack_types": "APT, Espionage"
        },
        {
            "name": "APT28",
            "aliases": "Fancy Bear, Sofacy, Sednit",
            "description": "Russian military intelligence (GRU) cyber unit",
            "country": "Russia",
            "attack_types": "APT, Espionage, Disinformation"
        },
        {
            "name": "Mozi Botnet",
            "aliases": "Mozi",
            "description": "IoT botnet targeting routers and DVRs for DDoS attacks",
            "country": "China",
            "attack_types": "Botnet, DDoS, IoT"
        },
        {
            "name": "Mirai",
            "aliases": "Mirai Botnet",
            "description": "Infamous IoT botnet used for massive DDoS attacks",
            "country": "Unknown",
            "attack_types": "Botnet, DDoS, IoT"
        },
        {
            "name": "Emotet",
            "aliases": "Heodo, Geodo",
            "description": "Banking trojan turned malware distribution network",
            "country": "Unknown",
            "attack_types": "Malware, Banking Trojan, Spam"
        },
        {
            "name": "TrickBot",
            "aliases": "TrickLoader",
            "description": "Modular banking trojan often used with ransomware",
            "country": "Russia",
            "attack_types": "Malware, Banking Trojan, Ransomware"
        },
        {
            "name": "Cobalt Group",
            "aliases": "Cobalt Gang",
            "description": "Financially motivated group targeting banks worldwide",
            "country": "Unknown",
            "attack_types": "APT, Financial, CobaltStrike"
        },
    ]

    with get_connection() as conn:
        cursor = conn.cursor()
        for actor in actors:
            cursor.execute("""
                INSERT OR IGNORE INTO threat_actors (name, aliases, description, country, attack_types)
                VALUES (?, ?, ?, ?, ?)
            """, (actor["name"], actor["aliases"], actor["description"], actor["country"], actor["attack_types"]))
        conn.commit()


# Alert functions
def get_alert_rules():
    """Get all alert rules"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM alert_rules")
        return [dict(row) for row in cursor.fetchall()]


def create_alert_rule(name, rule_type, conditions, actions, cooldown=5):
    """Create a new alert rule"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO alert_rules (name, rule_type, conditions, actions, cooldown_minutes)
            VALUES (?, ?, ?, ?, ?)
        """, (name, rule_type, json.dumps(conditions), json.dumps(actions), cooldown))
        conn.commit()
        return cursor.lastrowid


def log_alert(rule_id, attack_id, message):
    """Log an alert trigger"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO alert_history (rule_id, attack_id, message)
            VALUES (?, ?, ?)
        """, (rule_id, attack_id, message))
        cursor.execute("""
            UPDATE alert_rules SET last_triggered = CURRENT_TIMESTAMP, trigger_count = trigger_count + 1
            WHERE id = ?
        """, (rule_id,))
        conn.commit()


def get_stats_summary():
    """Get overall statistics summary"""
    with get_connection() as conn:
        cursor = conn.cursor()

        # Total attacks
        cursor.execute("SELECT COUNT(*) as total FROM attacks")
        total = cursor.fetchone()["total"]

        # Today's attacks
        cursor.execute("""
            SELECT COUNT(*) as today FROM attacks
            WHERE timestamp >= date('now')
        """)
        today = cursor.fetchone()["today"]

        # Unique IPs
        cursor.execute("SELECT COUNT(DISTINCT origin_ip) as unique_ips FROM attacks")
        unique_ips = cursor.fetchone()["unique_ips"]

        # Blocklist size
        cursor.execute("SELECT COUNT(*) as blocked FROM blocklist")
        blocked = cursor.fetchone()["blocked"]

        return {
            "total_attacks": total,
            "today_attacks": today,
            "unique_attackers": unique_ips,
            "blocked_ips": blocked
        }


# Initialize database on import
init_db()
