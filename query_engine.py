"""
Threat Hunting Query Engine for Threat Map
SQL-like queries for searching attack data
"""

import re
import operator
from datetime import datetime, timedelta
from typing import List, Dict, Any, Callable, Optional
from dataclasses import dataclass


@dataclass
class SavedQuery:
    """A saved query"""
    id: str
    name: str
    query: str
    description: str
    created_by: str
    created_at: str
    run_count: int = 0
    last_run: Optional[str] = None


class QueryEngine:
    """
    Simple query engine for threat hunting.
    Supports SQL-like syntax for filtering attacks.

    Examples:
        type = "DDoS" AND severity = "critical"
        origin.country = "Russia" OR origin.country = "China"
        timestamp > "2024-01-01" AND type IN ("Malware", "Ransomware")
        origin.ip LIKE "192.168.%"
        severity = "critical" ORDER BY timestamp DESC LIMIT 100
    """

    OPERATORS = {
        "=": operator.eq,
        "!=": operator.ne,
        ">": operator.gt,
        "<": operator.lt,
        ">=": operator.ge,
        "<=": operator.le,
    }

    def __init__(self):
        self.saved_queries: Dict[str, SavedQuery] = {}
        self.query_history: List[dict] = []
        self._init_default_queries()

    def _init_default_queries(self):
        """Initialize default saved queries"""
        defaults = [
            SavedQuery(
                id="critical_attacks",
                name="Critical Severity Attacks",
                query='severity = "critical"',
                description="Find all critical severity attacks",
                created_by="system",
                created_at=datetime.utcnow().isoformat() + "Z"
            ),
            SavedQuery(
                id="russian_attacks",
                name="Attacks from Russia",
                query='origin.country = "Russia"',
                description="Find attacks originating from Russia",
                created_by="system",
                created_at=datetime.utcnow().isoformat() + "Z"
            ),
            SavedQuery(
                id="ransomware",
                name="Ransomware Attacks",
                query='type = "Ransomware" OR type = "APT"',
                description="Find ransomware and APT attacks",
                created_by="system",
                created_at=datetime.utcnow().isoformat() + "Z"
            ),
            SavedQuery(
                id="recent_critical",
                name="Recent Critical (1 hour)",
                query='severity = "critical" AND timestamp > NOW(-1h)',
                description="Critical attacks in the last hour",
                created_by="system",
                created_at=datetime.utcnow().isoformat() + "Z"
            ),
            SavedQuery(
                id="brute_force",
                name="Brute Force Attacks",
                query='type = "Brute Force" OR source = "honeypot"',
                description="Brute force and honeypot captures",
                created_by="system",
                created_at=datetime.utcnow().isoformat() + "Z"
            ),
        ]

        for q in defaults:
            self.saved_queries[q.id] = q

    def execute(self, query: str, attacks: List[dict], limit: int = 1000) -> dict:
        """Execute a query against attack data"""
        start_time = datetime.utcnow()

        try:
            # Parse query
            parsed = self._parse_query(query)

            # Apply filters
            results = self._apply_filters(attacks, parsed["conditions"])

            # Apply ordering
            if parsed.get("order_by"):
                results = self._apply_order(results, parsed["order_by"], parsed.get("order_dir", "ASC"))

            # Apply limit
            query_limit = parsed.get("limit", limit)
            results = results[:query_limit]

            end_time = datetime.utcnow()
            duration_ms = (end_time - start_time).total_seconds() * 1000

            result = {
                "success": True,
                "query": query,
                "total_scanned": len(attacks),
                "results_count": len(results),
                "results": results,
                "duration_ms": round(duration_ms, 2),
                "timestamp": end_time.isoformat() + "Z"
            }

            # Log query
            self.query_history.append({
                "query": query,
                "results_count": len(results),
                "duration_ms": result["duration_ms"],
                "timestamp": result["timestamp"]
            })

            if len(self.query_history) > 100:
                self.query_history = self.query_history[-50:]

            return result

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "query": query,
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }

    def _parse_query(self, query: str) -> dict:
        """Parse query into conditions and modifiers"""
        result = {
            "conditions": [],
            "order_by": None,
            "order_dir": "ASC",
            "limit": None
        }

        # Extract ORDER BY
        order_match = re.search(r'\s+ORDER\s+BY\s+(\w+(?:\.\w+)?)\s*(ASC|DESC)?', query, re.IGNORECASE)
        if order_match:
            result["order_by"] = order_match.group(1)
            result["order_dir"] = (order_match.group(2) or "ASC").upper()
            query = query[:order_match.start()]

        # Extract LIMIT
        limit_match = re.search(r'\s+LIMIT\s+(\d+)', query, re.IGNORECASE)
        if limit_match:
            result["limit"] = int(limit_match.group(1))
            query = query[:limit_match.start()]

        # Parse conditions
        result["conditions"] = self._parse_conditions(query.strip())

        return result

    def _parse_conditions(self, query: str) -> List[dict]:
        """Parse WHERE conditions"""
        conditions = []

        # Handle NOW() function
        query = self._expand_now(query)

        # Split by AND/OR (simple approach)
        # For complex queries, a proper parser would be needed
        parts = re.split(r'\s+(AND|OR)\s+', query, flags=re.IGNORECASE)

        current_operator = "AND"
        for i, part in enumerate(parts):
            if part.upper() in ("AND", "OR"):
                current_operator = part.upper()
                continue

            condition = self._parse_single_condition(part.strip())
            if condition:
                condition["logical_op"] = current_operator if conditions else None
                conditions.append(condition)

        return conditions

    def _expand_now(self, query: str) -> str:
        """Expand NOW() function to actual timestamp"""
        def replace_now(match):
            offset = match.group(1) or "0h"
            value = int(re.match(r'-?(\d+)', offset).group(1))
            unit = offset[-1]

            if unit == 'h':
                delta = timedelta(hours=value)
            elif unit == 'd':
                delta = timedelta(days=value)
            elif unit == 'm':
                delta = timedelta(minutes=value)
            else:
                delta = timedelta(hours=value)

            if offset.startswith('-'):
                ts = datetime.utcnow() - delta
            else:
                ts = datetime.utcnow() + delta

            return f'"{ts.isoformat()}Z"'

        return re.sub(r'NOW\(([^)]*)\)', replace_now, query)

    def _parse_single_condition(self, condition: str) -> Optional[dict]:
        """Parse a single condition like 'type = "DDoS"'"""

        # Handle IN operator
        in_match = re.match(r'(\w+(?:\.\w+)?)\s+IN\s*\(([^)]+)\)', condition, re.IGNORECASE)
        if in_match:
            field = in_match.group(1)
            values = [v.strip().strip('"\'') for v in in_match.group(2).split(',')]
            return {"field": field, "operator": "IN", "value": values}

        # Handle LIKE operator
        like_match = re.match(r'(\w+(?:\.\w+)?)\s+LIKE\s+["\']([^"\']+)["\']', condition, re.IGNORECASE)
        if like_match:
            field = like_match.group(1)
            pattern = like_match.group(2).replace('%', '.*').replace('_', '.')
            return {"field": field, "operator": "LIKE", "value": pattern}

        # Handle comparison operators
        for op in ["!=", ">=", "<=", "=", ">", "<"]:
            if op in condition:
                parts = condition.split(op, 1)
                if len(parts) == 2:
                    field = parts[0].strip()
                    value = parts[1].strip().strip('"\'')
                    return {"field": field, "operator": op, "value": value}

        return None

    def _apply_filters(self, attacks: List[dict], conditions: List[dict]) -> List[dict]:
        """Apply filter conditions to attacks"""
        if not conditions:
            return attacks

        results = []

        for attack in attacks:
            match = True
            last_logical_op = "AND"

            for i, cond in enumerate(conditions):
                cond_match = self._evaluate_condition(attack, cond)

                if i == 0:
                    match = cond_match
                elif cond.get("logical_op") == "OR":
                    match = match or cond_match
                else:  # AND
                    match = match and cond_match

            if match:
                results.append(attack)

        return results

    def _evaluate_condition(self, attack: dict, condition: dict) -> bool:
        """Evaluate a single condition against an attack"""
        field = condition["field"]
        op = condition["operator"]
        value = condition["value"]

        # Get field value (supports nested like origin.country)
        actual_value = self._get_field_value(attack, field)

        if actual_value is None:
            return False

        # Convert value types
        if isinstance(actual_value, (int, float)) and isinstance(value, str):
            try:
                value = float(value)
            except:
                pass

        # Evaluate
        if op == "IN":
            return str(actual_value) in [str(v) for v in value]
        elif op == "LIKE":
            return bool(re.match(value, str(actual_value), re.IGNORECASE))
        elif op in self.OPERATORS:
            try:
                return self.OPERATORS[op](actual_value, value)
            except:
                return str(actual_value) == str(value)

        return False

    def _get_field_value(self, attack: dict, field: str) -> Any:
        """Get value from attack dict, supporting nested fields"""
        parts = field.split('.')
        value = attack

        for part in parts:
            if isinstance(value, dict):
                value = value.get(part)
            else:
                return None

        return value

    def _apply_order(self, results: List[dict], field: str, direction: str) -> List[dict]:
        """Apply ORDER BY to results"""
        reverse = direction.upper() == "DESC"

        return sorted(
            results,
            key=lambda x: self._get_field_value(x, field) or "",
            reverse=reverse
        )

    def save_query(self, query_id: str, name: str, query: str, description: str = "", created_by: str = "user") -> SavedQuery:
        """Save a query"""
        saved = SavedQuery(
            id=query_id,
            name=name,
            query=query,
            description=description,
            created_by=created_by,
            created_at=datetime.utcnow().isoformat() + "Z"
        )
        self.saved_queries[query_id] = saved
        return saved

    def delete_query(self, query_id: str) -> bool:
        """Delete a saved query"""
        if query_id in self.saved_queries:
            del self.saved_queries[query_id]
            return True
        return False

    def get_saved_queries(self) -> List[dict]:
        """Get all saved queries"""
        return [
            {
                "id": q.id,
                "name": q.name,
                "query": q.query,
                "description": q.description,
                "created_by": q.created_by,
                "created_at": q.created_at,
                "run_count": q.run_count,
                "last_run": q.last_run
            }
            for q in self.saved_queries.values()
        ]

    def run_saved_query(self, query_id: str, attacks: List[dict]) -> dict:
        """Run a saved query"""
        if query_id not in self.saved_queries:
            return {"success": False, "error": "Query not found"}

        saved = self.saved_queries[query_id]
        saved.run_count += 1
        saved.last_run = datetime.utcnow().isoformat() + "Z"

        return self.execute(saved.query, attacks)

    def get_query_history(self) -> List[dict]:
        """Get recent query history"""
        return list(reversed(self.query_history))

    def get_query_suggestions(self, partial: str) -> List[str]:
        """Get query suggestions based on partial input"""
        suggestions = []

        # Field suggestions
        fields = ["type", "severity", "origin.country", "origin.ip", "origin.city",
                  "target.country", "target.ip", "timestamp", "source"]

        for field in fields:
            if field.startswith(partial.lower()):
                suggestions.append(field)

        # Value suggestions
        if "type" in partial.lower():
            types = ["DDoS", "Malware", "Botnet", "Brute Force", "SQL Injection",
                     "XSS", "Phishing", "Ransomware", "APT", "Scanner"]
            suggestions.extend([f'type = "{t}"' for t in types])

        if "severity" in partial.lower():
            suggestions.extend([f'severity = "{s}"' for s in ["critical", "high", "medium", "low"]])

        return suggestions[:10]
