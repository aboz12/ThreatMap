"""
Report Generation for Threat Map
Generate PDF, HTML, and CSV reports
"""

import json
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from dataclasses import dataclass
import html
import csv
import io


@dataclass
class ReportConfig:
    """Report configuration"""
    id: str
    name: str
    report_type: str  # daily, weekly, monthly, custom
    format: str  # html, pdf, csv, json
    sections: List[str]
    schedule: Optional[str] = None  # cron expression
    recipients: List[str] = None
    last_generated: Optional[str] = None


class ReportGenerator:
    """Generates threat reports"""

    def __init__(self):
        self.configs: Dict[str, ReportConfig] = {}
        self.generated_reports: List[dict] = []

    def generate_report(
        self,
        attacks: List[dict],
        stats: dict,
        format: str = "html",
        title: str = "Threat Intelligence Report",
        period: str = "Last 24 Hours",
        include_sections: List[str] = None
    ) -> dict:
        """Generate a comprehensive report"""

        sections = include_sections or [
            "executive_summary",
            "attack_statistics",
            "top_attackers",
            "geographic_analysis",
            "attack_types",
            "severity_breakdown",
            "timeline",
            "recommendations"
        ]

        report_data = self._gather_report_data(attacks, stats, sections)
        report_data["title"] = title
        report_data["period"] = period
        report_data["generated_at"] = datetime.utcnow().isoformat() + "Z"

        if format == "html":
            content = self._generate_html(report_data)
            mime_type = "text/html"
        elif format == "csv":
            content = self._generate_csv(attacks)
            mime_type = "text/csv"
        elif format == "json":
            content = json.dumps(report_data, indent=2)
            mime_type = "application/json"
        else:
            content = self._generate_html(report_data)
            mime_type = "text/html"

        report = {
            "title": title,
            "format": format,
            "mime_type": mime_type,
            "content": content,
            "generated_at": report_data["generated_at"],
            "attack_count": len(attacks),
            "period": period
        }

        self.generated_reports.append({
            "title": title,
            "format": format,
            "generated_at": report_data["generated_at"],
            "attack_count": len(attacks)
        })

        if len(self.generated_reports) > 100:
            self.generated_reports = self.generated_reports[-50:]

        return report

    def _gather_report_data(self, attacks: List[dict], stats: dict, sections: List[str]) -> dict:
        """Gather data for report sections"""
        data = {}

        if "executive_summary" in sections:
            data["executive_summary"] = self._generate_executive_summary(attacks, stats)

        if "attack_statistics" in sections:
            data["attack_statistics"] = {
                "total_attacks": len(attacks),
                "by_type": stats.get("attacks_by_type", {}),
                "by_severity": self._count_by_field(attacks, "severity")
            }

        if "top_attackers" in sections:
            data["top_attackers"] = self._get_top_attackers(attacks, limit=20)

        if "geographic_analysis" in sections:
            data["geographic_analysis"] = {
                "by_country": self._count_by_field(attacks, "origin.country"),
                "top_cities": self._count_by_field(attacks, "origin.city")
            }

        if "attack_types" in sections:
            data["attack_types"] = self._analyze_attack_types(attacks)

        if "severity_breakdown" in sections:
            data["severity_breakdown"] = self._count_by_field(attacks, "severity")

        if "timeline" in sections:
            data["timeline"] = self._generate_timeline(attacks)

        if "recommendations" in sections:
            data["recommendations"] = self._generate_recommendations(attacks, stats)

        return data

    def _generate_executive_summary(self, attacks: List[dict], stats: dict) -> dict:
        """Generate executive summary"""
        total = len(attacks)
        critical = len([a for a in attacks if a.get("severity") == "critical"])
        high = len([a for a in attacks if a.get("severity") == "high"])

        # Get top threat
        types = self._count_by_field(attacks, "type")
        top_type = max(types.items(), key=lambda x: x[1])[0] if types else "Unknown"

        # Get top source country
        countries = self._count_by_field(attacks, "origin.country")
        top_country = max(countries.items(), key=lambda x: x[1])[0] if countries else "Unknown"

        return {
            "total_attacks": total,
            "critical_attacks": critical,
            "high_attacks": high,
            "risk_level": "High" if critical > 10 or (critical + high) > total * 0.3 else "Medium" if high > 10 else "Low",
            "top_threat_type": top_type,
            "top_source_country": top_country,
            "key_findings": [
                f"Detected {total} attacks during the reporting period",
                f"{critical} critical and {high} high severity attacks",
                f"Most common attack type: {top_type}",
                f"Primary source country: {top_country}"
            ]
        }

    def _count_by_field(self, attacks: List[dict], field: str) -> Dict[str, int]:
        """Count attacks by field value"""
        counts = {}
        for attack in attacks:
            # Handle nested fields
            parts = field.split(".")
            value = attack
            for part in parts:
                if isinstance(value, dict):
                    value = value.get(part, "Unknown")
                else:
                    value = "Unknown"
                    break

            value = str(value)
            counts[value] = counts.get(value, 0) + 1

        return dict(sorted(counts.items(), key=lambda x: x[1], reverse=True))

    def _get_top_attackers(self, attacks: List[dict], limit: int = 20) -> List[dict]:
        """Get top attacking IPs"""
        ip_counts = {}
        ip_info = {}

        for attack in attacks:
            ip = attack.get("origin", {}).get("ip", "unknown")
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
            if ip not in ip_info:
                ip_info[ip] = {
                    "country": attack.get("origin", {}).get("country", "Unknown"),
                    "city": attack.get("origin", {}).get("city", "Unknown"),
                    "types": set()
                }
            ip_info[ip]["types"].add(attack.get("type", "Unknown"))

        sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:limit]

        return [
            {
                "ip": ip,
                "count": count,
                "country": ip_info[ip]["country"],
                "city": ip_info[ip]["city"],
                "attack_types": list(ip_info[ip]["types"])
            }
            for ip, count in sorted_ips
        ]

    def _analyze_attack_types(self, attacks: List[dict]) -> List[dict]:
        """Analyze attack types"""
        type_data = {}

        for attack in attacks:
            attack_type = attack.get("type", "Unknown")
            if attack_type not in type_data:
                type_data[attack_type] = {
                    "count": 0,
                    "severities": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                    "countries": set()
                }

            type_data[attack_type]["count"] += 1
            severity = attack.get("severity", "medium")
            type_data[attack_type]["severities"][severity] = type_data[attack_type]["severities"].get(severity, 0) + 1
            type_data[attack_type]["countries"].add(attack.get("origin", {}).get("country", "Unknown"))

        return [
            {
                "type": t,
                "count": d["count"],
                "severities": d["severities"],
                "unique_countries": len(d["countries"])
            }
            for t, d in sorted(type_data.items(), key=lambda x: x[1]["count"], reverse=True)
        ]

    def _generate_timeline(self, attacks: List[dict]) -> List[dict]:
        """Generate hourly timeline"""
        hourly = {}

        for attack in attacks:
            try:
                ts = attack.get("timestamp", "")
                if ts:
                    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    hour_key = dt.strftime("%Y-%m-%d %H:00")
                    hourly[hour_key] = hourly.get(hour_key, 0) + 1
            except:
                pass

        return [
            {"hour": h, "count": c}
            for h, c in sorted(hourly.items())
        ]

    def _generate_recommendations(self, attacks: List[dict], stats: dict) -> List[str]:
        """Generate security recommendations"""
        recommendations = []

        types = self._count_by_field(attacks, "type")
        countries = self._count_by_field(attacks, "origin.country")
        severities = self._count_by_field(attacks, "severity")

        # Type-based recommendations
        if types.get("DDoS", 0) > 10:
            recommendations.append("Implement DDoS mitigation services (Cloudflare, AWS Shield)")

        if types.get("Brute Force", 0) > 10:
            recommendations.append("Enable account lockout policies and implement MFA")

        if types.get("SQL Injection", 0) > 5:
            recommendations.append("Review web application security; implement WAF rules")

        if types.get("Malware", 0) > 10:
            recommendations.append("Update antivirus signatures; review email filtering")

        if types.get("Ransomware", 0) > 0:
            recommendations.append("CRITICAL: Verify backup integrity; isolate affected systems")

        # Country-based recommendations
        high_risk = ["Russia", "China", "North Korea", "Iran"]
        for country in high_risk:
            if countries.get(country, 0) > 20:
                recommendations.append(f"Consider geoblocking traffic from {country}")

        # Severity-based recommendations
        if severities.get("critical", 0) > 5:
            recommendations.append("URGENT: Investigate critical severity attacks immediately")

        # Generic recommendations
        recommendations.extend([
            "Review and update firewall rules",
            "Ensure all systems are patched to latest versions",
            "Conduct security awareness training for staff"
        ])

        return recommendations[:10]

    def _generate_html(self, data: dict) -> str:
        """Generate HTML report"""
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>{html.escape(data.get('title', 'Threat Report'))}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #1a1a2e;
            color: #eee;
        }}
        h1 {{ color: #00ff88; border-bottom: 2px solid #00ff88; padding-bottom: 10px; }}
        h2 {{ color: #00aaff; margin-top: 30px; }}
        .header {{ text-align: center; margin-bottom: 40px; }}
        .meta {{ color: #888; font-size: 14px; }}
        .card {{
            background: #16213e;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
            border: 1px solid #0f3460;
        }}
        .stat-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
        }}
        .stat-box {{
            background: #0f3460;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }}
        .stat-value {{ font-size: 32px; font-weight: bold; color: #00ff88; }}
        .stat-label {{ color: #888; margin-top: 5px; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #0f3460;
        }}
        th {{ background: #0f3460; color: #00aaff; }}
        tr:hover {{ background: #1a1a3e; }}
        .severity-critical {{ color: #ff4444; }}
        .severity-high {{ color: #ff8800; }}
        .severity-medium {{ color: #ffff00; }}
        .severity-low {{ color: #00ff00; }}
        .recommendation {{
            background: #0f3460;
            padding: 10px 15px;
            margin: 10px 0;
            border-left: 4px solid #00aaff;
            border-radius: 4px;
        }}
        .risk-high {{ color: #ff4444; }}
        .risk-medium {{ color: #ffff00; }}
        .risk-low {{ color: #00ff00; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>{html.escape(data.get('title', 'Threat Intelligence Report'))}</h1>
        <div class="meta">
            Period: {html.escape(data.get('period', 'Unknown'))} |
            Generated: {data.get('generated_at', '')}
        </div>
    </div>
"""

        # Executive Summary
        if "executive_summary" in data:
            summary = data["executive_summary"]
            risk_class = f"risk-{summary.get('risk_level', 'medium').lower()}"
            html_content += f"""
    <div class="card">
        <h2>Executive Summary</h2>
        <div class="stat-grid">
            <div class="stat-box">
                <div class="stat-value">{summary.get('total_attacks', 0)}</div>
                <div class="stat-label">Total Attacks</div>
            </div>
            <div class="stat-box">
                <div class="stat-value severity-critical">{summary.get('critical_attacks', 0)}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-box">
                <div class="stat-value severity-high">{summary.get('high_attacks', 0)}</div>
                <div class="stat-label">High Severity</div>
            </div>
            <div class="stat-box">
                <div class="stat-value {risk_class}">{summary.get('risk_level', 'Unknown')}</div>
                <div class="stat-label">Risk Level</div>
            </div>
        </div>
        <h3>Key Findings</h3>
        <ul>
"""
            for finding in summary.get("key_findings", []):
                html_content += f"            <li>{html.escape(finding)}</li>\n"

            html_content += """        </ul>
    </div>
"""

        # Top Attackers
        if "top_attackers" in data:
            html_content += """
    <div class="card">
        <h2>Top Attacking IPs</h2>
        <table>
            <tr><th>IP Address</th><th>Country</th><th>Attack Count</th><th>Attack Types</th></tr>
"""
            for attacker in data["top_attackers"][:15]:
                types_str = ", ".join(attacker.get("attack_types", [])[:3])
                html_content += f"""            <tr>
                <td>{html.escape(attacker.get('ip', ''))}</td>
                <td>{html.escape(attacker.get('country', ''))}</td>
                <td>{attacker.get('count', 0)}</td>
                <td>{html.escape(types_str)}</td>
            </tr>
"""
            html_content += """        </table>
    </div>
"""

        # Attack Types
        if "attack_types" in data:
            html_content += """
    <div class="card">
        <h2>Attack Types Analysis</h2>
        <table>
            <tr><th>Type</th><th>Count</th><th>Critical</th><th>High</th><th>Countries</th></tr>
"""
            for at in data["attack_types"][:10]:
                html_content += f"""            <tr>
                <td>{html.escape(at.get('type', ''))}</td>
                <td>{at.get('count', 0)}</td>
                <td class="severity-critical">{at.get('severities', {}).get('critical', 0)}</td>
                <td class="severity-high">{at.get('severities', {}).get('high', 0)}</td>
                <td>{at.get('unique_countries', 0)}</td>
            </tr>
"""
            html_content += """        </table>
    </div>
"""

        # Recommendations
        if "recommendations" in data:
            html_content += """
    <div class="card">
        <h2>Security Recommendations</h2>
"""
            for i, rec in enumerate(data["recommendations"], 1):
                html_content += f"""        <div class="recommendation">{i}. {html.escape(rec)}</div>
"""
            html_content += """    </div>
"""

        html_content += """
    <div class="meta" style="text-align: center; margin-top: 40px;">
        Generated by ThreatMap Intelligence Platform
    </div>
</body>
</html>"""

        return html_content

    def _generate_csv(self, attacks: List[dict]) -> str:
        """Generate CSV report of attacks"""
        output = io.StringIO()
        writer = csv.writer(output)

        # Header
        writer.writerow([
            "Timestamp", "Type", "Severity", "Source IP", "Source Country",
            "Source City", "Target IP", "Target Country", "Source"
        ])

        # Data
        for attack in attacks:
            origin = attack.get("origin", {})
            target = attack.get("target", {})
            writer.writerow([
                attack.get("timestamp", ""),
                attack.get("type", ""),
                attack.get("severity", ""),
                origin.get("ip", ""),
                origin.get("country", ""),
                origin.get("city", ""),
                target.get("ip", ""),
                target.get("country", ""),
                attack.get("source", "")
            ])

        return output.getvalue()

    def get_report_history(self) -> List[dict]:
        """Get report generation history"""
        return list(reversed(self.generated_reports))

    def schedule_report(self, config: ReportConfig) -> str:
        """Schedule a report"""
        self.configs[config.id] = config
        return config.id
