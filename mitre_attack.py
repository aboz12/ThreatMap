"""
MITRE ATT&CK Framework Mapping for Threat Map
Maps detected attacks to ATT&CK techniques and tactics
"""

from dataclasses import dataclass
from typing import List, Dict, Optional


@dataclass
class AttackTechnique:
    """MITRE ATT&CK Technique"""
    id: str
    name: str
    tactic: str
    description: str
    mitigations: List[str]
    detection: str
    url: str


# MITRE ATT&CK Technique Database (subset of common techniques)
ATTACK_TECHNIQUES: Dict[str, AttackTechnique] = {
    "T1190": AttackTechnique(
        id="T1190",
        name="Exploit Public-Facing Application",
        tactic="Initial Access",
        description="Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network.",
        mitigations=["Application Isolation", "Exploit Protection", "Network Segmentation", "Update Software", "Vulnerability Scanning"],
        detection="Monitor application logs for abnormal behavior. Use web application firewalls.",
        url="https://attack.mitre.org/techniques/T1190"
    ),
    "T1110": AttackTechnique(
        id="T1110",
        name="Brute Force",
        tactic="Credential Access",
        description="Adversaries may use brute force techniques to gain access to accounts when passwords are unknown.",
        mitigations=["Account Lockout Policies", "Multi-factor Authentication", "Password Policies"],
        detection="Monitor authentication logs for repeated failed attempts.",
        url="https://attack.mitre.org/techniques/T1110"
    ),
    "T1498": AttackTechnique(
        id="T1498",
        name="Network Denial of Service",
        tactic="Impact",
        description="Adversaries may perform Network Denial of Service (DoS) attacks to degrade or block the availability of targeted resources.",
        mitigations=["Filter Network Traffic", "Use DDoS Protection Services"],
        detection="Monitor network traffic for unusual volume or patterns.",
        url="https://attack.mitre.org/techniques/T1498"
    ),
    "T1059": AttackTechnique(
        id="T1059",
        name="Command and Scripting Interpreter",
        tactic="Execution",
        description="Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
        mitigations=["Antivirus/Antimalware", "Code Signing", "Disable or Remove Feature", "Execution Prevention"],
        detection="Monitor command-line arguments and script execution.",
        url="https://attack.mitre.org/techniques/T1059"
    ),
    "T1071": AttackTechnique(
        id="T1071",
        name="Application Layer Protocol",
        tactic="Command and Control",
        description="Adversaries may communicate using OSI application layer protocols to avoid detection.",
        mitigations=["Network Intrusion Prevention", "Network Segmentation"],
        detection="Analyze network data for uncommon data flows.",
        url="https://attack.mitre.org/techniques/T1071"
    ),
    "T1486": AttackTechnique(
        id="T1486",
        name="Data Encrypted for Impact",
        tactic="Impact",
        description="Adversaries may encrypt data on target systems to interrupt availability (ransomware).",
        mitigations=["Data Backup", "Behavior Prevention on Endpoint"],
        detection="Monitor for file modifications and encryption operations.",
        url="https://attack.mitre.org/techniques/T1486"
    ),
    "T1566": AttackTechnique(
        id="T1566",
        name="Phishing",
        tactic="Initial Access",
        description="Adversaries may send phishing messages to gain access to victim systems.",
        mitigations=["User Training", "Antivirus/Antimalware", "Network Intrusion Prevention"],
        detection="Monitor for suspicious email attachments and links.",
        url="https://attack.mitre.org/techniques/T1566"
    ),
    "T1595": AttackTechnique(
        id="T1595",
        name="Active Scanning",
        tactic="Reconnaissance",
        description="Adversaries may scan victim infrastructure to gather information for targeting.",
        mitigations=["Pre-compromise mitigation is difficult"],
        detection="Monitor for suspicious network scanning activity.",
        url="https://attack.mitre.org/techniques/T1595"
    ),
    "T1592": AttackTechnique(
        id="T1592",
        name="Gather Victim Host Information",
        tactic="Reconnaissance",
        description="Adversaries may gather information about victim hosts for targeting.",
        mitigations=["Pre-compromise mitigation is difficult"],
        detection="Monitor for information gathering attempts.",
        url="https://attack.mitre.org/techniques/T1592"
    ),
    "T1078": AttackTechnique(
        id="T1078",
        name="Valid Accounts",
        tactic="Defense Evasion",
        description="Adversaries may obtain and abuse credentials of existing accounts.",
        mitigations=["Multi-factor Authentication", "Privileged Account Management", "User Account Management"],
        detection="Monitor for unusual account activity.",
        url="https://attack.mitre.org/techniques/T1078"
    ),
    "T1021": AttackTechnique(
        id="T1021",
        name="Remote Services",
        tactic="Lateral Movement",
        description="Adversaries may use valid accounts to log into remote services.",
        mitigations=["Multi-factor Authentication", "Network Segmentation", "User Account Management"],
        detection="Monitor for remote login events.",
        url="https://attack.mitre.org/techniques/T1021"
    ),
    "T1105": AttackTechnique(
        id="T1105",
        name="Ingress Tool Transfer",
        tactic="Command and Control",
        description="Adversaries may transfer tools or files from an external system into a compromised environment.",
        mitigations=["Network Intrusion Prevention", "Web Proxy"],
        detection="Monitor for unusual file downloads.",
        url="https://attack.mitre.org/techniques/T1105"
    ),
}

# Mapping from threat types to ATT&CK techniques
THREAT_TYPE_MAPPING: Dict[str, List[str]] = {
    "DDoS": ["T1498"],
    "Malware": ["T1059", "T1105", "T1071"],
    "Botnet": ["T1071", "T1059", "T1105"],
    "Brute Force": ["T1110", "T1078"],
    "SQL Injection": ["T1190"],
    "XSS": ["T1190"],
    "Phishing": ["T1566"],
    "Ransomware": ["T1486", "T1059"],
    "APT": ["T1595", "T1592", "T1190", "T1078", "T1021"],
    "Spam": ["T1566"],
    "Scanner": ["T1595", "T1592"],
    "Exploitation": ["T1190", "T1059"],
}

# Kill chain phases
KILL_CHAIN = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact"
]


class MitreMapper:
    """Maps attacks to MITRE ATT&CK framework"""

    def __init__(self):
        self.attack_counts: Dict[str, int] = {}
        self.tactic_counts: Dict[str, int] = {}

    def map_attack(self, attack: dict) -> dict:
        """Map a single attack to ATT&CK techniques"""
        attack_type = attack.get("type", "Unknown")
        technique_ids = THREAT_TYPE_MAPPING.get(attack_type, [])

        techniques = []
        tactics = set()

        for tid in technique_ids:
            if tid in ATTACK_TECHNIQUES:
                tech = ATTACK_TECHNIQUES[tid]
                techniques.append({
                    "id": tech.id,
                    "name": tech.name,
                    "tactic": tech.tactic,
                    "url": tech.url
                })
                tactics.add(tech.tactic)

                # Update counts
                self.attack_counts[tid] = self.attack_counts.get(tid, 0) + 1
                self.tactic_counts[tech.tactic] = self.tactic_counts.get(tech.tactic, 0) + 1

        # Determine kill chain position
        kill_chain_position = None
        for i, phase in enumerate(KILL_CHAIN):
            if phase in tactics:
                kill_chain_position = i
                break

        return {
            "attack_type": attack_type,
            "techniques": techniques,
            "tactics": list(tactics),
            "kill_chain_position": kill_chain_position,
            "kill_chain_phase": KILL_CHAIN[kill_chain_position] if kill_chain_position is not None else None
        }

    def get_technique_details(self, technique_id: str) -> Optional[dict]:
        """Get full details for a technique"""
        if technique_id not in ATTACK_TECHNIQUES:
            return None

        tech = ATTACK_TECHNIQUES[technique_id]
        return {
            "id": tech.id,
            "name": tech.name,
            "tactic": tech.tactic,
            "description": tech.description,
            "mitigations": tech.mitigations,
            "detection": tech.detection,
            "url": tech.url,
            "observed_count": self.attack_counts.get(technique_id, 0)
        }

    def get_all_techniques(self) -> List[dict]:
        """Get all techniques with observation counts"""
        return [
            {
                "id": tech.id,
                "name": tech.name,
                "tactic": tech.tactic,
                "description": tech.description[:100] + "..." if len(tech.description) > 100 else tech.description,
                "url": tech.url,
                "observed_count": self.attack_counts.get(tid, 0)
            }
            for tid, tech in ATTACK_TECHNIQUES.items()
        ]

    def get_tactic_summary(self) -> List[dict]:
        """Get summary by tactic"""
        return [
            {"tactic": tactic, "count": self.tactic_counts.get(tactic, 0)}
            for tactic in KILL_CHAIN
        ]

    def get_kill_chain_view(self) -> dict:
        """Get kill chain visualization data"""
        phases = []
        for i, phase in enumerate(KILL_CHAIN):
            techniques_in_phase = [
                {"id": tid, "name": tech.name, "count": self.attack_counts.get(tid, 0)}
                for tid, tech in ATTACK_TECHNIQUES.items()
                if tech.tactic == phase
            ]
            phases.append({
                "position": i,
                "phase": phase,
                "count": self.tactic_counts.get(phase, 0),
                "techniques": techniques_in_phase
            })
        return {"kill_chain": phases}

    def get_mitigations_for_attack(self, attack_type: str) -> List[dict]:
        """Get recommended mitigations for an attack type"""
        technique_ids = THREAT_TYPE_MAPPING.get(attack_type, [])

        all_mitigations = set()
        technique_mitigations = []

        for tid in technique_ids:
            if tid in ATTACK_TECHNIQUES:
                tech = ATTACK_TECHNIQUES[tid]
                for m in tech.mitigations:
                    all_mitigations.add(m)
                technique_mitigations.append({
                    "technique": tech.name,
                    "mitigations": tech.mitigations
                })

        return {
            "attack_type": attack_type,
            "all_mitigations": list(all_mitigations),
            "by_technique": technique_mitigations
        }

    def get_statistics(self) -> dict:
        """Get MITRE mapping statistics"""
        top_techniques = sorted(
            self.attack_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]

        top_tactics = sorted(
            self.tactic_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )

        return {
            "total_mapped_attacks": sum(self.attack_counts.values()),
            "unique_techniques_observed": len([t for t, c in self.attack_counts.items() if c > 0]),
            "unique_tactics_observed": len([t for t, c in self.tactic_counts.items() if c > 0]),
            "top_techniques": [
                {"id": tid, "name": ATTACK_TECHNIQUES[tid].name, "count": count}
                for tid, count in top_techniques if tid in ATTACK_TECHNIQUES
            ],
            "top_tactics": [{"tactic": t, "count": c} for t, c in top_tactics]
        }
