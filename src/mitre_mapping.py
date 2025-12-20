"""MITRE ATT&CK mapping utilities."""

from typing import Dict, List, Optional

# MITRE ATT&CK tactic to techniques mapping (subset for demonstration)
TACTIC_TECHNIQUES: Dict[str, List[str]] = {
    "initial-access": ["T1566", "T1190", "T1133", "T1078"],
    "execution": ["T1059", "T1106", "T1053", "T1203"],
    "persistence": ["T1053", "T1543", "T1547", "T1136"],
    "privilege-escalation": ["T1548", "T1134", "T1068", "T1078"],
    "defense-evasion": ["T1562", "T1070", "T1036", "T1027"],
    "credential-access": ["T1003", "T1110", "T1558", "T1212"],
    "discovery": ["T1087", "T1083", "T1046", "T1018"],
    "lateral-movement": ["T1021", "T1570", "T1534", "T1550"],
    "collection": ["T1560", "T1113", "T1005", "T1039"],
    "command-and-control": ["T1071", "T1573", "T1095", "T1105"],
    "exfiltration": ["T1041", "T1048", "T1567", "T1030"],
    "impact": ["T1486", "T1490", "T1485", "T1489"],
}

# Technique descriptions
TECHNIQUE_DESCRIPTIONS: Dict[str, str] = {
    "T1566": "Phishing",
    "T1059": "Command and Scripting Interpreter",
    "T1003": "OS Credential Dumping",
    "T1190": "Exploit Public-Facing Application",
    "T1133": "External Remote Services",
    "T1078": "Valid Accounts",
    "T1106": "Native API",
    "T1053": "Scheduled Task/Job",
    "T1203": "Exploitation for Client Execution",
    "T1543": "Create or Modify System Process",
    "T1547": "Boot or Logon Autostart Execution",
    "T1136": "Create Account",
    "T1548": "Abuse Elevation Control Mechanism",
    "T1134": "Access Token Manipulation",
    "T1068": "Exploitation for Privilege Escalation",
    "T1562": "Impair Defenses",
    "T1070": "Indicator Removal",
    "T1036": "Masquerading",
    "T1027": "Obfuscated Files or Information",
    "T1110": "Brute Force",
    "T1558": "Steal or Forge Kerberos Tickets",
    "T1212": "Exploitation for Credential Access",
    "T1087": "Account Discovery",
    "T1083": "File and Directory Discovery",
    "T1046": "Network Service Discovery",
    "T1018": "Remote System Discovery",
    "T1021": "Remote Services",
    "T1570": "Lateral Tool Transfer",
    "T1534": "Internal Spearphishing",
    "T1550": "Use Alternate Authentication Material",
    "T1560": "Archive Collected Data",
    "T1113": "Screen Capture",
    "T1005": "Data from Local System",
    "T1039": "Data from Network Shared Drive",
    "T1071": "Application Layer Protocol",
    "T1573": "Encrypted Channel",
    "T1095": "Non-Application Layer Protocol",
    "T1105": "Ingress Tool Transfer",
    "T1041": "Exfiltration Over C2 Channel",
    "T1048": "Exfiltration Over Alternative Protocol",
    "T1567": "Exfiltration Over Web Service",
    "T1030": "Data Transfer Size Limits",
    "T1486": "Data Encrypted for Impact",
    "T1490": "Inhibit System Recovery",
    "T1485": "Data Destruction",
    "T1489": "Service Stop",
}


class MitreMapper:
    """MITRE ATT&CK mapping utilities."""

    def __init__(self):
        """Initialize the mapper."""
        self.tactics = TACTIC_TECHNIQUES
        self.techniques = TECHNIQUE_DESCRIPTIONS

    def get_technique_name(self, technique_id: str) -> str:
        """Get the name of a technique.

        Args:
            technique_id: MITRE technique ID (e.g., T1566)

        Returns:
            Technique name or "Unknown" if not found
        """
        return self.techniques.get(technique_id, "Unknown")

    def get_techniques_by_tactic(self, tactic: str) -> List[str]:
        """Get all techniques for a given tactic.

        Args:
            tactic: Tactic name (e.g., initial-access)

        Returns:
            List of technique IDs
        """
        tactic_normalized = tactic.lower().replace(" ", "-")
        return self.tactics.get(tactic_normalized, [])

    def get_tactic_for_technique(self, technique_id: str) -> Optional[str]:
        """Get the primary tactic for a technique.

        Args:
            technique_id: MITRE technique ID

        Returns:
            Tactic name or None if not found
        """
        for tactic, techniques in self.tactics.items():
            if technique_id in techniques:
                return tactic
        return None

    def format_mitre_info(self, technique_id: str) -> str:
        """Format MITRE technique information for display.

        Args:
            technique_id: MITRE technique ID

        Returns:
            Formatted string with technique info
        """
        name = self.get_technique_name(technique_id)
        tactic = self.get_tactic_for_technique(technique_id)

        if tactic:
            return f"{technique_id} - {name} ({tactic})"
        else:
            return f"{technique_id} - {name}"

    def get_all_tactics(self) -> List[str]:
        """Get list of all available tactics.

        Returns:
            List of tactic names
        """
        return list(self.tactics.keys())

    def validate_technique_id(self, technique_id: str) -> bool:
        """Check if a technique ID is valid.

        Args:
            technique_id: Technique ID to validate

        Returns:
            True if valid, False otherwise
        """
        # Basic format check
        if not technique_id.startswith("T") or len(technique_id) < 5:
            return False

        # Check if it's in our database
        return technique_id in self.techniques

    def get_attack_url(self, technique_id: str) -> str:
        """Get the MITRE ATT&CK URL for a technique.

        Args:
            technique_id: MITRE technique ID

        Returns:
            URL to the technique page
        """
        return f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"
