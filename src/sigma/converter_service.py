"""Sigma to SPL conversion service."""
import re
import yaml
from typing import Dict, Any, List, Optional, Tuple

from .schemas import (
    MappingStatusEnum,
    PrerequisiteInfo,
    RequiredLogSource,
    GapItem,
    HealthCheck,
    MappingResult,
)


class ConverterService:
    """Service for converting between Sigma and SPL formats."""

    # Default field mappings for common Sigma fields
    DEFAULT_MAPPINGS = {
        # Process fields
        "CommandLine": "CommandLine",
        "Image": "Image",
        "ParentImage": "ParentImage",
        "ParentCommandLine": "ParentCommandLine",
        "User": "User",
        "IntegrityLevel": "IntegrityLevel",
        "CurrentDirectory": "CurrentDirectory",
        "ProcessId": "ProcessId",
        "ParentProcessId": "ParentProcessId",
        "OriginalFileName": "OriginalFileName",
        "Hashes": "Hashes",
        "Company": "Company",
        "Description": "Description",
        "Product": "Product",
        "FileVersion": "FileVersion",
        # File fields
        "TargetFilename": "TargetFilename",
        "SourceFilename": "SourceFilename",
        "CreationUtcTime": "CreationUtcTime",
        # Network fields
        "DestinationIp": "DestinationIp",
        "DestinationPort": "DestinationPort",
        "SourceIp": "SourceIp",
        "SourcePort": "SourcePort",
        "DestinationHostname": "DestinationHostname",
        "Protocol": "Protocol",
        # Registry fields
        "TargetObject": "TargetObject",
        "Details": "Details",
        "EventType": "EventType",
        # DNS fields
        "QueryName": "QueryName",
        "QueryResults": "QueryResults",
        # PowerShell fields
        "ScriptBlockText": "ScriptBlockText",
        "EngineVersion": "EngineVersion",
        "HostApplication": "HostApplication",
        # Security fields
        "TargetUserName": "TargetUserName",
        "TargetDomainName": "TargetDomainName",
        "SubjectUserName": "SubjectUserName",
        "SubjectDomainName": "SubjectDomainName",
        "LogonType": "LogonType",
        "IpAddress": "IpAddress",
        "WorkstationName": "WorkstationName",
        # Generic
        "EventID": "EventCode",
        "Channel": "Channel",
        "Provider_Name": "SourceName",
    }

    # CIM field mappings
    CIM_MAPPINGS = {
        "CommandLine": "process_command_line",
        "Image": "process_path",
        "ParentImage": "parent_process_path",
        "ParentCommandLine": "parent_process_command_line",
        "User": "user",
        "ProcessId": "process_id",
        "ParentProcessId": "parent_process_id",
        "TargetFilename": "file_path",
        "DestinationIp": "dest_ip",
        "DestinationPort": "dest_port",
        "SourceIp": "src_ip",
        "SourcePort": "src_port",
        "TargetUserName": "user",
        "IpAddress": "src_ip",
    }

    # Logsource to index/sourcetype mapping
    LOGSOURCE_MAPPING = {
        # Windows Services
        ("windows", "sysmon", None): {
            "index": "windows",
            "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
        },
        ("windows", "security", None): {
            "index": "windows",
            "sourcetype": "XmlWinEventLog:Security",
        },
        ("windows", "system", None): {
            "index": "windows",
            "sourcetype": "XmlWinEventLog:System",
        },
        ("windows", "powershell", None): {
            "index": "windows",
            "sourcetype": "XmlWinEventLog:Microsoft-Windows-PowerShell/Operational",
        },
        ("windows", "powershell-classic", None): {
            "index": "windows",
            "sourcetype": "XmlWinEventLog:Windows PowerShell",
        },
        ("windows", "windefend", None): {
            "index": "windows",
            "sourcetype": "XmlWinEventLog:Microsoft-Windows-Windows Defender/Operational",
        },
        ("windows", "firewall-as", None): {
            "index": "windows",
            "sourcetype": "XmlWinEventLog:Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
        },
        ("windows", "bits-client", None): {
            "index": "windows",
            "sourcetype": "XmlWinEventLog:Microsoft-Windows-Bits-Client/Operational",
        },
        ("windows", "taskscheduler", None): {
            "index": "windows",
            "sourcetype": "XmlWinEventLog:Microsoft-Windows-TaskScheduler/Operational",
        },
        ("windows", "wmi", None): {
            "index": "windows",
            "sourcetype": "XmlWinEventLog:Microsoft-Windows-WMI-Activity/Operational",
        },
        ("windows", "dns-server", None): {
            "index": "windows",
            "sourcetype": "XmlWinEventLog:DNS Server",
        },
        ("windows", "applocker", None): {
            "index": "windows",
            "sourcetype": "XmlWinEventLog:Microsoft-Windows-AppLocker/EXE and DLL",
        },
        # Windows Categories (Sysmon-based)
        ("windows", None, "process_creation"): {
            "index": "windows",
            "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
            "eventcode": 1,
        },
        ("windows", None, "file_event"): {
            "index": "windows",
            "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
            "eventcode": 11,
        },
        ("windows", None, "file_creation"): {
            "index": "windows",
            "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
            "eventcode": 11,
        },
        ("windows", None, "file_delete"): {
            "index": "windows",
            "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
            "eventcode": 23,
        },
        ("windows", None, "network_connection"): {
            "index": "windows",
            "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
            "eventcode": 3,
        },
        ("windows", None, "registry_event"): {
            "index": "windows",
            "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
            "eventcode": "12 OR EventCode=13 OR EventCode=14",
        },
        ("windows", None, "registry_set"): {
            "index": "windows",
            "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
            "eventcode": 13,
        },
        ("windows", None, "registry_add"): {
            "index": "windows",
            "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
            "eventcode": 12,
        },
        ("windows", None, "registry_delete"): {
            "index": "windows",
            "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
            "eventcode": 12,
        },
        ("windows", None, "dns_query"): {
            "index": "windows",
            "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
            "eventcode": 22,
        },
        ("windows", None, "image_load"): {
            "index": "windows",
            "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
            "eventcode": 7,
        },
        ("windows", None, "driver_load"): {
            "index": "windows",
            "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
            "eventcode": 6,
        },
        ("windows", None, "pipe_created"): {
            "index": "windows",
            "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
            "eventcode": 17,
        },
        ("windows", None, "wmi_event"): {
            "index": "windows",
            "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
            "eventcode": "19 OR EventCode=20 OR EventCode=21",
        },
        ("windows", None, "create_remote_thread"): {
            "index": "windows",
            "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
            "eventcode": 8,
        },
        ("windows", None, "process_access"): {
            "index": "windows",
            "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
            "eventcode": 10,
        },
        # PowerShell categories
        ("windows", None, "ps_script"): {
            "index": "windows",
            "sourcetype": "XmlWinEventLog:Microsoft-Windows-PowerShell/Operational",
            "eventcode": 4104,
        },
        ("windows", None, "ps_module"): {
            "index": "windows",
            "sourcetype": "XmlWinEventLog:Microsoft-Windows-PowerShell/Operational",
            "eventcode": 4103,
        },
        ("windows", None, "ps_classic_start"): {
            "index": "windows",
            "sourcetype": "XmlWinEventLog:Windows PowerShell",
            "eventcode": 400,
        },
        ("windows", "powershell", "ps_script"): {
            "index": "windows",
            "sourcetype": "XmlWinEventLog:Microsoft-Windows-PowerShell/Operational",
            "eventcode": 4104,
        },
        ("windows", "powershell", "ps_module"): {
            "index": "windows",
            "sourcetype": "XmlWinEventLog:Microsoft-Windows-PowerShell/Operational",
            "eventcode": 4103,
        },
        # Linux
        ("linux", "syslog", None): {
            "index": "linux",
            "sourcetype": "syslog",
        },
        ("linux", "audit", None): {
            "index": "linux",
            "sourcetype": "linux:audit",
        },
        ("linux", None, "process_creation"): {
            "index": "linux",
            "sourcetype": "linux:audit",
        },
        ("linux", None, "file_event"): {
            "index": "linux",
            "sourcetype": "linux:audit",
        },
        ("linux", None, "network_connection"): {
            "index": "linux",
            "sourcetype": "linux:audit",
        },
    }

    # Event ID info for prerequisites
    EVENT_INFO = {
        1: {"name": "Process Creation", "source": "Sysmon"},
        2: {"name": "File Creation Time Changed", "source": "Sysmon"},
        3: {"name": "Network Connection", "source": "Sysmon"},
        5: {"name": "Process Terminated", "source": "Sysmon"},
        6: {"name": "Driver Loaded", "source": "Sysmon"},
        7: {"name": "Image Loaded", "source": "Sysmon"},
        8: {"name": "CreateRemoteThread", "source": "Sysmon"},
        9: {"name": "RawAccessRead", "source": "Sysmon"},
        10: {"name": "ProcessAccess", "source": "Sysmon"},
        11: {"name": "File Created", "source": "Sysmon"},
        12: {"name": "Registry Object Added/Deleted", "source": "Sysmon"},
        13: {"name": "Registry Value Set", "source": "Sysmon"},
        14: {"name": "Registry Key/Value Renamed", "source": "Sysmon"},
        15: {"name": "FileCreateStreamHash", "source": "Sysmon"},
        17: {"name": "PipeEvent Created", "source": "Sysmon"},
        18: {"name": "PipeEvent Connected", "source": "Sysmon"},
        19: {"name": "WMI Event Filter", "source": "Sysmon"},
        20: {"name": "WMI Event Consumer", "source": "Sysmon"},
        21: {"name": "WMI Consumer Binding", "source": "Sysmon"},
        22: {"name": "DNS Query", "source": "Sysmon"},
        23: {"name": "File Delete Archived", "source": "Sysmon"},
        24: {"name": "Clipboard Change", "source": "Sysmon"},
        25: {"name": "Process Tampering", "source": "Sysmon"},
        26: {"name": "File Delete Logged", "source": "Sysmon"},
        27: {"name": "File Block Executable", "source": "Sysmon"},
        28: {"name": "File Block Shredding", "source": "Sysmon"},
        29: {"name": "FileExecutableDetected", "source": "Sysmon"},
        4624: {"name": "Successful Logon", "source": "Security"},
        4625: {"name": "Failed Logon", "source": "Security"},
        4634: {"name": "Logoff", "source": "Security"},
        4648: {"name": "Explicit Credential Logon", "source": "Security"},
        4656: {"name": "Object Handle Requested", "source": "Security"},
        4657: {"name": "Registry Value Modified", "source": "Security"},
        4663: {"name": "Object Access Attempt", "source": "Security"},
        4672: {"name": "Special Privileges Assigned", "source": "Security"},
        4688: {"name": "Process Creation", "source": "Security"},
        4689: {"name": "Process Termination", "source": "Security"},
        4697: {"name": "Service Installed", "source": "Security"},
        4698: {"name": "Scheduled Task Created", "source": "Security"},
        4699: {"name": "Scheduled Task Deleted", "source": "Security"},
        4700: {"name": "Scheduled Task Enabled", "source": "Security"},
        4701: {"name": "Scheduled Task Disabled", "source": "Security"},
        4702: {"name": "Scheduled Task Updated", "source": "Security"},
        4703: {"name": "Token Privileges Adjusted", "source": "Security"},
        4720: {"name": "User Account Created", "source": "Security"},
        4722: {"name": "User Account Enabled", "source": "Security"},
        4723: {"name": "Password Change Attempt", "source": "Security"},
        4724: {"name": "Password Reset Attempt", "source": "Security"},
        4725: {"name": "User Account Disabled", "source": "Security"},
        4726: {"name": "User Account Deleted", "source": "Security"},
        4728: {"name": "Member Added to Global Group", "source": "Security"},
        4732: {"name": "Member Added to Local Group", "source": "Security"},
        4738: {"name": "User Account Changed", "source": "Security"},
        4756: {"name": "Member Added to Universal Group", "source": "Security"},
        4768: {"name": "Kerberos TGT Request", "source": "Security"},
        4769: {"name": "Kerberos Service Ticket Request", "source": "Security"},
        4770: {"name": "Kerberos Service Ticket Renewed", "source": "Security"},
        4771: {"name": "Kerberos Pre-Auth Failed", "source": "Security"},
        4776: {"name": "NTLM Authentication", "source": "Security"},
        5140: {"name": "Network Share Access", "source": "Security"},
        5145: {"name": "Network Share Object Check", "source": "Security"},
        5156: {"name": "Windows Filtering Platform Connection", "source": "Security"},
        5157: {"name": "Windows Filtering Platform Block", "source": "Security"},
        # PowerShell
        4103: {"name": "Module Logging", "source": "PowerShell"},
        4104: {"name": "Script Block Logging", "source": "PowerShell"},
        # Windows Firewall
        2003: {"name": "Firewall Rule Added", "source": "Firewall"},
        2004: {"name": "Firewall Rule Modified", "source": "Firewall"},
        2005: {"name": "Firewall Rule Deleted", "source": "Firewall"},
        2006: {"name": "Firewall Rules Deleted", "source": "Firewall"},
    }

    # Detailed log source information
    LOG_SOURCE_INFO = {
        "sysmon": {
            "name": "Windows Sysmon",
            "description": "System Monitor - provides detailed information about process creations, network connections, file changes, registry modifications, and more",
            "windows_channel": "Microsoft-Windows-Sysmon/Operational",
            "splunk_sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
            "setup_instructions": [
                "Download Sysmon from Microsoft Sysinternals",
                "Install with a configuration file: sysmon64.exe -accepteula -i sysmonconfig.xml",
                "Use SwiftOnSecurity or Olaf Hartong's sysmon-modular config for comprehensive logging",
                "Ensure Splunk Universal Forwarder is configured to collect Sysmon events",
            ],
        },
        "security": {
            "name": "Windows Security",
            "description": "Windows Security Event Log - captures authentication, authorization, and audit events",
            "windows_channel": "Security",
            "splunk_sourcetype": "XmlWinEventLog:Security",
            "setup_instructions": [
                "Enable Advanced Audit Policy via GPO (Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy)",
                "Enable 'Audit Process Creation' for Event ID 4688",
                "Enable command line logging: GPO > Administrative Templates > System > Audit Process Creation > Include command line",
                "Configure Splunk to collect Security event log",
            ],
        },
        "powershell": {
            "name": "Windows PowerShell",
            "description": "PowerShell operational and script block logging for detecting malicious script execution",
            "windows_channel": "Microsoft-Windows-PowerShell/Operational",
            "splunk_sourcetype": "XmlWinEventLog:Microsoft-Windows-PowerShell/Operational",
            "setup_instructions": [
                "Enable Module Logging: GPO > Administrative Templates > Windows Components > Windows PowerShell > Turn on Module Logging",
                "Enable Script Block Logging: GPO > Administrative Templates > Windows Components > Windows PowerShell > Turn on Script Block Logging",
                "Enable Transcription (optional): Turn on PowerShell Transcription for full session logs",
                "Ensure PowerShell v5+ is installed for enhanced logging",
            ],
        },
        "system": {
            "name": "Windows System",
            "description": "Windows System Event Log - captures system-level events including services, drivers, and hardware",
            "windows_channel": "System",
            "splunk_sourcetype": "XmlWinEventLog:System",
            "setup_instructions": [
                "System logging is enabled by default",
                "Configure Splunk Universal Forwarder to collect System event log",
            ],
        },
        "firewall": {
            "name": "Windows Firewall",
            "description": "Windows Firewall with Advanced Security logs - network connection filtering and rule changes",
            "windows_channel": "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
            "splunk_sourcetype": "XmlWinEventLog:Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
            "setup_instructions": [
                "Enable Windows Firewall logging via GPO or local policy",
                "Configure logging: Windows Firewall > Properties > Logging > Log dropped packets and/or successful connections",
                "Default log location: %systemroot%\\system32\\LogFiles\\Firewall\\pfirewall.log",
                "Configure Splunk to collect firewall events",
            ],
        },
        "defender": {
            "name": "Windows Defender",
            "description": "Windows Defender Antivirus events - malware detection, scan results, and protection status",
            "windows_channel": "Microsoft-Windows-Windows Defender/Operational",
            "splunk_sourcetype": "XmlWinEventLog:Microsoft-Windows-Windows Defender/Operational",
            "setup_instructions": [
                "Windows Defender logging is enabled by default when Defender is active",
                "Configure Splunk to collect Windows Defender event log",
            ],
        },
    }

    def __init__(self):
        self.default_mappings = self.DEFAULT_MAPPINGS.copy()
        self.cim_mappings = self.CIM_MAPPINGS.copy()

    def convert_sigma_to_spl(
        self,
        rule: Dict[str, Any],
        custom_mappings: Optional[Dict[str, str]] = None,
        use_cim: bool = False,
        index_override: Optional[str] = None,
        sourcetype_override: Optional[str] = None,
        time_range: Optional[str] = None,
    ) -> Tuple[str, List[MappingResult], PrerequisiteInfo, List[GapItem], List[HealthCheck]]:
        """
        Convert a Sigma rule to SPL query.

        Returns:
            Tuple of (spl_query, mappings, prerequisites, gaps, health_checks)
        """
        # Get base mappings
        if use_cim:
            field_mappings = {**self.default_mappings, **self.cim_mappings}
        else:
            field_mappings = self.default_mappings.copy()

        # Apply custom mappings
        if custom_mappings:
            field_mappings.update(custom_mappings)

        # Extract logsource info
        logsource = rule.get("logsource", {})
        product = logsource.get("product")
        service = logsource.get("service")
        category = logsource.get("category")

        # Determine index and sourcetype
        ls_key = (product, service, category)
        ls_fallback = (product, service, None)
        ls_category = (product, None, category)

        ls_info = (
            self.LOGSOURCE_MAPPING.get(ls_key)
            or self.LOGSOURCE_MAPPING.get(ls_fallback)
            or self.LOGSOURCE_MAPPING.get(ls_category)
            or {"index": "*", "sourcetype": "*"}
        )

        index = index_override or ls_info.get("index", "*")
        sourcetype = sourcetype_override or ls_info.get("sourcetype", "*")
        eventcode = ls_info.get("eventcode")

        # Build base search
        spl_parts = []
        spl_parts.append(f'index={index}')
        if sourcetype != "*":
            spl_parts.append(f'sourcetype="{sourcetype}"')
        if eventcode:
            spl_parts.append(f'EventCode={eventcode}')

        # Process detection
        detection = rule.get("detection", {})
        condition = detection.get("condition", "")

        # Track mappings and gaps
        mapping_results = []
        gaps = []
        used_fields = set()

        # Convert detection blocks to SPL
        where_clauses = []
        for block_name, block_value in detection.items():
            if block_name == "condition":
                continue

            if isinstance(block_value, dict):
                clause, fields = self._convert_selection_block(
                    block_value, field_mappings
                )
                if clause:
                    where_clauses.append((block_name, clause))
                used_fields.update(fields)
            elif isinstance(block_value, list):
                # Handle list of dicts (OR relationship between items)
                or_clauses = []
                for item in block_value:
                    if isinstance(item, dict):
                        clause, fields = self._convert_selection_block(
                            item, field_mappings
                        )
                        if clause:
                            or_clauses.append(clause)
                        used_fields.update(fields)
                    elif isinstance(item, str):
                        # Handle list of strings (simple values)
                        or_clauses.append(f'"{self._escape_spl_value(item)}"')
                if or_clauses:
                    combined = " OR ".join(f"({c})" for c in or_clauses)
                    where_clauses.append((block_name, combined))

        # Build the condition-based SPL
        spl = " ".join(spl_parts)

        # Process condition
        if where_clauses:
            condition_spl = self._process_condition(condition, where_clauses)
            if condition_spl:
                spl += f"\n| where {condition_spl}"

        # Add time range if specified
        if time_range:
            spl = f"{spl}\n| where _time >= relative_time(now(), \"{time_range}\")"

        # Generate mapping results
        for field in used_fields:
            target = field_mappings.get(field)
            if target and target != f"UNMAPPED_{field}":
                mapping_results.append(
                    MappingResult(
                        sigma_field=field,
                        target_field=target,
                        status=MappingStatusEnum.OK,
                    )
                )
            else:
                mapping_results.append(
                    MappingResult(
                        sigma_field=field,
                        target_field=None,
                        status=MappingStatusEnum.MISSING,
                    )
                )
                gaps.append(
                    GapItem(
                        field=field,
                        location="detection",
                        impact=f"Query will use placeholder UNMAPPED_{field}",
                        suggestions=[
                            "Map to existing field in your environment",
                            "Check if field exists with different name",
                            "Verify log source is correctly configured",
                        ],
                    )
                )

        # Generate prerequisites
        prerequisites = self._generate_prerequisites(rule, ls_info)

        # Generate health checks
        health_checks = self._generate_health_checks(
            index, sourcetype, eventcode, mapping_results, field_mappings
        )

        return spl, mapping_results, prerequisites, gaps, health_checks

    def _convert_selection_block(
        self, block: Dict[str, Any], field_mappings: Dict[str, str]
    ) -> Tuple[str, set]:
        """Convert a Sigma selection block to SPL WHERE clause."""
        conditions = []
        fields_used = set()

        for key, value in block.items():
            # Parse field name and modifiers
            parts = key.split("|")
            field_name = parts[0]
            modifiers = parts[1:] if len(parts) > 1 else []

            # Get mapped field name
            mapped_field = field_mappings.get(field_name, f"UNMAPPED_{field_name}")
            fields_used.add(field_name)

            # Convert value based on modifiers
            if isinstance(value, list):
                value_conditions = []
                for v in value:
                    cond = self._create_field_condition(mapped_field, v, modifiers)
                    if cond:
                        value_conditions.append(cond)
                if value_conditions:
                    conditions.append(f"({' OR '.join(value_conditions)})")
            else:
                cond = self._create_field_condition(mapped_field, value, modifiers)
                if cond:
                    conditions.append(cond)

        return " AND ".join(conditions), fields_used

    def _create_field_condition(
        self, field: str, value: Any, modifiers: List[str]
    ) -> Optional[str]:
        """Create a single field condition for SPL."""
        if value is None:
            return f'isnull({field})'

        # Handle modifiers
        is_contains = "contains" in modifiers
        is_startswith = "startswith" in modifiers
        is_endswith = "endswith" in modifiers
        is_re = "re" in modifiers
        is_cidr = "cidr" in modifiers

        # Case sensitivity
        case_insensitive = True  # Default for Sigma

        if isinstance(value, bool):
            return f'{field}={"true" if value else "false"}'
        elif isinstance(value, (int, float)):
            return f'{field}={value}'
        elif isinstance(value, str):
            # Escape special characters for SPL
            escaped = self._escape_spl_value(value)

            if is_re:
                return f'match({field}, "{escaped}")'
            elif is_cidr:
                return f'cidrmatch("{escaped}", {field})'
            elif is_contains:
                if case_insensitive:
                    return f'match({field}, "(?i).*{self._regex_escape(value)}.*")'
                return f'like({field}, "%{escaped}%")'
            elif is_startswith:
                if case_insensitive:
                    return f'match({field}, "(?i)^{self._regex_escape(value)}.*")'
                return f'like({field}, "{escaped}%")'
            elif is_endswith:
                if case_insensitive:
                    return f'match({field}, "(?i).*{self._regex_escape(value)}$")'
                return f'like({field}, "%{escaped}")'
            else:
                # Handle wildcards
                if "*" in value or "?" in value:
                    pattern = value.replace("*", ".*").replace("?", ".")
                    if case_insensitive:
                        return f'match({field}, "(?i){pattern}")'
                    return f'match({field}, "{pattern}")'
                else:
                    if case_insensitive:
                        return f'lower({field})=lower("{escaped}")'
                    return f'{field}="{escaped}"'

        return None

    def _escape_spl_value(self, value: str) -> str:
        """Escape special characters for SPL string values."""
        return value.replace("\\", "\\\\").replace('"', '\\"')

    def _regex_escape(self, value: str) -> str:
        """Escape special regex characters."""
        special_chars = r"\.^$*+?{}[]|()"
        for char in special_chars:
            value = value.replace(char, f"\\{char}")
        return value

    def _process_condition(
        self, condition: str, where_clauses: List[Tuple[str, str]]
    ) -> str:
        """Process Sigma condition into SPL WHERE clause."""
        if not condition or not where_clauses:
            return ""

        # Create mapping of block names to SPL
        block_map = {name: clause for name, clause in where_clauses}

        # Handle simple conditions
        if condition in block_map:
            return block_map[condition]

        # Process complex conditions
        result = condition

        # Replace block names with their SPL equivalents
        for name, clause in sorted(where_clauses, key=lambda x: -len(x[0])):
            # Use word boundaries to avoid partial replacements
            pattern = r'\b' + re.escape(name) + r'\b'
            result = re.sub(pattern, f"({clause})", result)

        # Convert Sigma operators to SPL
        result = re.sub(r'\band\b', 'AND', result, flags=re.IGNORECASE)
        result = re.sub(r'\bor\b', 'OR', result, flags=re.IGNORECASE)
        result = re.sub(r'\bnot\b', 'NOT', result, flags=re.IGNORECASE)

        # Handle 1/all of patterns
        result = re.sub(r'1 of (\w+)\*', r'(\1)', result)
        result = re.sub(r'all of (\w+)\*', r'(\1)', result)

        return result

    def _generate_prerequisites(
        self, rule: Dict[str, Any], ls_info: Dict[str, Any]
    ) -> PrerequisiteInfo:
        """Generate prerequisites information for a Sigma rule."""
        logsource = rule.get("logsource", {})
        product = logsource.get("product", "").lower()
        service = logsource.get("service", "")
        category = logsource.get("category", "")

        # Event IDs
        event_ids = []
        eventcode = ls_info.get("eventcode")
        if eventcode:
            if isinstance(eventcode, int):
                info = self.EVENT_INFO.get(eventcode, {})
                event_ids.append({
                    "id": eventcode,
                    "name": info.get("name", "Unknown"),
                    "source": info.get("source", "Unknown"),
                })
            elif isinstance(eventcode, str):
                # Parse multiple event codes
                codes = re.findall(r'\d+', str(eventcode))
                for code in codes:
                    code_int = int(code)
                    info = self.EVENT_INFO.get(code_int, {})
                    event_ids.append({
                        "id": code_int,
                        "name": info.get("name", "Unknown"),
                        "source": info.get("source", "Unknown"),
                    })

        # Channels
        channels = []
        if service == "sysmon":
            channels.append("Microsoft-Windows-Sysmon/Operational")
        elif service == "security":
            channels.append("Security")
        elif service == "system":
            channels.append("System")
        elif service == "powershell":
            channels.append("Microsoft-Windows-PowerShell/Operational")

        # Configuration requirements
        configuration = []
        if category == "process_creation":
            configuration.append("Enable command line logging (GPO required for EventID 4688)")
            configuration.append("Sysmon installed and configured (for EventID 1)")
        elif category == "network_connection":
            configuration.append("Sysmon with network logging enabled")
        elif category == "dns_query":
            configuration.append("Sysmon v10+ with DNS logging enabled")

        # Generate detailed required_logs
        required_logs = self._determine_required_logs(product, service, category, event_ids)

        return PrerequisiteInfo(
            log_source={
                "product": logsource.get("product", "unknown"),
                "service": logsource.get("service"),
                "category": logsource.get("category"),
            },
            required_logs=required_logs,
            event_ids=event_ids,
            channels=channels,
            configuration=configuration,
        )

    def _determine_required_logs(
        self,
        product: str,
        service: str,
        category: str,
        event_ids: List[Dict[str, Any]],
    ) -> List[RequiredLogSource]:
        """Determine which log sources are required based on the rule's logsource."""
        required_logs = []

        # Map category to typical log sources
        category_to_logsource = {
            "process_creation": ["sysmon", "security"],
            "file_event": ["sysmon"],
            "file_creation": ["sysmon"],
            "file_delete": ["sysmon"],
            "file_rename": ["sysmon"],
            "file_change": ["sysmon"],
            "network_connection": ["sysmon", "firewall"],
            "dns_query": ["sysmon"],
            "dns": ["sysmon"],
            "registry_event": ["sysmon"],
            "registry_set": ["sysmon"],
            "registry_add": ["sysmon"],
            "registry_delete": ["sysmon"],
            "image_load": ["sysmon"],
            "driver_load": ["sysmon"],
            "pipe_created": ["sysmon"],
            "wmi_event": ["sysmon"],
            "ps_script": ["powershell"],
            "ps_module": ["powershell"],
            "ps_classic_start": ["powershell"],
            "ps_classic_script": ["powershell"],
        }

        # Determine log sources from explicit service
        log_source_keys = []
        if service:
            log_source_keys.append(service.lower())
        elif category:
            log_source_keys.extend(category_to_logsource.get(category, []))

        # Also check event_ids to infer additional log sources
        for evt in event_ids:
            source = evt.get("source", "").lower()
            if source and source not in log_source_keys:
                log_source_keys.append(source)

        # Build RequiredLogSource objects
        for key in log_source_keys:
            log_info = self.LOG_SOURCE_INFO.get(key)
            if log_info:
                # Filter event_ids for this specific log source
                source_event_ids = [
                    evt for evt in event_ids
                    if evt.get("source", "").lower() == key or
                    (key == "sysmon" and evt.get("source") == "Sysmon") or
                    (key == "security" and evt.get("source") == "Security") or
                    (key == "powershell" and evt.get("source") == "PowerShell") or
                    (key == "firewall" and evt.get("source") == "Firewall")
                ]

                required_logs.append(RequiredLogSource(
                    name=log_info["name"],
                    description=log_info["description"],
                    windows_channel=log_info.get("windows_channel"),
                    splunk_sourcetype=log_info.get("splunk_sourcetype"),
                    event_ids=source_event_ids,
                    setup_instructions=log_info.get("setup_instructions", []),
                ))

        # If no specific logs found, provide a generic recommendation
        if not required_logs and product == "windows":
            # Default to Sysmon for Windows
            sysmon_info = self.LOG_SOURCE_INFO.get("sysmon")
            if sysmon_info:
                required_logs.append(RequiredLogSource(
                    name=sysmon_info["name"],
                    description=sysmon_info["description"],
                    windows_channel=sysmon_info.get("windows_channel"),
                    splunk_sourcetype=sysmon_info.get("splunk_sourcetype"),
                    event_ids=event_ids,
                    setup_instructions=sysmon_info.get("setup_instructions", []),
                ))

        return required_logs

    def _generate_health_checks(
        self,
        index: str,
        sourcetype: str,
        eventcode: Any,
        mappings: List[MappingResult],
        field_mappings: Dict[str, str],
    ) -> List[HealthCheck]:
        """Generate health check queries for the conversion."""
        health_checks = []

        # Check log source exists
        base_search = f'index={index}'
        if sourcetype != "*":
            base_search += f' sourcetype="{sourcetype}"'

        health_checks.append(
            HealthCheck(
                name="Log Source Exists",
                description="Verify that the log source is receiving data",
                query=f'{base_search} earliest=-1h | head 1 | stats count',
            )
        )

        # Check event code if specified
        if eventcode:
            health_checks.append(
                HealthCheck(
                    name=f"EventCode {eventcode} Present",
                    description="Verify that the required EventCode is being logged",
                    query=f'{base_search} EventCode={eventcode} earliest=-24h | stats count',
                )
            )

        # Check mapped fields exist
        for mapping in mappings:
            if mapping.status == MappingStatusEnum.OK and mapping.target_field:
                health_checks.append(
                    HealthCheck(
                        name=f'Field "{mapping.target_field}" Exists',
                        description=f"Verify that field {mapping.target_field} (mapped from {mapping.sigma_field}) exists",
                        query=f'{base_search} earliest=-1h | where isnotnull({mapping.target_field}) | head 1 | stats count',
                    )
                )

        return health_checks

    def reverse_spl_to_sigma(
        self,
        spl: str,
        title: str = "Custom Detection Rule",
        level: str = "medium",
        status: str = "experimental",
        author: Optional[str] = None,
        description: Optional[str] = None,
    ) -> Tuple[str, Optional[str]]:
        """
        Convert SPL query to Sigma rule (best effort).

        Returns:
            Tuple of (sigma_yaml, correlation_notes)
        """
        correlation_notes = None

        # Check for complex SPL features
        complex_features = []
        if re.search(r'\|\s*join\b', spl, re.IGNORECASE):
            complex_features.append("join command - correlation logic cannot be fully represented")
        if re.search(r'\|\s*transaction\b', spl, re.IGNORECASE):
            complex_features.append("transaction command - multi-event correlation")
        if re.search(r'\|\s*stats\b.*\bby\b', spl, re.IGNORECASE):
            complex_features.append("stats aggregation - converted to basic detection")
        if re.search(r'\|\s*lookup\b', spl, re.IGNORECASE):
            complex_features.append("lookup command - external data reference")

        if complex_features:
            correlation_notes = "Complex SPL features detected:\n" + "\n".join(
                f"- {f}" for f in complex_features
            )
            correlation_notes += "\n\nConsider using Sigma correlation rules for full functionality."

        # Parse index and sourcetype
        logsource = {"product": "windows"}

        index_match = re.search(r'index\s*=\s*(\S+)', spl)
        if index_match:
            index = index_match.group(1).strip('"\'')
            if "linux" in index.lower():
                logsource["product"] = "linux"

        sourcetype_match = re.search(r'sourcetype\s*=\s*["\']?([^"\'\s]+)', spl)
        if sourcetype_match:
            sourcetype = sourcetype_match.group(1).lower()
            if "sysmon" in sourcetype:
                logsource["service"] = "sysmon"
            elif "security" in sourcetype:
                logsource["service"] = "security"
            elif "powershell" in sourcetype:
                logsource["service"] = "powershell"

        # Parse EventCode
        eventcode_match = re.search(r'EventCode\s*=\s*(\d+)', spl, re.IGNORECASE)
        detection = {"selection": {}, "condition": "selection"}

        if eventcode_match:
            eventcode = int(eventcode_match.group(1))
            detection["selection"]["EventID"] = eventcode

            # Infer category from EventCode
            if eventcode == 1:
                logsource["category"] = "process_creation"
            elif eventcode == 3:
                logsource["category"] = "network_connection"
            elif eventcode == 11:
                logsource["category"] = "file_event"
            elif eventcode in [12, 13, 14]:
                logsource["category"] = "registry_event"
            elif eventcode == 22:
                logsource["category"] = "dns_query"
            elif eventcode == 4688:
                logsource["category"] = "process_creation"
                logsource["service"] = "security"

        # Parse field conditions from where clause
        where_matches = re.findall(
            r'(?:match|like)\s*\(\s*(\w+)\s*,\s*["\']([^"\']+)["\']',
            spl,
            re.IGNORECASE
        )
        for field, pattern in where_matches:
            # Clean up the pattern
            pattern = pattern.replace("(?i)", "").replace(".*", "*").replace(".", "?")
            pattern = pattern.strip("^$")
            if pattern:
                detection["selection"][f"{field}|contains"] = pattern

        # Parse simple equality conditions
        eq_matches = re.findall(r'(\w+)\s*=\s*["\']([^"\']+)["\']', spl)
        for field, value in eq_matches:
            if field.lower() not in ["index", "sourcetype", "eventcode"]:
                detection["selection"][field] = value

        # Parse NOT conditions for filter
        not_matches = re.findall(r'(\w+)\s*!=\s*["\']([^"\']+)["\']', spl)
        if not_matches:
            detection["filter"] = {}
            for field, value in not_matches:
                detection["filter"][field] = value
            detection["condition"] = "selection and not filter"

        # Build Sigma rule
        sigma_rule = {
            "title": title,
            "status": status,
            "description": description or "Auto-generated from SPL query",
            "author": author or "Sigma Translator",
            "logsource": logsource,
            "detection": detection,
            "level": level,
        }

        # Remove None values
        sigma_rule = {k: v for k, v in sigma_rule.items() if v is not None}

        # Generate YAML
        sigma_yaml = yaml.dump(sigma_rule, default_flow_style=False, sort_keys=False)

        return sigma_yaml, correlation_notes


# Singleton instance
converter_service = ConverterService()
