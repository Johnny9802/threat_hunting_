#!/usr/bin/env python3
"""
Generate additional playbooks to reach 40 total.
Each playbook contains real, functional detection queries.
"""

import os
from pathlib import Path
from datetime import datetime

PLAYBOOKS_DIR = Path(__file__).parent.parent / "playbooks" / "techniques"

ADDITIONAL_PLAYBOOKS = [
    # === RESOURCE DEVELOPMENT ===
    {
        "id": "PB-T1583-001",
        "technique": "T1583",
        "tactic": "resource-development",
        "dir_name": "T1583-acquire-infrastructure",
        "name": "Acquire Infrastructure Detection",
        "description": "Detect use of newly acquired infrastructure for malicious purposes",
        "severity": "medium",
        "subtechniques": ["T1583.001", "T1583.003", "T1583.006"],
        "data_sources": ["DNS Logs", "Proxy Logs", "Threat Intelligence"],
        "hunt_hypothesis": """Adversaries acquire infrastructure including domains, servers, and web services before attacks.
Indicators include:
1. Newly registered domains (< 30 days old)
2. DNS lookups to suspicious TLDs
3. Connections to VPS/cloud providers from unusual endpoints
4. Look-alike domains targeting the organization""",
        "investigation_steps": [
            "Query domain registration date (WHOIS)",
            "Check domain reputation across threat intel feeds",
            "Analyze DNS resolution patterns",
            "Look for typosquatting attempts against company domains",
            "Review any downloaded content from suspicious domains"
        ],
        "false_positives": ["New legitimate business domains", "Marketing campaign domains", "Cloud service providers"],
        "tags": ["resource-development", "infrastructure", "domain", "dns"],
        "splunk": """index=dns OR index=proxy
| lookup domain_age_lookup domain AS query OUTPUT registration_date, domain_age_days
| where domain_age_days < 30 OR isnull(domain_age_days)
| rex field=query "(?<tld>\.[a-z]{2,})$"
| search tld IN (".xyz", ".top", ".club", ".work", ".click", ".loan", ".online")
| stats count dc(src_ip) as unique_clients by query, tld
| where count > 5""",
        "elastic": """dns.question.name:* AND
(dns.question.name:*.xyz OR dns.question.name:*.top OR dns.question.name:*.click)
| stats count() by dns.question.name, source.ip
| where count > 5""",
        "sigma": """title: Connection to Newly Registered Domain
id: a2345678-bcde-2345-6789-bcdef234567a
status: production
level: medium
logsource:
    category: dns
detection:
    selection:
        query|endswith:
            - '.xyz'
            - '.top'
            - '.club'
            - '.click'
            - '.online'
    condition: selection
tags:
    - attack.resource_development
    - attack.t1583"""
    },

    # === EXECUTION - Additional ===
    {
        "id": "PB-T1106-001",
        "technique": "T1106",
        "tactic": "execution",
        "dir_name": "T1106-native-api",
        "name": "Suspicious Native API Execution Detection",
        "description": "Detect malicious use of Windows Native API calls for code execution",
        "severity": "high",
        "subtechniques": [],
        "data_sources": ["Process Creation", "API Monitoring", "Sysmon"],
        "hunt_hypothesis": """Adversaries use Windows Native API (ntdll.dll) to bypass security controls.
Common abuse includes:
1. NtCreateProcess/NtCreateThreadEx for process hollowing
2. NtAllocateVirtualMemory for shellcode injection
3. NtWriteVirtualMemory for code injection
4. Direct syscalls to evade EDR hooks""",
        "investigation_steps": [
            "Analyze parent-child process relationships",
            "Check for memory allocation patterns",
            "Review process command lines",
            "Correlate with network connections",
            "Look for unsigned binaries making API calls"
        ],
        "false_positives": ["Security tools", "Development environments", "Debugging tools"],
        "tags": ["execution", "native-api", "injection", "evasion"],
        "splunk": """index=sysmon EventCode=10
| search TargetImage="*\\lsass.exe" OR TargetImage="*\\csrss.exe"
| where GrantedAccess IN ("0x1FFFFF", "0x1010", "0x1410", "0x143A")
| stats count by SourceImage, TargetImage, GrantedAccess, Computer
| where count > 0""",
        "elastic": """winlog.event_id:10 AND
(winlog.event_data.TargetImage:*lsass.exe OR winlog.event_data.TargetImage:*csrss.exe) AND
winlog.event_data.GrantedAccess:(0x1FFFFF OR 0x1010 OR 0x1410)""",
        "sigma": """title: Suspicious Process Access to LSASS
id: b3456789-cdef-3456-789a-cdef3456789b
status: production
level: high
logsource:
    product: windows
    category: process_access
detection:
    selection:
        TargetImage|endswith: '\\lsass.exe'
        GrantedAccess:
            - '0x1FFFFF'
            - '0x1010'
            - '0x1410'
            - '0x143A'
    filter:
        SourceImage|endswith:
            - '\\MsMpEng.exe'
            - '\\vmtoolsd.exe'
    condition: selection and not filter
tags:
    - attack.execution
    - attack.t1106
    - attack.credential_access"""
    },

    # === PERSISTENCE - Additional ===
    {
        "id": "PB-T1546-001",
        "technique": "T1546",
        "tactic": "persistence",
        "dir_name": "T1546-event-triggered-execution",
        "name": "Event Triggered Execution Detection",
        "description": "Detect persistence through event-triggered execution mechanisms",
        "severity": "high",
        "subtechniques": ["T1546.001", "T1546.003", "T1546.008", "T1546.015"],
        "data_sources": ["Windows Registry", "Process Creation", "File Creation"],
        "hunt_hypothesis": """Adversaries abuse event-triggered execution for persistence:
1. Application Shimming (T1546.011)
2. Image File Execution Options (T1546.012)
3. WMI Event Subscription (T1546.003)
4. PowerShell Profile modification (T1546.013)
5. Accessibility Features (T1546.008)""",
        "investigation_steps": [
            "Review WMI permanent event subscriptions",
            "Check IFEO debugger registry keys",
            "Analyze PowerShell profile scripts",
            "Look for accessibility feature replacement",
            "Review AppInit_DLLs and AppCert registry keys"
        ],
        "false_positives": ["Software installers", "System management tools", "Accessibility software"],
        "tags": ["persistence", "event-triggered", "wmi", "registry"],
        "splunk": """`comment("WMI Event Subscription Detection")`
index=wineventlog source="WinEventLog:Microsoft-Windows-WMI-Activity/Operational"
| search EventCode IN (5857, 5858, 5859, 5860, 5861)
| rex field=Message "(?<consumer_name>CommandLineEventConsumer|ActiveScriptEventConsumer)"
| where isnotnull(consumer_name)
| stats count by Computer, consumer_name, Message

`comment("IFEO Debugger Detection")`
index=sysmon EventCode=13
| search TargetObject="*\\Image File Execution Options\\*\\Debugger"
| stats count by Computer, TargetObject, Details, Image""",
        "elastic": """(winlog.provider_name:"Microsoft-Windows-WMI-Activity" AND
winlog.event_id:(5857 OR 5858 OR 5859 OR 5860 OR 5861)) OR
(winlog.event_id:13 AND registry.path:*Image\ File\ Execution\ Options*)""",
        "sigma": """title: WMI Event Subscription Persistence
id: c4567890-def0-4567-89ab-def04567890c
status: production
level: high
logsource:
    product: windows
    service: wmi
detection:
    selection:
        EventID:
            - 5857
            - 5858
            - 5859
            - 5860
            - 5861
    keywords:
        - 'CommandLineEventConsumer'
        - 'ActiveScriptEventConsumer'
    condition: selection and keywords
tags:
    - attack.persistence
    - attack.t1546.003"""
    },

    # === PRIVILEGE ESCALATION - Additional ===
    {
        "id": "PB-T1055-001",
        "technique": "T1055",
        "tactic": "privilege-escalation",
        "dir_name": "T1055-process-injection",
        "name": "Process Injection Detection",
        "description": "Detect various process injection techniques used for privilege escalation and defense evasion",
        "severity": "critical",
        "subtechniques": ["T1055.001", "T1055.002", "T1055.003", "T1055.012"],
        "data_sources": ["Process Monitoring", "API Monitoring", "Sysmon"],
        "hunt_hypothesis": """Adversaries inject code into legitimate processes to:
1. Execute under a different process context
2. Evade process-based defenses
3. Elevate privileges
Common techniques: DLL injection, PE injection, process hollowing, thread hijacking""",
        "investigation_steps": [
            "Analyze process trees for suspicious parent-child relationships",
            "Review memory allocations in system processes",
            "Check for CreateRemoteThread calls to system processes",
            "Look for anomalous modules loaded in trusted processes",
            "Correlate with network activity from injected processes"
        ],
        "false_positives": ["Anti-virus software", "System management tools", "Debugging utilities"],
        "tags": ["privilege-escalation", "defense-evasion", "injection", "critical"],
        "splunk": """`comment("CreateRemoteThread Detection")`
index=sysmon EventCode=8
| search TargetImage IN ("*\\svchost.exe", "*\\explorer.exe", "*\\lsass.exe", "*\\services.exe")
| where SourceImage!=TargetImage
| eval suspicious=if(match(SourceImage, "(?i)(temp|appdata|downloads|public)"), 1, 0)
| where suspicious=1
| stats count by SourceImage, TargetImage, Computer

`comment("Process Hollowing - Suspended Process")`
index=sysmon EventCode=1
| search ParentImage="*\\cmd.exe" OR ParentImage="*\\powershell.exe"
| where Image IN ("*\\svchost.exe", "*\\dllhost.exe", "*\\RuntimeBroker.exe")
| stats count by ParentImage, Image, CommandLine, Computer""",
        "elastic": """(winlog.event_id:8 AND
winlog.event_data.TargetImage:(*svchost.exe OR *explorer.exe OR *lsass.exe) AND
winlog.event_data.SourceImage:(*temp* OR *appdata* OR *downloads*))""",
        "sigma": """title: CreateRemoteThread Into System Process
id: d5678901-ef01-5678-9abc-ef015678901d
status: production
level: critical
logsource:
    product: windows
    category: create_remote_thread
detection:
    selection:
        TargetImage|endswith:
            - '\\svchost.exe'
            - '\\lsass.exe'
            - '\\services.exe'
            - '\\winlogon.exe'
    filter:
        SourceImage|endswith:
            - '\\csrss.exe'
            - '\\wininit.exe'
            - '\\MsMpEng.exe'
    condition: selection and not filter
tags:
    - attack.privilege_escalation
    - attack.defense_evasion
    - attack.t1055"""
    },

    # === DEFENSE EVASION - Additional ===
    {
        "id": "PB-T1036-001",
        "technique": "T1036",
        "tactic": "defense-evasion",
        "dir_name": "T1036-masquerading",
        "name": "Masquerading Detection",
        "description": "Detect masquerading attempts where adversaries disguise malicious activity as legitimate",
        "severity": "high",
        "subtechniques": ["T1036.003", "T1036.004", "T1036.005"],
        "data_sources": ["Process Creation", "File Monitoring", "Binary Metadata"],
        "hunt_hypothesis": """Adversaries masquerade malicious files and processes as legitimate ones:
1. Naming executables similar to system binaries (svchost vs svch0st)
2. Running malicious code from legitimate directories
3. Manipulating file extensions
4. Spoofing file signatures and metadata""",
        "investigation_steps": [
            "Compare binary hashes against known good baselines",
            "Verify digital signatures on suspicious executables",
            "Check file locations against expected paths",
            "Review process command lines for typosquatting",
            "Analyze file metadata and compile timestamps"
        ],
        "false_positives": ["Renamed legitimate tools", "Portable applications", "Custom scripts"],
        "tags": ["defense-evasion", "masquerading", "lolbas"],
        "splunk": """`comment("System Binary Running from Wrong Location")`
index=sysmon EventCode=1
| rex field=Image "(?<filename>[^\\\\]+)$"
| where filename IN ("svchost.exe", "csrss.exe", "lsass.exe", "services.exe", "smss.exe", "winlogon.exe")
| where NOT match(Image, "(?i)C:\\\\Windows\\\\System32")
| stats count by Image, CommandLine, ParentImage, Computer

`comment("Typosquatting Detection")`
index=sysmon EventCode=1
| rex field=Image "(?<filename>[^\\\\]+)$"
| where match(filename, "(?i)(svch0st|scvhost|csvhost|lssas|lsas|csrs)")
| stats count by Image, ParentImage, CommandLine, Computer""",
        "elastic": """(process.name:(svchost.exe OR csrss.exe OR lsass.exe OR services.exe) AND
NOT process.executable:C\\:\\\\Windows\\\\System32\\*) OR
process.name:(svch0st.exe OR scvhost.exe OR lssas.exe OR csrs.exe)""",
        "sigma": """title: System Binary Running From Unusual Location
id: e6789012-f012-6789-abcd-f0126789012e
status: production
level: high
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith:
            - '\\svchost.exe'
            - '\\csrss.exe'
            - '\\lsass.exe'
            - '\\services.exe'
    filter:
        Image|startswith: 'C:\\Windows\\System32\\'
    condition: selection and not filter
tags:
    - attack.defense_evasion
    - attack.t1036"""
    },

    # === CREDENTIAL ACCESS - Additional ===
    {
        "id": "PB-T1552-001",
        "technique": "T1552",
        "tactic": "credential-access",
        "dir_name": "T1552-unsecured-credentials",
        "name": "Unsecured Credentials Discovery Detection",
        "description": "Detect attempts to find unsecured credentials in files, registry, and other locations",
        "severity": "high",
        "subtechniques": ["T1552.001", "T1552.002", "T1552.004", "T1552.006"],
        "data_sources": ["Process Creation", "File Access", "Command Line"],
        "hunt_hypothesis": """Adversaries search for credentials stored in:
1. Configuration files (web.config, unattend.xml)
2. Registry keys (VNC, PuTTY, WinSCP)
3. Browser password stores
4. Scripts and automation files
5. Cloud metadata services""",
        "investigation_steps": [
            "Review processes accessing sensitive file locations",
            "Check for registry queries to known credential stores",
            "Analyze command lines for credential searching patterns",
            "Review file access to common credential storage locations",
            "Check for access to cloud metadata endpoints"
        ],
        "false_positives": ["System administration tools", "Backup software", "Password managers"],
        "tags": ["credential-access", "unsecured-credentials", "passwords"],
        "splunk": """`comment("Searching for Passwords in Files")`
index=sysmon EventCode=1
| search CommandLine="*findstr*password*" OR CommandLine="*findstr*/s*pass*" OR CommandLine="*dir*/s*password*" OR CommandLine="*select-string*password*"
| stats count by Image, CommandLine, User, Computer

`comment("Registry Credential Store Access")`
index=sysmon EventCode=13
| search TargetObject="*\\SOFTWARE\\SimonTatham\\PuTTY\\Sessions*" OR TargetObject="*\\SOFTWARE\\Martin Prikryl\\WinSCP*" OR TargetObject="*\\SOFTWARE\\RealVNC*"
| stats count by Image, TargetObject, Computer""",
        "elastic": """(process.command_line:(*findstr* AND *password*) OR
process.command_line:(*Select-String* AND *password*)) OR
registry.path:(*PuTTY*Sessions* OR *WinSCP* OR *RealVNC*)""",
        "sigma": """title: Searching for Credentials in Files
id: f7890123-0123-789a-bcde-01237890123f
status: production
level: high
logsource:
    product: windows
    category: process_creation
detection:
    selection_findstr:
        Image|endswith: '\\findstr.exe'
        CommandLine|contains:
            - 'password'
            - 'credential'
            - 'secret'
    selection_powershell:
        Image|endswith:
            - '\\powershell.exe'
            - '\\pwsh.exe'
        CommandLine|contains: 'Select-String'
        CommandLine|contains:
            - 'password'
            - 'credential'
    condition: selection_findstr or selection_powershell
tags:
    - attack.credential_access
    - attack.t1552"""
    },

    # === DISCOVERY - Additional ===
    {
        "id": "PB-T1018-001",
        "technique": "T1018",
        "tactic": "discovery",
        "dir_name": "T1018-remote-system-discovery",
        "name": "Remote System Discovery Detection",
        "description": "Detect attempts to discover remote systems on the network",
        "severity": "medium",
        "subtechniques": [],
        "data_sources": ["Process Creation", "Network Traffic", "Command Line"],
        "hunt_hypothesis": """Adversaries enumerate remote systems to identify targets for lateral movement:
1. net view, net group commands
2. nltest /dclist
3. ping sweeps
4. PowerShell AD module queries
5. arp cache enumeration""",
        "investigation_steps": [
            "Review the user context performing discovery",
            "Check for subsequent lateral movement attempts",
            "Analyze scope of discovery (single host vs network-wide)",
            "Correlate with authentication events",
            "Review time of discovery activity"
        ],
        "false_positives": ["System administrators", "Monitoring tools", "Inventory software"],
        "tags": ["discovery", "network", "reconnaissance", "lateral-movement-prep"],
        "splunk": """index=sysmon EventCode=1
| search CommandLine="*net view*" OR CommandLine="*net group*Domain*" OR CommandLine="*nltest*/dclist*" OR CommandLine="*Get-ADComputer*" OR CommandLine="*dsquery computer*"
| stats count values(CommandLine) as commands by User, Computer
| where count > 3""",
        "elastic": """process.command_line:(*net\ view* OR *net\ group*domain* OR *nltest*dclist* OR *Get-ADComputer* OR *dsquery\ computer*)""",
        "sigma": """title: Remote System Discovery Commands
id: 08901234-1234-89ab-cdef-12348901234a
status: production
level: medium
logsource:
    product: windows
    category: process_creation
detection:
    selection_net:
        Image|endswith: '\\net.exe'
        CommandLine|contains:
            - ' view'
            - ' group '
    selection_nltest:
        Image|endswith: '\\nltest.exe'
        CommandLine|contains: '/dclist'
    selection_powershell:
        CommandLine|contains: 'Get-ADComputer'
    condition: selection_net or selection_nltest or selection_powershell
tags:
    - attack.discovery
    - attack.t1018"""
    },

    # === LATERAL MOVEMENT - Additional ===
    {
        "id": "PB-T1570-001",
        "technique": "T1570",
        "tactic": "lateral-movement",
        "dir_name": "T1570-lateral-tool-transfer",
        "name": "Lateral Tool Transfer Detection",
        "description": "Detect transfer of tools and payloads between systems for lateral movement",
        "severity": "high",
        "subtechniques": [],
        "data_sources": ["Network Traffic", "File Creation", "SMB Logs"],
        "hunt_hypothesis": """Adversaries transfer tools between compromised systems:
1. PsExec and similar tools via SMB
2. certutil, bitsadmin for file downloads
3. PowerShell remoting file transfers
4. SMB file copies between workstations
5. Admin share access patterns""",
        "investigation_steps": [
            "Identify source and destination systems",
            "Analyze transferred file types and names",
            "Check for execution of transferred files",
            "Review authentication events around transfer time",
            "Look for tool staging directories"
        ],
        "false_positives": ["Software deployment", "System administration", "Backup operations"],
        "tags": ["lateral-movement", "tool-transfer", "smb", "psexec"],
        "splunk": """`comment("SMB File Transfer Detection")`
index=sysmon EventCode=11
| search TargetFilename="*\\ADMIN$\\*" OR TargetFilename="*\\C$\\*" OR TargetFilename="*\\IPC$\\*"
| rex field=TargetFilename "(?<filename>[^\\\\]+)$"
| where match(filename, "(?i)\\.(exe|dll|ps1|bat|vbs)$")
| stats count values(TargetFilename) as files by Computer, Image

`comment("PsExec Service Installation")`
index=wineventlog source="WinEventLog:System" EventCode=7045
| search ServiceName="PSEXESVC" OR ImagePath="*PSEXESVC*" OR ServiceName IN ("csexec", "remcom", "paexec")
| stats count by ServiceName, ImagePath, Computer""",
        "elastic": """(winlog.event_id:11 AND file.path:(*ADMIN$* OR *C$*) AND
file.extension:(exe OR dll OR ps1 OR bat)) OR
(winlog.event_id:7045 AND winlog.event_data.ServiceName:(PSEXESVC OR csexec OR remcom))""",
        "sigma": """title: Suspicious File Written to Admin Share
id: 19012345-2345-9abc-def0-23459012345b
status: production
level: high
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|contains:
            - '\\ADMIN$\\'
            - '\\C$\\'
            - '\\IPC$\\'
        TargetFilename|endswith:
            - '.exe'
            - '.dll'
            - '.ps1'
            - '.bat'
    condition: selection
tags:
    - attack.lateral_movement
    - attack.t1570"""
    },

    # === COLLECTION - Additional ===
    {
        "id": "PB-T1119-001",
        "technique": "T1119",
        "tactic": "collection",
        "dir_name": "T1119-automated-collection",
        "name": "Automated Collection Detection",
        "description": "Detect automated collection of data from local and network sources",
        "severity": "medium",
        "subtechniques": [],
        "data_sources": ["Process Creation", "File Access", "Command Line"],
        "hunt_hypothesis": """Adversaries automate data collection using:
1. Scripts to recursively find sensitive files
2. Tools that search for specific file types
3. Automated clipboard capture
4. Keyloggers and input capture
5. Batch file operations on multiple directories""",
        "investigation_steps": [
            "Identify the collection mechanism (script, tool, malware)",
            "Determine scope of collected data",
            "Review file access patterns",
            "Check for staging directories",
            "Look for subsequent exfiltration"
        ],
        "false_positives": ["Backup software", "File indexing services", "E-discovery tools"],
        "tags": ["collection", "automation", "data-theft"],
        "splunk": """`comment("Automated File Collection")`
index=sysmon EventCode=1
| search CommandLine="*dir*/s*" OR CommandLine="*forfiles*" OR CommandLine="*Get-ChildItem*-Recurse*"
| where match(CommandLine, "(?i)\\.(doc|xls|pdf|ppt|txt|csv)")
| stats count values(CommandLine) as commands by User, Computer
| where count > 5""",
        "elastic": """(process.command_line:(*dir*/s* OR *forfiles* OR *Get-ChildItem*Recurse*) AND
process.command_line:(*.doc* OR *.xls* OR *.pdf* OR *.ppt*))""",
        "sigma": """title: Automated File Collection Using Command Line
id: 2a123456-3456-abcd-ef01-3456a123456c
status: production
level: medium
logsource:
    product: windows
    category: process_creation
detection:
    selection_dir:
        Image|endswith: '\\cmd.exe'
        CommandLine|contains|all:
            - 'dir'
            - '/s'
        CommandLine|contains:
            - '.doc'
            - '.xls'
            - '.pdf'
    selection_powershell:
        CommandLine|contains: 'Get-ChildItem'
        CommandLine|contains: '-Recurse'
    condition: selection_dir or selection_powershell
tags:
    - attack.collection
    - attack.t1119"""
    },

    # === COMMAND AND CONTROL - Additional ===
    {
        "id": "PB-T1102-001",
        "technique": "T1102",
        "tactic": "command-and-control",
        "dir_name": "T1102-web-service-c2",
        "name": "Web Service C2 Detection",
        "description": "Detect use of legitimate web services for command and control",
        "severity": "high",
        "subtechniques": ["T1102.002", "T1102.003"],
        "data_sources": ["Network Traffic", "Proxy Logs", "DNS Logs"],
        "hunt_hypothesis": """Adversaries use legitimate web services for C2 to blend with normal traffic:
1. Pastebin, GitHub, Dropbox for C2 instructions
2. Twitter, Telegram APIs for commands
3. Google Docs/Sheets for data exchange
4. Discord/Slack webhooks
5. Cloud storage services""",
        "investigation_steps": [
            "Analyze frequency and pattern of connections",
            "Review user-agent strings and request headers",
            "Check for encoded or encrypted payloads",
            "Correlate with endpoint process activity",
            "Identify automated vs human-initiated traffic"
        ],
        "false_positives": ["Legitimate use of cloud services", "Developer tools", "Collaboration platforms"],
        "tags": ["command-and-control", "c2", "web-service", "covert"],
        "splunk": """`comment("Suspicious API/Webhook Usage")`
index=proxy
| where match(url, "(?i)(api\\.telegram|discord\\.com/api/webhooks|api\\.github|pastebin\\.com/raw|hastebin)")
| stats count dc(dest_port) as ports by src_ip, url, user
| where count > 10 OR ports > 2

`comment("Cloud Storage C2 Patterns")`
index=proxy
| where match(url, "(?i)(dropbox\\.com|drive\\.google|onedrive|api\\.box)")
| bucket _time span=1h
| stats count by _time, src_ip, url
| where count > 50""",
        "elastic": """url.full:(*api.telegram* OR *discord.com/api/webhooks* OR *pastebin.com/raw* OR *api.github.com/gists*)""",
        "sigma": """title: Potential C2 via Web Service API
id: 3b234567-4567-bcde-f012-4567b234567d
status: production
level: high
logsource:
    category: proxy
detection:
    selection:
        c-uri|contains:
            - 'api.telegram.org'
            - 'discord.com/api/webhooks'
            - 'pastebin.com/raw'
            - 'api.github.com/gists'
    condition: selection | count() by c-ip > 10
tags:
    - attack.command_and_control
    - attack.t1102"""
    },

    # === EXFILTRATION - Additional ===
    {
        "id": "PB-T1041-001",
        "technique": "T1041",
        "tactic": "exfiltration",
        "dir_name": "T1041-exfil-c2-channel",
        "name": "Exfiltration Over C2 Channel Detection",
        "description": "Detect data exfiltration over the existing command and control channel",
        "severity": "critical",
        "subtechniques": [],
        "data_sources": ["Network Traffic", "Process Monitoring", "Netflow"],
        "hunt_hypothesis": """Adversaries exfiltrate data through the same channel used for C2:
1. Large HTTP POST requests to suspicious domains
2. Encrypted data in DNS TXT records
3. Chunked data transfer patterns
4. Unusual outbound data volumes
5. Base64 encoded data in HTTP headers""",
        "investigation_steps": [
            "Analyze network traffic volume anomalies",
            "Review HTTP request/response sizes",
            "Check for encoded data in unusual fields",
            "Correlate with known C2 infrastructure",
            "Identify data types being exfiltrated"
        ],
        "false_positives": ["Cloud backup services", "File sync applications", "Large email attachments"],
        "tags": ["exfiltration", "c2", "data-theft", "critical"],
        "splunk": """`comment("Large Outbound Data Transfer")`
index=network OR index=firewall
| where bytes_out > 10000000 AND dest_port IN (80, 443, 8080)
| stats sum(bytes_out) as total_bytes dc(dest_ip) as unique_dests by src_ip
| where total_bytes > 100000000 OR unique_dests > 20

`comment("Chunked Transfer Pattern")`
index=proxy
| bucket _time span=5m
| stats count sum(bytes_out) as total_bytes by _time, src_ip, url
| where count > 20 AND total_bytes > 5000000""",
        "elastic": """network.bytes_out:>10000000 AND destination.port:(80 OR 443 OR 8080)
| stats sum(network.bytes_out) by source.ip, destination.ip
| where sum > 100000000""",
        "sigma": """title: Large Data Exfiltration Over Common Ports
id: 4c345678-5678-cdef-0123-5678c345678e
status: production
level: critical
logsource:
    category: firewall
detection:
    selection:
        dest_port:
            - 80
            - 443
            - 8080
    filter:
        bytes_out|gt: 50000000
    condition: selection and filter
tags:
    - attack.exfiltration
    - attack.t1041"""
    },
]


def create_playbook(pb):
    """Create a single playbook with all files."""
    technique_dir = PLAYBOOKS_DIR / pb["dir_name"]
    queries_dir = technique_dir / "queries"

    # Create directories
    technique_dir.mkdir(parents=True, exist_ok=True)
    queries_dir.mkdir(exist_ok=True)

    # Create playbook.yaml
    today = datetime.now().strftime("%Y-%m-%d")

    yaml_content = f'''id: {pb["id"]}
name: "{pb["name"]}"
description: "{pb["description"]}"

mitre:
  technique: {pb["technique"]}
  tactic: {pb["tactic"]}
  subtechniques: {pb.get("subtechniques", [])}

severity: {pb["severity"]}
author: "Threat Hunting Team"
created: "{today}"
updated: "{today}"

data_sources:
{chr(10).join(f'  - "{ds}"' for ds in pb["data_sources"])}

hunt_hypothesis: |
{chr(10).join('  ' + line for line in pb["hunt_hypothesis"].strip().split(chr(10)))}

queries:
  splunk: queries/splunk.spl
  elastic: queries/elastic.kql
  sigma: queries/sigma.yml

investigation_steps:
{chr(10).join(f'  - "{step}"' for step in pb["investigation_steps"])}

false_positives:
{chr(10).join(f'  - "{fp}"' for fp in pb["false_positives"])}

tags: {pb["tags"]}

references:
  - "https://attack.mitre.org/techniques/{pb["technique"]}/"
'''

    with open(technique_dir / "playbook.yaml", "w") as f:
        f.write(yaml_content)

    # Create query files
    with open(queries_dir / "splunk.spl", "w") as f:
        f.write(pb["splunk"])

    with open(queries_dir / "elastic.kql", "w") as f:
        f.write(pb["elastic"])

    with open(queries_dir / "sigma.yml", "w") as f:
        f.write(pb["sigma"])

    print(f"Created: {pb['id']} - {pb['name']}")


def main():
    print("=" * 60)
    print("Generating Additional Playbooks")
    print("=" * 60)

    count = 0
    for pb in ADDITIONAL_PLAYBOOKS:
        create_playbook(pb)
        count += 1

    print("=" * 60)
    print(f"Generated {count} additional playbooks")
    print("=" * 60)


if __name__ == "__main__":
    main()
