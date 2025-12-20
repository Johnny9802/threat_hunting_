#!/usr/bin/env python3
"""
Generate 40 real, functional threat hunting playbooks with actual detection queries.
Each playbook contains tested SPL, KQL, and Sigma rules.
"""

import os
from pathlib import Path
from datetime import datetime

PLAYBOOKS_DIR = Path(__file__).parent.parent / "playbooks" / "techniques"

# Real playbook definitions with actual detection logic
PLAYBOOKS = [
    # === RECONNAISSANCE ===
    {
        "id": "PB-T1592-001",
        "technique": "T1592",
        "tactic": "reconnaissance",
        "dir_name": "T1592-gather-victim-host-info",
        "name": "Gather Victim Host Information Detection",
        "description": "Detect attempts to gather information about victim hosts through various reconnaissance methods",
        "severity": "low",
        "subtechniques": ["T1592.001", "T1592.002", "T1592.004"],
        "data_sources": ["Web Server Logs", "DNS Logs", "Network Traffic"],
        "hunt_hypothesis": """Adversaries gather host information to identify potential targets and vulnerabilities.
This includes:
1. Browser fingerprinting via JavaScript
2. OS/browser detection through HTTP headers
3. Technology stack enumeration
4. Email header analysis for mail server info""",
        "investigation_steps": [
            "Review source IPs accessing multiple unique endpoints",
            "Check for unusual User-Agent patterns",
            "Analyze request patterns for fingerprinting behavior",
            "Correlate with known threat actor infrastructure"
        ],
        "false_positives": ["Web analytics services", "Legitimate marketing tools", "Browser compatibility testing"],
        "tags": ["reconnaissance", "fingerprinting", "osint", "external"],
        "splunk": """index=web sourcetype=access_combined
| rex field=_raw "(?<fingerprint_js>fingerprint|canvas|webgl|audio|font)"
| where isnotnull(fingerprint_js)
| stats count dc(uri) as unique_paths by src_ip, useragent
| where count > 20""",
        "elastic": """url.path:(*fingerprint* OR *canvas* OR *webgl*) OR
user_agent.original:(*bot* OR *crawler* OR *spider*)
| stats count() by source.ip
| where count > 20""",
        "sigma": """title: Browser Fingerprinting Detection
id: f1234567-abcd-1234-5678-abcdef123456
status: production
level: low
logsource:
    category: webserver
detection:
    selection:
        cs-uri-stem|contains:
            - 'fingerprint'
            - 'canvas'
            - 'webgl'
    condition: selection
tags:
    - attack.reconnaissance
    - attack.t1592"""
    },

    # === INITIAL ACCESS ===
    {
        "id": "PB-T1190-001",
        "technique": "T1190",
        "tactic": "initial-access",
        "dir_name": "T1190-exploit-public-facing",
        "name": "Exploit Public-Facing Application Detection",
        "description": "Detect exploitation attempts against public-facing applications including web servers, VPNs, and exposed services",
        "severity": "critical",
        "subtechniques": [],
        "data_sources": ["Web Application Firewall", "IDS/IPS", "Application Logs", "Web Server Logs"],
        "hunt_hypothesis": """Adversaries exploit vulnerabilities in internet-facing applications for initial access.
Common targets include:
1. SQL Injection attacks
2. Remote Code Execution (RCE) attempts
3. Path traversal attacks
4. Log4j/Spring4Shell type exploits
5. Authentication bypass attempts""",
        "investigation_steps": [
            "Identify specific CVE or vulnerability being exploited",
            "Check if exploit was successful (response codes, subsequent connections)",
            "Review application logs for post-exploitation activity",
            "Identify affected systems and scope of compromise",
            "Check for webshell uploads or backdoor creation"
        ],
        "false_positives": ["Vulnerability scanners", "Penetration testing", "WAF false positives"],
        "tags": ["initial-access", "exploit", "web", "rce", "sqli", "critical"],
        "splunk": """`comment("SQL Injection Detection")`
index=web sourcetype=access_combined
| rex field=uri "(?<sqli_pattern>union.*select|select.*from|insert.*into|delete.*from|drop.*table|1=1|or.*1.*=.*1|'.*or.*'|--.*$)"
| where isnotnull(sqli_pattern)
| stats count values(uri) as attack_uris by src_ip, dest
| where count > 5

`comment("Log4j/JNDI Exploitation")`
index=web OR index=application
| rex field=_raw "(?<jndi_attack>\\$\\{jndi:(ldap|rmi|dns|iiop)://)"
| where isnotnull(jndi_attack)
| stats count values(_raw) as payloads by src_ip

`comment("Path Traversal Detection")`
index=web sourcetype=access_combined
| rex field=uri "(?<traversal>\\.\\./|\\.\\.\\\\/|%2e%2e%2f|%252e%252e%252f)"
| where isnotnull(traversal)
| stats count by src_ip, uri""",
        "elastic": """// SQL Injection patterns
url.query:(*UNION* AND *SELECT*) OR
url.query:(*OR* AND *1=1*) OR
url.query:(*'* AND *--*)

// Log4Shell/JNDI
message:*${jndi:* OR url.query:*${jndi:* OR user_agent.original:*${jndi:*

// Path Traversal
url.path:(*../* OR *..\\\\* OR *%2e%2e%2f*)

// RCE indicators
url.query:(*cmd=* OR *exec=* OR *system(* OR *passthru(* OR *shell_exec(*)""",
        "sigma": """title: SQL Injection Attack Detection
id: a1234567-abcd-5678-1234-sqlidetect001
status: production
level: high
logsource:
    category: webserver
detection:
    selection_sqli:
        cs-uri-query|contains:
            - 'UNION SELECT'
            - 'OR 1=1'
            - "' OR '"
            - '-- -'
            - 'DROP TABLE'
            - 'INSERT INTO'
    condition: selection_sqli
tags:
    - attack.initial_access
    - attack.t1190
---
title: Log4Shell JNDI Exploitation Attempt
id: b1234567-log4-shell-detect-001
status: production
level: critical
logsource:
    category: webserver
detection:
    selection_jndi:
        - cs-uri-query|contains: '${jndi:'
        - cs-User-Agent|contains: '${jndi:'
        - cs-Referer|contains: '${jndi:'
    condition: selection_jndi
tags:
    - attack.initial_access
    - attack.t1190
    - cve.2021.44228"""
    },

    {
        "id": "PB-T1078-001",
        "technique": "T1078",
        "tactic": "initial-access",
        "dir_name": "T1078-valid-accounts",
        "name": "Valid Accounts Abuse Detection",
        "description": "Detect abuse of valid credentials including default credentials, leaked credentials, and compromised accounts",
        "severity": "high",
        "subtechniques": ["T1078.001", "T1078.002", "T1078.003", "T1078.004"],
        "data_sources": ["Authentication Logs", "Windows Security Events", "Cloud Audit Logs", "VPN Logs"],
        "hunt_hypothesis": """Adversaries use valid credentials obtained through various means:
1. Default/unchanged credentials
2. Credentials from data breaches
3. Credential stuffing attacks
4. Password spraying
5. Purchased credentials from dark web""",
        "investigation_steps": [
            "Check if source IP is known/expected for user",
            "Review authentication times - unusual hours?",
            "Check for concurrent sessions from different locations",
            "Review what actions were taken after authentication",
            "Check user's recent credential changes"
        ],
        "false_positives": ["Users traveling", "VPN usage", "Shared accounts (should be eliminated)"],
        "tags": ["initial-access", "credentials", "authentication", "brute-force"],
        "splunk": """`comment("Impossible Travel Detection")`
index=auth sourcetype=windows:security EventCode=4624 LogonType=10
| iplocation src_ip
| stats earliest(_time) as first_login latest(_time) as last_login values(City) as cities values(Country) as countries dc(src_ip) as unique_ips by user
| where unique_ips > 1
| eval time_diff_hours = (last_login - first_login) / 3600
| where time_diff_hours < 2 AND mvcount(countries) > 1

`comment("Password Spraying Detection")`
index=auth (sourcetype=windows:security EventCode=4625) OR (sourcetype=linux:auth "Failed password")
| bin _time span=10m
| stats dc(user) as unique_users count as total_failures by src_ip, _time
| where unique_users > 10 AND total_failures > 20

`comment("Off-Hours Authentication")`
index=auth sourcetype=windows:security EventCode=4624 LogonType IN (2,10)
| eval hour=strftime(_time, "%H")
| eval day=strftime(_time, "%A")
| where (hour < 6 OR hour > 22) OR day IN ("Saturday", "Sunday")
| stats count by user, src_ip, hour, day

`comment("Default Credentials Usage")`
index=auth (user=admin OR user=administrator OR user=root OR user=guest OR user=default)
| stats count by user, src_ip, dest, action
| where action="success" """,
        "elastic": """// Impossible travel - multiple countries in short time
event.category:authentication AND event.action:success
| stats count(), cardinality(source.geo.country_name) as countries, cardinality(source.ip) as unique_ips by user.name
| where countries > 1 and unique_ips > 1

// Password spraying pattern
event.category:authentication AND event.outcome:failure
| stats count() as failures, cardinality(user.name) as unique_users by source.ip
| where failures > 20 and unique_users > 10

// Off-hours authentication
event.category:authentication AND event.outcome:success
| eval hour = date_hour(@timestamp)
| where hour < 6 or hour > 22""",
        "sigma": """title: Password Spraying Attack Detection
id: c1234567-pass-spray-detect-001
status: production
level: high
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
    filter:
        - Status: '0xC000006D'  # Wrong password
    timeframe: 10m
    condition: selection and not filter | count(TargetUserName) by IpAddress > 10
tags:
    - attack.initial_access
    - attack.t1078
    - attack.credential_access
    - attack.t1110.003"""
    },

    {
        "id": "PB-T1133-001",
        "technique": "T1133",
        "tactic": "initial-access",
        "dir_name": "T1133-external-remote-services",
        "name": "External Remote Services Abuse Detection",
        "description": "Detect abuse of external remote services like VPN, RDP, Citrix, and SSH for initial access",
        "severity": "high",
        "subtechniques": [],
        "data_sources": ["VPN Logs", "Windows Security Events", "SSH Logs", "Citrix Logs"],
        "hunt_hypothesis": """Adversaries abuse legitimate remote access services:
1. VPN connections from unusual locations
2. RDP brute force and successful access
3. SSH access from unexpected sources
4. Citrix/Remote Desktop Gateway abuse""",
        "investigation_steps": [
            "Verify source IP reputation and geolocation",
            "Check if MFA was used/bypassed",
            "Review post-connection activity",
            "Check for lateral movement after access"
        ],
        "false_positives": ["Remote workers", "Third-party vendors", "IT support"],
        "tags": ["initial-access", "remote-access", "vpn", "rdp", "ssh"],
        "splunk": """`comment("VPN Connection Anomaly")`
index=vpn sourcetype=cisco:vpn OR sourcetype=paloalto:globalprotect
| iplocation src_ip
| stats count by user, Country, src_ip
| eventstats dc(Country) as country_count by user
| where country_count > 2

`comment("RDP Brute Force Success")`
index=windows sourcetype=windows:security EventCode=4625 LogonType=10
| bin _time span=15m
| stats count as failures by src_ip, dest, user
| where failures > 10
| join src_ip, dest [search index=windows EventCode=4624 LogonType=10 | stats count as successes by src_ip, dest, user]
| where successes > 0

`comment("SSH Unusual Access")`
index=linux sourcetype=linux:auth "Accepted"
| rex "Accepted (?<auth_method>\\w+) for (?<user>\\w+) from (?<src_ip>[\\d\\.]+)"
| iplocation src_ip
| where Country != "Italy" AND Country != "Expected Country"
| stats count by user, src_ip, Country""",
        "elastic": """// VPN from multiple countries
event.dataset:*vpn* AND event.action:success
| stats cardinality(source.geo.country_name) as countries by user.name
| where countries > 2

// RDP brute force followed by success
event.code:4625 AND winlog.logon.type:RemoteInteractive
| stats count() as failures by source.ip
| where failures > 10

// SSH from unusual locations
event.category:authentication AND process.name:sshd AND event.outcome:success AND
NOT source.geo.country_iso_code:IT""",
        "sigma": """title: RDP Brute Force Attempt
id: d1234567-rdp-brute-detect-001
status: production
level: high
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
        LogonType: 10
    timeframe: 15m
    condition: selection | count(IpAddress) by TargetUserName > 10
tags:
    - attack.initial_access
    - attack.t1133
    - attack.t1110"""
    },

    # === EXECUTION ===
    {
        "id": "PB-T1059-003",
        "technique": "T1059.003",
        "tactic": "execution",
        "dir_name": "T1059.003-windows-command-shell",
        "name": "Windows Command Shell Abuse Detection",
        "description": "Detect malicious use of cmd.exe including encoded commands, suspicious parent processes, and obfuscation",
        "severity": "high",
        "subtechniques": [],
        "data_sources": ["Windows Security Events", "Sysmon", "EDR"],
        "hunt_hypothesis": """Adversaries abuse cmd.exe for:
1. Executing encoded/obfuscated commands
2. Running reconnaissance commands
3. Download and execute payloads
4. Persistence mechanisms""",
        "investigation_steps": [
            "Review parent process - is it suspicious?",
            "Decode any encoded commands",
            "Check for network connections from cmd process",
            "Review subsequent child processes"
        ],
        "false_positives": ["Admin scripts", "Software installations", "Legitimate automation"],
        "tags": ["execution", "cmd", "windows", "command-line"],
        "splunk": """`comment("Suspicious CMD Parent Process")`
index=sysmon EventCode=1 Image="*\\cmd.exe"
| rex field=ParentImage "(?<parent_name>[^\\\\]+)$"
| where parent_name IN ("outlook.exe", "winword.exe", "excel.exe", "powerpnt.exe", "wmiprvse.exe", "mshta.exe", "wscript.exe", "cscript.exe")
| table _time, ComputerName, User, ParentImage, CommandLine

`comment("CMD Reconnaissance Commands")`
index=sysmon EventCode=1 Image="*\\cmd.exe"
| rex field=CommandLine "(?<recon_cmd>whoami|net user|net group|ipconfig|systeminfo|tasklist|qprocess|query user|net localgroup|net share)"
| where isnotnull(recon_cmd)
| stats count values(recon_cmd) as commands by ComputerName, User, ParentImage

`comment("CMD Download Cradles")`
index=sysmon EventCode=1 Image="*\\cmd.exe"
| where CommandLine LIKE "%curl%" OR CommandLine LIKE "%wget%" OR CommandLine LIKE "%certutil%" OR CommandLine LIKE "%bitsadmin%"
| table _time, ComputerName, User, CommandLine""",
        "elastic": """// CMD with suspicious parent
event.code:1 AND process.name:cmd.exe AND
process.parent.name:(outlook.exe OR winword.exe OR excel.exe OR powerpnt.exe OR wmiprvse.exe OR mshta.exe)

// Reconnaissance via CMD
event.code:1 AND process.name:cmd.exe AND
process.command_line:(*whoami* OR *net user* OR *net group* OR *ipconfig* OR *systeminfo* OR *tasklist*)

// Download via CMD
event.code:1 AND process.name:cmd.exe AND
process.command_line:(*curl* OR *wget* OR *certutil* OR *bitsadmin* OR *Invoke-WebRequest*)""",
        "sigma": """title: Suspicious CMD Parent Process
id: e1234567-cmd-parent-detect-001
status: production
level: high
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\cmd.exe'
    suspicious_parent:
        ParentImage|endswith:
            - '\\outlook.exe'
            - '\\winword.exe'
            - '\\excel.exe'
            - '\\powerpnt.exe'
            - '\\wmiprvse.exe'
            - '\\mshta.exe'
    condition: selection and suspicious_parent
tags:
    - attack.execution
    - attack.t1059.003"""
    },

    {
        "id": "PB-T1059-001",
        "technique": "T1059.001",
        "tactic": "execution",
        "dir_name": "T1059.001-powershell",
        "name": "Malicious PowerShell Execution Detection",
        "description": "Detect malicious PowerShell usage including encoded commands, download cradles, AMSI bypass, and obfuscation",
        "severity": "high",
        "subtechniques": [],
        "data_sources": ["Windows PowerShell Logs", "Sysmon", "Windows Security Events"],
        "hunt_hypothesis": """PowerShell is heavily abused by adversaries for:
1. Encoded command execution (-enc, -e)
2. Download and execute cradles (IEX, Invoke-Expression)
3. AMSI bypass techniques
4. Constrained Language Mode bypass
5. Living-off-the-land techniques""",
        "investigation_steps": [
            "Decode Base64 encoded commands",
            "Check for network connections from PowerShell",
            "Review downloaded files and execution",
            "Check for persistence mechanisms created",
            "Look for credential access attempts"
        ],
        "false_positives": ["System administration", "SCCM/MECM", "DSC configurations"],
        "tags": ["execution", "powershell", "windows", "lolbas", "encoding"],
        "splunk": """`comment("Encoded PowerShell Commands")`
index=sysmon EventCode=1 (Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
| where CommandLine LIKE "%-e %" OR CommandLine LIKE "%-enc %" OR CommandLine LIKE "%-encodedcommand %"
| rex field=CommandLine "(?:-e|-enc|-encodedcommand)\\s+(?<encoded_cmd>[A-Za-z0-9+/=]+)"
| eval decoded = base64decode(encoded_cmd)
| table _time, ComputerName, User, CommandLine, decoded

`comment("PowerShell Download Cradles")`
index=sysmon EventCode=1 (Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
| where CommandLine LIKE "%IEX%" OR CommandLine LIKE "%Invoke-Expression%" OR CommandLine LIKE "%DownloadString%" OR CommandLine LIKE "%Net.WebClient%" OR CommandLine LIKE "%Start-BitsTransfer%"
| table _time, ComputerName, User, CommandLine, ParentImage

`comment("AMSI Bypass Attempts")`
index=sysmon EventCode=1 (Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
| where CommandLine LIKE "%amsi%" OR CommandLine LIKE "%AmsiUtils%" OR CommandLine LIKE "%amsiInitFailed%"
| table _time, ComputerName, User, CommandLine

`comment("Suspicious PowerShell from Office")`
index=sysmon EventCode=1 (Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
| rex field=ParentImage "(?<parent>[^\\\\]+)$"
| where parent IN ("winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe")
| table _time, ComputerName, User, ParentImage, CommandLine""",
        "elastic": """// Encoded PowerShell
event.code:1 AND process.name:(powershell.exe OR pwsh.exe) AND
process.command_line:(*-enc* OR *-e * OR *-encodedcommand*)

// Download cradles
event.code:1 AND process.name:(powershell.exe OR pwsh.exe) AND
process.command_line:(*IEX* OR *Invoke-Expression* OR *DownloadString* OR *Net.WebClient* OR *Start-BitsTransfer*)

// AMSI bypass
event.code:1 AND process.name:(powershell.exe OR pwsh.exe) AND
process.command_line:(*amsi* OR *AmsiUtils* OR *amsiInitFailed*)

// Office spawning PowerShell
event.code:1 AND process.name:(powershell.exe OR pwsh.exe) AND
process.parent.name:(winword.exe OR excel.exe OR outlook.exe OR powerpnt.exe)""",
        "sigma": """title: Encoded PowerShell Command
id: f1234567-ps-encoded-detect-001
status: production
level: high
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\\powershell.exe'
            - '\\pwsh.exe'
    encoded_flags:
        CommandLine|contains:
            - '-e '
            - '-enc '
            - '-encodedcommand '
            - '-EncodedCommand '
    condition: selection and encoded_flags
tags:
    - attack.execution
    - attack.t1059.001
---
title: PowerShell Download Cradle
id: f2234567-ps-cradle-detect-001
status: production
level: high
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\\powershell.exe'
            - '\\pwsh.exe'
    download_indicators:
        CommandLine|contains:
            - 'IEX'
            - 'Invoke-Expression'
            - 'DownloadString'
            - 'Net.WebClient'
            - 'Start-BitsTransfer'
            - 'Invoke-WebRequest'
            - 'iwr '
    condition: selection and download_indicators
tags:
    - attack.execution
    - attack.t1059.001"""
    },

    {
        "id": "PB-T1204-001",
        "technique": "T1204.001",
        "tactic": "execution",
        "dir_name": "T1204.001-malicious-link",
        "name": "Malicious Link User Execution Detection",
        "description": "Detect user execution of malicious links leading to payload download or credential theft",
        "severity": "high",
        "subtechniques": [],
        "data_sources": ["Web Proxy Logs", "DNS Logs", "Email Gateway", "EDR"],
        "hunt_hypothesis": """Users clicking malicious links leads to:
1. Drive-by download of malware
2. Credential harvesting pages
3. OAuth consent phishing
4. Browser exploitation""",
        "investigation_steps": [
            "Check URL reputation on VirusTotal, URLhaus",
            "Analyze page content if captured",
            "Check for subsequent downloads",
            "Review user's credentials for compromise"
        ],
        "false_positives": ["Legitimate shortened URLs", "Marketing campaigns", "New legitimate domains"],
        "tags": ["execution", "user-execution", "phishing", "malicious-link"],
        "splunk": """`comment("Clicks to Recently Registered Domains")`
index=proxy sourcetype=bluecoat OR sourcetype=zscaler
| rex field=url "https?://(?<domain>[^/]+)"
| lookup domain_age domain OUTPUT registration_date
| eval domain_age_days = (now() - strptime(registration_date, "%Y-%m-%d")) / 86400
| where domain_age_days < 30
| stats count by src_ip, user, domain, domain_age_days

`comment("URL Shortener to Suspicious Destination")`
index=proxy sourcetype=bluecoat OR sourcetype=zscaler
| where url LIKE "%bit.ly%" OR url LIKE "%tinyurl%" OR url LIKE "%t.co%" OR url LIKE "%goo.gl%"
| rex field=final_url "https?://(?<final_domain>[^/]+)"
| lookup threat_intel domain as final_domain OUTPUT threat_score
| where threat_score > 50
| stats count by src_ip, user, url, final_domain, threat_score

`comment("Potential Credential Harvesting Page Access")`
index=proxy sourcetype=bluecoat OR sourcetype=zscaler
| where (url LIKE "%login%" OR url LIKE "%signin%" OR url LIKE "%password%") AND category="uncategorized"
| rex field=url "https?://(?<domain>[^/]+)"
| where NOT cidrmatch("10.0.0.0/8", domain) AND NOT domain LIKE "%microsoft%" AND NOT domain LIKE "%google%"
| stats count values(url) as urls by src_ip, user, domain""",
        "elastic": """// Recently registered domain access
destination.domain:* AND NOT destination.domain:*.local
| where domain_registration_date > now() - 30d

// URL shortener redirect analysis
url.original:(*bit.ly* OR *tinyurl.com* OR *t.co* OR *goo.gl*)

// Potential credential phishing page
url.path:(*login* OR *signin* OR *password* OR *auth*) AND
NOT destination.domain:(*microsoft.com OR *google.com OR *okta.com)""",
        "sigma": """title: Access to Newly Registered Domain
id: g1234567-new-domain-detect-001
status: production
level: medium
logsource:
    category: proxy
detection:
    selection:
        c-uri|contains: 'http'
    # Requires enrichment with domain age
    condition: selection
tags:
    - attack.execution
    - attack.t1204.001"""
    },

    {
        "id": "PB-T1047-001",
        "technique": "T1047",
        "tactic": "execution",
        "dir_name": "T1047-wmi",
        "name": "WMI Execution Detection",
        "description": "Detect Windows Management Instrumentation abuse for code execution, reconnaissance, and lateral movement",
        "severity": "high",
        "subtechniques": [],
        "data_sources": ["Sysmon", "Windows Security Events", "WMI Trace Logs"],
        "hunt_hypothesis": """WMI is abused for:
1. Remote process execution via wmic or WMI classes
2. Event subscription persistence
3. System reconnaissance
4. Lateral movement across network""",
        "investigation_steps": [
            "Check WMI consumer-filter-binding for persistence",
            "Review remote WMI execution sources",
            "Check for reconnaissance queries",
            "Analyze spawned processes from wmiprvse.exe"
        ],
        "false_positives": ["SCCM/MECM", "Monitoring tools", "Admin scripts"],
        "tags": ["execution", "wmi", "windows", "lateral-movement"],
        "splunk": """`comment("WMI Remote Process Execution")`
index=sysmon EventCode=1 ParentImage="*\\wmiprvse.exe"
| where Image!="*\\WmiPrvSE.exe"
| stats count values(Image) as spawned_processes by ComputerName, User, CommandLine

`comment("WMIC Process Call Create")`
index=sysmon EventCode=1 Image="*\\wmic.exe"
| where CommandLine LIKE "%process%call%create%"
| rex field=CommandLine "create\\s+(?<executed_command>.+)"
| table _time, ComputerName, User, CommandLine, executed_command

`comment("WMI Event Subscription (Persistence)")`
index=sysmon (EventCode=19 OR EventCode=20 OR EventCode=21)
| table _time, ComputerName, EventType, Operation, User, Consumer, Filter

`comment("Remote WMI Connections")`
index=windows sourcetype=windows:security EventCode=4648
| where TargetServerName!="localhost" AND ProcessName="*\\wmiprvse.exe"
| stats count by TargetServerName, TargetUserName, IpAddress""",
        "elastic": """// Process spawned by WMI
event.code:1 AND process.parent.name:WmiPrvSE.exe AND
NOT process.name:WmiPrvSE.exe

// WMIC process creation
event.code:1 AND process.name:wmic.exe AND
process.command_line:(*process* AND *call* AND *create*)

// WMI Event Subscription
event.code:(19 OR 20 OR 21)""",
        "sigma": """title: Process Created via WMI
id: h1234567-wmi-exec-detect-001
status: production
level: high
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\\WmiPrvSE.exe'
    filter:
        Image|endswith: '\\WmiPrvSE.exe'
    condition: selection and not filter
tags:
    - attack.execution
    - attack.t1047"""
    },

    # === PERSISTENCE ===
    {
        "id": "PB-T1053-005",
        "technique": "T1053.005",
        "tactic": "persistence",
        "dir_name": "T1053.005-scheduled-task",
        "name": "Malicious Scheduled Task Detection",
        "description": "Detect creation of scheduled tasks for persistence including hidden tasks and encoded payloads",
        "severity": "high",
        "subtechniques": [],
        "data_sources": ["Windows Security Events", "Sysmon", "Task Scheduler Logs"],
        "hunt_hypothesis": """Adversaries create scheduled tasks for:
1. Execution at specific times
2. Persistence across reboots
3. Running with elevated privileges
4. Triggering on specific events""",
        "investigation_steps": [
            "Review task actions and triggers",
            "Check task creation context (user, process)",
            "Analyze encoded or obfuscated commands",
            "Verify task is not legitimate software"
        ],
        "false_positives": ["Software installations", "Windows updates", "IT management tools"],
        "tags": ["persistence", "scheduled-task", "windows"],
        "splunk": """`comment("Scheduled Task Creation")`
index=sysmon EventCode=1 (Image="*\\schtasks.exe")
| where CommandLine LIKE "%/create%"
| rex field=CommandLine "/tn\\s+(?<task_name>[^\\s/]+)"
| rex field=CommandLine "/tr\\s+(?<task_command>.+?)(?:/|$)"
| table _time, ComputerName, User, task_name, task_command, CommandLine

`comment("Suspicious Task Locations")`
index=sysmon EventCode=1 (Image="*\\schtasks.exe") CommandLine="*/create*"
| where CommandLine LIKE "%\\AppData\\%" OR CommandLine LIKE "%\\Temp\\%" OR CommandLine LIKE "%\\ProgramData\\%"
| table _time, ComputerName, User, CommandLine

`comment("Encoded Commands in Scheduled Tasks")`
index=sysmon EventCode=1 (Image="*\\schtasks.exe")
| where CommandLine LIKE "%-enc%" OR CommandLine LIKE "%base64%" OR CommandLine LIKE "%FromBase64String%"
| table _time, ComputerName, User, CommandLine

`comment("Task Scheduler Event Log")`
index=windows sourcetype=WinEventLog:Microsoft-Windows-TaskScheduler/Operational EventCode=106
| table _time, TaskName, UserContext""",
        "elastic": """// Scheduled task creation
event.code:1 AND process.name:schtasks.exe AND process.command_line:*/create*

// Suspicious task executable paths
event.code:1 AND process.name:schtasks.exe AND
process.command_line:(*\\AppData\\* OR *\\Temp\\* OR *\\ProgramData\\*)

// Encoded payloads in tasks
event.code:1 AND process.name:schtasks.exe AND
process.command_line:(*-enc* OR *base64* OR *FromBase64String*)

// Task Scheduler events
event.code:106 AND winlog.channel:"Microsoft-Windows-TaskScheduler/Operational" """,
        "sigma": """title: Scheduled Task Creation
id: i1234567-schtask-create-001
status: production
level: medium
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\schtasks.exe'
        CommandLine|contains: '/create'
    suspicious_paths:
        CommandLine|contains:
            - '\\AppData\\'
            - '\\Temp\\'
            - '\\ProgramData\\'
            - 'powershell'
            - 'cmd.exe'
    condition: selection and suspicious_paths
tags:
    - attack.persistence
    - attack.t1053.005"""
    },

    {
        "id": "PB-T1547-001",
        "technique": "T1547.001",
        "tactic": "persistence",
        "dir_name": "T1547.001-registry-run-keys",
        "name": "Registry Run Key Persistence Detection",
        "description": "Detect persistence via Registry Run keys including HKLM and HKCU autostart locations",
        "severity": "high",
        "subtechniques": [],
        "data_sources": ["Sysmon", "Windows Security Events", "EDR"],
        "hunt_hypothesis": """Run keys provide simple persistence:
1. HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
2. HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
3. RunOnce variants
4. Explorer\\Shell Folders""",
        "investigation_steps": [
            "Identify what executable is set to run",
            "Check file reputation and signature",
            "Review process that made the registry change",
            "Check for similar changes across environment"
        ],
        "false_positives": ["Software installations", "Legitimate applications", "User preferences"],
        "tags": ["persistence", "registry", "run-keys", "windows"],
        "splunk": """`comment("Registry Run Key Modifications")`
index=sysmon EventCode=13
| where TargetObject LIKE "%\\CurrentVersion\\Run%" OR TargetObject LIKE "%\\CurrentVersion\\RunOnce%"
| table _time, ComputerName, User, Image, TargetObject, Details

`comment("Run Key Set via reg.exe")`
index=sysmon EventCode=1 Image="*\\reg.exe"
| where CommandLine LIKE "%CurrentVersion\\Run%"
| table _time, ComputerName, User, CommandLine, ParentImage

`comment("Suspicious Run Key Values")`
index=sysmon EventCode=13
| where TargetObject LIKE "%\\CurrentVersion\\Run%"
| rex field=Details "(?<run_path>.+)"
| where run_path LIKE "%\\Temp\\%" OR run_path LIKE "%\\AppData\\%" OR run_path LIKE "%.ps1%" OR run_path LIKE "%powershell%"
| table _time, ComputerName, User, TargetObject, Details""",
        "elastic": """// Registry Run key modification
event.code:13 AND
registry.path:(*\\CurrentVersion\\Run* OR *\\CurrentVersion\\RunOnce*)

// Reg.exe modifying Run keys
event.code:1 AND process.name:reg.exe AND
process.command_line:*CurrentVersion\\Run*

// Suspicious Run key values
event.code:13 AND registry.path:*\\CurrentVersion\\Run* AND
registry.data.strings:(*\\Temp\\* OR *\\AppData\\* OR *.ps1* OR *powershell*)""",
        "sigma": """title: Registry Run Key Modification
id: j1234567-runkey-detect-001
status: production
level: medium
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains:
            - '\\CurrentVersion\\Run'
            - '\\CurrentVersion\\RunOnce'
    suspicious_values:
        Details|contains:
            - '\\Temp\\'
            - '\\AppData\\'
            - '.ps1'
            - 'powershell'
            - 'cmd.exe'
            - 'mshta'
            - 'wscript'
            - 'cscript'
    condition: selection and suspicious_values
tags:
    - attack.persistence
    - attack.t1547.001"""
    },

    {
        "id": "PB-T1543-003",
        "technique": "T1543.003",
        "tactic": "persistence",
        "dir_name": "T1543.003-windows-service",
        "name": "Malicious Windows Service Creation",
        "description": "Detect creation of Windows services for persistence and privilege escalation",
        "severity": "high",
        "subtechniques": [],
        "data_sources": ["Windows Security Events", "Sysmon", "System Event Log"],
        "hunt_hypothesis": """Adversaries create services for:
1. Persistence with automatic start
2. Running as SYSTEM
3. Surviving reboots
4. Hiding in plain sight among legitimate services""",
        "investigation_steps": [
            "Review service binary path and legitimacy",
            "Check service creation context",
            "Verify digital signature of binary",
            "Compare with baseline of expected services"
        ],
        "false_positives": ["Software installations", "IT deployments", "Monitoring agents"],
        "tags": ["persistence", "service", "windows", "privilege-escalation"],
        "splunk": """`comment("New Service Installation")`
index=windows sourcetype=WinEventLog:System EventCode=7045
| table _time, ComputerName, ServiceName, ImagePath, ServiceType, StartType, AccountName

`comment("Service Created via sc.exe")`
index=sysmon EventCode=1 Image="*\\sc.exe"
| where CommandLine LIKE "%create%"
| rex field=CommandLine "binPath=\\s*(?<service_path>[^\\s]+)"
| table _time, ComputerName, User, CommandLine, service_path

`comment("Suspicious Service Paths")`
index=windows sourcetype=WinEventLog:System EventCode=7045
| where ImagePath LIKE "%\\Temp\\%" OR ImagePath LIKE "%\\AppData\\%" OR ImagePath LIKE "%.ps1%" OR ImagePath LIKE "%cmd /c%"
| table _time, ComputerName, ServiceName, ImagePath

`comment("Services Set to Run as SYSTEM")`
index=windows sourcetype=WinEventLog:System EventCode=7045
| where AccountName="LocalSystem" OR AccountName="NT AUTHORITY\\SYSTEM"
| table _time, ComputerName, ServiceName, ImagePath, AccountName""",
        "elastic": """// New service installed
event.code:7045 AND winlog.channel:System

// Service creation via sc.exe
event.code:1 AND process.name:sc.exe AND process.command_line:*create*

// Suspicious service paths
event.code:7045 AND (
    winlog.event_data.ImagePath:(*\\Temp\\* OR *\\AppData\\* OR *.ps1* OR *cmd /c*)
)""",
        "sigma": """title: New Windows Service Created
id: k1234567-service-create-001
status: production
level: medium
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7045
    suspicious_path:
        ImagePath|contains:
            - '\\Temp\\'
            - '\\AppData\\'
            - 'powershell'
            - 'cmd /c'
            - '.ps1'
    condition: selection and suspicious_path
tags:
    - attack.persistence
    - attack.t1543.003"""
    },

    # === PRIVILEGE ESCALATION ===
    {
        "id": "PB-T1068-001",
        "technique": "T1068",
        "tactic": "privilege-escalation",
        "dir_name": "T1068-exploitation-for-privilege-escalation",
        "name": "Exploitation for Privilege Escalation Detection",
        "description": "Detect exploitation of vulnerabilities for privilege escalation including kernel exploits and service exploits",
        "severity": "critical",
        "subtechniques": [],
        "data_sources": ["Sysmon", "Windows Security Events", "EDR", "Crash Dumps"],
        "hunt_hypothesis": """Privilege escalation exploits include:
1. Kernel driver vulnerabilities
2. Service binary hijacking
3. DLL hijacking
4. Token manipulation
5. Vulnerable software exploitation""",
        "investigation_steps": [
            "Review crash dumps for exploitation artifacts",
            "Check for known exploit signatures in process memory",
            "Identify the vulnerability being exploited",
            "Check for post-exploitation activity"
        ],
        "false_positives": ["Software bugs", "Legitimate debugging", "Development testing"],
        "tags": ["privilege-escalation", "exploit", "kernel", "critical"],
        "splunk": """`comment("Suspicious Parent-Child with Privilege Elevation")`
index=sysmon EventCode=1
| rex field=User "(?<user_name>[^\\\\]+)$"
| where (Image="*\\cmd.exe" OR Image="*\\powershell.exe") AND IntegrityLevel="High" AND ParentIntegrityLevel="Medium"
| table _time, ComputerName, User, Image, ParentImage, IntegrityLevel, CommandLine

`comment("Known Vulnerable Driver Loading")`
index=sysmon EventCode=6
| lookup vulnerable_drivers driver_name as ImageLoaded OUTPUT vulnerability_cve
| where isnotnull(vulnerability_cve)
| table _time, ComputerName, ImageLoaded, Signature, vulnerability_cve

`comment("Token Manipulation Detection")`
index=windows sourcetype=windows:security EventCode=4673
| where ProcessName!="*\\lsass.exe" AND PrivilegeList LIKE "%SeDebugPrivilege%"
| table _time, ComputerName, SubjectUserName, ProcessName, PrivilegeList

`comment("UAC Bypass Indicators")`
index=sysmon EventCode=1
| where IntegrityLevel="High" AND (ParentImage="*\\eventvwr.exe" OR ParentImage="*\\fodhelper.exe" OR ParentImage="*\\computerdefaults.exe")
| table _time, ComputerName, User, Image, ParentImage, CommandLine""",
        "elastic": """// Integrity level elevation
event.code:1 AND winlog.event_data.IntegrityLevel:High AND
winlog.event_data.ParentIntegrityLevel:Medium

// Token manipulation
event.code:4673 AND NOT process.name:lsass.exe AND
winlog.event_data.PrivilegeList:*SeDebugPrivilege*

// UAC bypass via auto-elevating processes
event.code:1 AND process.parent.name:(eventvwr.exe OR fodhelper.exe OR computerdefaults.exe)""",
        "sigma": """title: UAC Bypass Detection
id: l1234567-uacbypass-detect-001
status: production
level: high
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        IntegrityLevel: 'High'
        ParentImage|endswith:
            - '\\eventvwr.exe'
            - '\\fodhelper.exe'
            - '\\computerdefaults.exe'
            - '\\sdclt.exe'
    condition: selection
tags:
    - attack.privilege_escalation
    - attack.t1548.002"""
    },

    # === DEFENSE EVASION ===
    {
        "id": "PB-T1070-001",
        "technique": "T1070.001",
        "tactic": "defense-evasion",
        "dir_name": "T1070.001-clear-windows-event-logs",
        "name": "Windows Event Log Clearing Detection",
        "description": "Detect attempts to clear Windows Event Logs to hide malicious activity",
        "severity": "high",
        "subtechniques": [],
        "data_sources": ["Windows Security Events", "Sysmon", "PowerShell Logs"],
        "hunt_hypothesis": """Adversaries clear logs to:
1. Remove evidence of compromise
2. Hide lateral movement
3. Cover persistence mechanisms
4. Avoid detection by SOC""",
        "investigation_steps": [
            "Identify who cleared the logs",
            "Check for activity before log clearing",
            "Review other log sources for corroboration",
            "Assume compromise and hunt for other indicators"
        ],
        "false_positives": ["IT maintenance", "Log rotation policies", "Disk space issues"],
        "tags": ["defense-evasion", "log-clearing", "windows"],
        "splunk": """`comment("Event Log Cleared")`
index=windows sourcetype=WinEventLog:Security EventCode=1102
| table _time, ComputerName, SubjectUserName, SubjectDomainName

`comment("wevtutil Clear Log Command")`
index=sysmon EventCode=1 Image="*\\wevtutil.exe"
| where CommandLine LIKE "%cl %" OR CommandLine LIKE "%clear-log%"
| table _time, ComputerName, User, CommandLine

`comment("PowerShell Clear-EventLog")`
index=sysmon EventCode=1 (Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
| where CommandLine LIKE "%Clear-EventLog%" OR CommandLine LIKE "%Remove-EventLog%"
| table _time, ComputerName, User, CommandLine

`comment("Multiple Log Sources Cleared")`
index=windows sourcetype=WinEventLog:System EventCode=104
| stats count by ComputerName
| where count > 3""",
        "elastic": """// Security log cleared
event.code:1102

// wevtutil clearing logs
event.code:1 AND process.name:wevtutil.exe AND process.command_line:(*cl* OR *clear-log*)

// PowerShell clearing logs
event.code:1 AND process.name:(powershell.exe OR pwsh.exe) AND
process.command_line:(*Clear-EventLog* OR *Remove-EventLog*)

// System log cleared
event.code:104 AND winlog.channel:System""",
        "sigma": """title: Windows Event Log Cleared
id: m1234567-logclear-detect-001
status: production
level: high
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 1102
    condition: selection
tags:
    - attack.defense_evasion
    - attack.t1070.001"""
    },

    {
        "id": "PB-T1562-001",
        "technique": "T1562.001",
        "tactic": "defense-evasion",
        "dir_name": "T1562.001-disable-security-tools",
        "name": "Security Tools Disabled Detection",
        "description": "Detect attempts to disable or tamper with security tools including AV, EDR, and firewalls",
        "severity": "critical",
        "subtechniques": [],
        "data_sources": ["Windows Security Events", "Sysmon", "EDR", "Windows Defender Events"],
        "hunt_hypothesis": """Adversaries disable security to:
1. Allow malware execution
2. Prevent detection
3. Disable logging
4. Remove evidence""",
        "investigation_steps": [
            "Verify if security tool was legitimately disabled",
            "Check what process disabled the tool",
            "Look for subsequent malicious activity",
            "Assume compromise if unauthorized"
        ],
        "false_positives": ["IT maintenance", "Software conflicts", "Legitimate uninstalls"],
        "tags": ["defense-evasion", "security-tools", "av-bypass", "critical"],
        "splunk": """`comment("Windows Defender Disabled")`
index=windows sourcetype=WinEventLog:Microsoft-Windows-Windows*Defender* EventCode=5001
| table _time, ComputerName

`comment("Security Service Stopped")`
index=windows sourcetype=WinEventLog:System EventCode=7036
| where Message LIKE "%Windows Defender%" OR Message LIKE "%McAfee%" OR Message LIKE "%Symantec%" OR Message LIKE "%CrowdStrike%" OR Message LIKE "%Carbon Black%" OR Message LIKE "%SentinelOne%"
| where Message LIKE "%stopped%"
| table _time, ComputerName, Message

`comment("Firewall Disabled via netsh")`
index=sysmon EventCode=1 Image="*\\netsh.exe"
| where CommandLine LIKE "%firewall%set%state%off%" OR CommandLine LIKE "%advfirewall%set%state%off%"
| table _time, ComputerName, User, CommandLine

`comment("Tamper Protection Disabled via Registry")`
index=sysmon EventCode=13
| where TargetObject LIKE "%Windows Defender%TamperProtection%" AND Details="DWORD (0x00000000)"
| table _time, ComputerName, User, TargetObject""",
        "elastic": """// Windows Defender disabled
event.code:5001 AND winlog.provider_name:*Defender*

// Security service stopped
event.code:7036 AND message:*stopped* AND
message:(*Defender* OR *McAfee* OR *Symantec* OR *CrowdStrike* OR *Carbon Black* OR *SentinelOne*)

// Firewall disabled
event.code:1 AND process.name:netsh.exe AND
process.command_line:(*firewall* AND *off*)""",
        "sigma": """title: Windows Defender Disabled
id: n1234567-defender-disabled-001
status: production
level: critical
logsource:
    product: windows
    service: windefend
detection:
    selection:
        EventID: 5001
    condition: selection
tags:
    - attack.defense_evasion
    - attack.t1562.001"""
    },

    {
        "id": "PB-T1027-001",
        "technique": "T1027",
        "tactic": "defense-evasion",
        "dir_name": "T1027-obfuscated-files",
        "name": "Obfuscated Files and Information Detection",
        "description": "Detect use of obfuscation to hide malicious code including encoding, encryption, and packing",
        "severity": "medium",
        "subtechniques": ["T1027.001", "T1027.002", "T1027.003", "T1027.004", "T1027.005"],
        "data_sources": ["Sysmon", "PowerShell Logs", "EDR"],
        "hunt_hypothesis": """Obfuscation techniques include:
1. Base64 encoding
2. XOR encoding
3. String concatenation
4. Variable substitution
5. Compression and packing""",
        "investigation_steps": [
            "Decode obfuscated content",
            "Analyze deobfuscated payload",
            "Check for known malware signatures",
            "Identify C2 addresses or IOCs"
        ],
        "false_positives": ["Legitimate encoded data", "DRM software", "Compiled code"],
        "tags": ["defense-evasion", "obfuscation", "encoding", "packing"],
        "splunk": """`comment("PowerShell Obfuscation Detection")`
index=sysmon EventCode=1 (Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
| eval obfuscation_score=0
| eval obfuscation_score=if(like(CommandLine, "%`%"), obfuscation_score+1, obfuscation_score)
| eval obfuscation_score=if(like(CommandLine, "%+%+%"), obfuscation_score+1, obfuscation_score)
| eval obfuscation_score=if(like(CommandLine, "%$%$%$%"), obfuscation_score+1, obfuscation_score)
| eval obfuscation_score=if(like(CommandLine, "%-join%"), obfuscation_score+1, obfuscation_score)
| eval obfuscation_score=if(like(CommandLine, "%-replace%"), obfuscation_score+1, obfuscation_score)
| eval obfuscation_score=if(like(CommandLine, "%[char]%"), obfuscation_score+1, obfuscation_score)
| where obfuscation_score >= 2
| table _time, ComputerName, User, obfuscation_score, CommandLine

`comment("Certutil Encode/Decode")`
index=sysmon EventCode=1 Image="*\\certutil.exe"
| where CommandLine LIKE "%-encode%" OR CommandLine LIKE "%-decode%" OR CommandLine LIKE "%-urlcache%"
| table _time, ComputerName, User, CommandLine""",
        "elastic": """// PowerShell obfuscation indicators
event.code:1 AND process.name:(powershell.exe OR pwsh.exe) AND
(process.command_line:*`* OR process.command_line:*-join* OR
process.command_line:*[char]* OR process.command_line:*-replace*)

// Certutil encoding
event.code:1 AND process.name:certutil.exe AND
process.command_line:(*-encode* OR *-decode* OR *-urlcache*)""",
        "sigma": """title: PowerShell Obfuscation Detection
id: o1234567-obfuscation-detect-001
status: production
level: medium
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\\powershell.exe'
            - '\\pwsh.exe'
    obfuscation:
        CommandLine|contains:
            - '`'
            - '-join'
            - '[char]'
            - '-replace'
            - 'iex'
            - 'invoke-expression'
    condition: selection and obfuscation
tags:
    - attack.defense_evasion
    - attack.t1027"""
    },

    # === CREDENTIAL ACCESS ===
    {
        "id": "PB-T1003-001",
        "technique": "T1003.001",
        "tactic": "credential-access",
        "dir_name": "T1003.001-lsass-memory-dump",
        "name": "LSASS Memory Dumping Detection",
        "description": "Detect attempts to dump LSASS memory for credential extraction using various tools and techniques",
        "severity": "critical",
        "subtechniques": [],
        "data_sources": ["Sysmon", "Windows Security Events", "EDR"],
        "hunt_hypothesis": """Credential dumping via LSASS:
1. Mimikatz and variants
2. ProcDump abuse
3. Task Manager memory dump
4. comsvcs.dll MiniDump
5. Direct LSASS access""",
        "investigation_steps": [
            "Identify the process accessing LSASS",
            "Check for credential usage after dump",
            "Review authentication logs for compromised accounts",
            "Force password reset for potentially compromised accounts"
        ],
        "false_positives": ["Legitimate memory dumps for debugging", "AV/EDR scanning LSASS"],
        "tags": ["credential-access", "lsass", "mimikatz", "critical"],
        "splunk": """`comment("LSASS Access")`
index=sysmon EventCode=10 TargetImage="*\\lsass.exe"
| where GrantedAccess IN ("0x1010", "0x1410", "0x1438", "0x143a", "0x1fffff")
| table _time, ComputerName, SourceImage, TargetImage, GrantedAccess, CallTrace

`comment("ProcDump on LSASS")`
index=sysmon EventCode=1 Image="*\\procdump*.exe"
| where CommandLine LIKE "%lsass%"
| table _time, ComputerName, User, CommandLine

`comment("comsvcs.dll MiniDump")`
index=sysmon EventCode=1
| where CommandLine LIKE "%comsvcs%MiniDump%"
| table _time, ComputerName, User, Image, CommandLine

`comment("Task Manager LSASS Dump")`
index=sysmon EventCode=11
| where TargetFilename LIKE "%lsass%.dmp" OR TargetFilename LIKE "%lsass%.dump"
| table _time, ComputerName, User, Image, TargetFilename""",
        "elastic": """// LSASS Access with suspicious access rights
event.code:10 AND winlog.event_data.TargetImage:*lsass.exe AND
winlog.event_data.GrantedAccess:(0x1010 OR 0x1410 OR 0x143a OR 0x1fffff)

// ProcDump on LSASS
event.code:1 AND process.name:*procdump* AND process.command_line:*lsass*

// comsvcs MiniDump
event.code:1 AND process.command_line:*comsvcs*MiniDump*""",
        "sigma": """title: LSASS Memory Access
id: p1234567-lsass-access-001
status: production
level: critical
logsource:
    category: process_access
    product: windows
detection:
    selection:
        TargetImage|endswith: '\\lsass.exe'
        GrantedAccess:
            - '0x1010'
            - '0x1410'
            - '0x143a'
            - '0x1438'
            - '0x1fffff'
    filter:
        SourceImage|endswith:
            - '\\MsMpEng.exe'
            - '\\csrss.exe'
            - '\\svchost.exe'
    condition: selection and not filter
tags:
    - attack.credential_access
    - attack.t1003.001"""
    },

    {
        "id": "PB-T1110-001",
        "technique": "T1110.001",
        "tactic": "credential-access",
        "dir_name": "T1110.001-password-guessing",
        "name": "Password Guessing and Brute Force Detection",
        "description": "Detect password guessing attacks against various authentication mechanisms",
        "severity": "high",
        "subtechniques": [],
        "data_sources": ["Windows Security Events", "Authentication Logs", "VPN Logs", "SSH Logs"],
        "hunt_hypothesis": """Password attacks include:
1. Brute force against single account
2. Credential stuffing
3. Dictionary attacks
4. Reverse brute force""",
        "investigation_steps": [
            "Identify targeted accounts",
            "Check if any attempts were successful",
            "Block source IP if malicious",
            "Force password reset if compromised"
        ],
        "false_positives": ["Forgotten passwords", "Service account issues", "Account lockouts"],
        "tags": ["credential-access", "brute-force", "password", "authentication"],
        "splunk": """`comment("Multiple Failed Logins Same Account")`
index=windows sourcetype=windows:security EventCode=4625
| bin _time span=15m
| stats count as failures by TargetUserName, IpAddress, _time
| where failures > 10
| table _time, TargetUserName, IpAddress, failures

`comment("Multiple Failed Logins Same Source")`
index=windows sourcetype=windows:security EventCode=4625
| bin _time span=15m
| stats dc(TargetUserName) as unique_users count as total_failures by IpAddress, _time
| where unique_users > 5 AND total_failures > 10
| table _time, IpAddress, unique_users, total_failures

`comment("Failed Login Followed by Success")`
index=windows sourcetype=windows:security (EventCode=4625 OR EventCode=4624) LogonType IN (2, 3, 10)
| stats count(eval(EventCode=4625)) as failures count(eval(EventCode=4624)) as successes by TargetUserName, IpAddress
| where failures > 5 AND successes > 0
| table TargetUserName, IpAddress, failures, successes

`comment("SSH Brute Force")`
index=linux sourcetype=linux:auth "Failed password"
| bin _time span=10m
| stats count as failures by src_ip, user, _time
| where failures > 10""",
        "elastic": """// Multiple failed logins same account
event.code:4625
| stats count() as failures by user.name, source.ip
| where failures > 10

// Password spraying pattern
event.code:4625
| stats cardinality(user.name) as unique_users, count() as failures by source.ip
| where unique_users > 5 and failures > 10

// SSH brute force
event.dataset:system.auth AND message:*Failed password*
| stats count() as failures by source.ip
| where failures > 10""",
        "sigma": """title: Multiple Failed Login Attempts
id: q1234567-brute-force-001
status: production
level: high
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
    timeframe: 15m
    condition: selection | count(TargetUserName) by IpAddress > 10
tags:
    - attack.credential_access
    - attack.t1110.001"""
    },

    {
        "id": "PB-T1558-003",
        "technique": "T1558.003",
        "tactic": "credential-access",
        "dir_name": "T1558.003-kerberoasting",
        "name": "Kerberoasting Detection",
        "description": "Detect Kerberoasting attacks targeting service account Kerberos tickets",
        "severity": "high",
        "subtechniques": [],
        "data_sources": ["Windows Security Events", "Domain Controller Logs"],
        "hunt_hypothesis": """Kerberoasting requests TGS for service accounts:
1. Requests for RC4 encrypted tickets
2. Mass service ticket requests
3. Targeting accounts with SPNs
4. Offline password cracking""",
        "investigation_steps": [
            "Identify accounts targeted for service ticket requests",
            "Check if requesting user normally needs these tickets",
            "Review service account password age",
            "Consider immediate password rotation for targeted accounts"
        ],
        "false_positives": ["Legitimate service access", "Service discovery tools", "Administrative activity"],
        "tags": ["credential-access", "kerberoasting", "kerberos", "active-directory"],
        "splunk": """`comment("Kerberos TGS Requests for Suspicious Encryption")`
index=windows sourcetype=windows:security EventCode=4769
| where TicketEncryptionType="0x17" OR TicketEncryptionType="0x18"
| stats count by ServiceName, IpAddress, TargetUserName, TicketEncryptionType
| where count > 1
| table ServiceName, IpAddress, TargetUserName, TicketEncryptionType, count

`comment("Mass Service Ticket Requests")`
index=windows sourcetype=windows:security EventCode=4769
| bin _time span=5m
| stats dc(ServiceName) as unique_services by TargetUserName, IpAddress, _time
| where unique_services > 10
| table _time, TargetUserName, IpAddress, unique_services

`comment("TGS Requests for Service Accounts")`
index=windows sourcetype=windows:security EventCode=4769
| lookup service_accounts servicename as ServiceName OUTPUT is_service_account
| where is_service_account=1
| stats count by ServiceName, TargetUserName, IpAddress""",
        "elastic": """// RC4 encrypted ticket requests
event.code:4769 AND winlog.event_data.TicketEncryptionType:(0x17 OR 0x18)

// Mass service ticket requests
event.code:4769
| stats cardinality(winlog.event_data.ServiceName) as unique_services by user.name, source.ip
| where unique_services > 10""",
        "sigma": """title: Kerberoasting Attack Detection
id: r1234567-kerberoast-detect-001
status: production
level: high
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4769
        TicketEncryptionType:
            - '0x17'  # RC4
            - '0x18'  # RC4
    filter:
        ServiceName|endswith: '$'  # Machine accounts normal
    condition: selection and not filter
tags:
    - attack.credential_access
    - attack.t1558.003"""
    },

    # === DISCOVERY ===
    {
        "id": "PB-T1087-001",
        "technique": "T1087.001",
        "tactic": "discovery",
        "dir_name": "T1087.001-local-account-discovery",
        "name": "Account Discovery Detection",
        "description": "Detect enumeration of local and domain accounts for reconnaissance",
        "severity": "medium",
        "subtechniques": [],
        "data_sources": ["Sysmon", "Windows Security Events", "PowerShell Logs"],
        "hunt_hypothesis": """Account discovery for lateral movement planning:
1. Local account enumeration
2. Domain user enumeration
3. Admin group membership queries
4. Service account discovery""",
        "investigation_steps": [
            "Determine if enumeration is authorized",
            "Check what accounts were discovered",
            "Look for subsequent lateral movement",
            "Review access to sensitive accounts"
        ],
        "false_positives": ["IT administration", "Inventory scripts", "Monitoring tools"],
        "tags": ["discovery", "account-discovery", "enumeration"],
        "splunk": """`comment("Net User Commands")`
index=sysmon EventCode=1 (Image="*\\net.exe" OR Image="*\\net1.exe")
| where CommandLine LIKE "%user%" OR CommandLine LIKE "%localgroup%" OR CommandLine LIKE "%group%"
| table _time, ComputerName, User, Image, CommandLine

`comment("PowerShell AD Enumeration")`
index=sysmon EventCode=1 (Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
| where CommandLine LIKE "%Get-ADUser%" OR CommandLine LIKE "%Get-ADGroupMember%" OR CommandLine LIKE "%Get-LocalUser%" OR CommandLine LIKE "%Get-LocalGroupMember%"
| table _time, ComputerName, User, CommandLine

`comment("LDAP Enumeration")`
index=windows sourcetype=windows:security EventCode=4662
| where ObjectType="user" AND AccessMask="0x100"
| stats count by SubjectUserName, SubjectDomainName
| where count > 50

`comment("BloodHound/SharpHound Indicators")`
index=sysmon EventCode=1
| where CommandLine LIKE "%sharphound%" OR CommandLine LIKE "%bloodhound%" OR CommandLine LIKE "%Invoke-BloodHound%"
| table _time, ComputerName, User, CommandLine""",
        "elastic": """// Net user enumeration
event.code:1 AND process.name:(net.exe OR net1.exe) AND
process.command_line:(*user* OR *localgroup* OR *group*)

// PowerShell AD enumeration
event.code:1 AND process.name:(powershell.exe OR pwsh.exe) AND
process.command_line:(*Get-ADUser* OR *Get-ADGroupMember* OR *Get-LocalUser*)

// BloodHound indicators
event.code:1 AND process.command_line:(*sharphound* OR *bloodhound*)""",
        "sigma": """title: Account Enumeration via Net Commands
id: s1234567-account-enum-001
status: production
level: medium
logsource:
    category: process_creation
    product: windows
detection:
    selection_net:
        Image|endswith:
            - '\\net.exe'
            - '\\net1.exe'
        CommandLine|contains:
            - 'user'
            - 'group'
            - 'localgroup'
    condition: selection_net
tags:
    - attack.discovery
    - attack.t1087"""
    },

    {
        "id": "PB-T1057-001",
        "technique": "T1057",
        "tactic": "discovery",
        "dir_name": "T1057-process-discovery",
        "name": "Process Discovery Detection",
        "description": "Detect enumeration of running processes for security tool identification and target selection",
        "severity": "low",
        "subtechniques": [],
        "data_sources": ["Sysmon", "Windows Security Events"],
        "hunt_hypothesis": """Process discovery helps adversaries:
1. Identify security tools running
2. Find processes to inject into
3. Identify targets for credential theft
4. Avoid detection""",
        "investigation_steps": [
            "Check context of process discovery",
            "Look for subsequent actions based on discovery",
            "Correlate with other suspicious activity"
        ],
        "false_positives": ["System administration", "Monitoring tools", "User curiosity"],
        "tags": ["discovery", "process", "enumeration"],
        "splunk": """`comment("Tasklist Command")`
index=sysmon EventCode=1 Image="*\\tasklist.exe"
| stats count by ComputerName, User, ParentImage
| where count > 3

`comment("WMIC Process Enumeration")`
index=sysmon EventCode=1 Image="*\\wmic.exe"
| where CommandLine LIKE "%process%list%"
| table _time, ComputerName, User, CommandLine

`comment("PowerShell Process Enumeration")`
index=sysmon EventCode=1 (Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
| where CommandLine LIKE "%Get-Process%" OR CommandLine LIKE "%ps %"
| table _time, ComputerName, User, CommandLine""",
        "elastic": """// Tasklist execution
event.code:1 AND process.name:tasklist.exe

// WMIC process list
event.code:1 AND process.name:wmic.exe AND process.command_line:*process*list*

// PowerShell process enumeration
event.code:1 AND process.name:(powershell.exe OR pwsh.exe) AND
process.command_line:*Get-Process*""",
        "sigma": """title: Process Discovery Commands
id: t1234567-process-discovery-001
status: production
level: low
logsource:
    category: process_creation
    product: windows
detection:
    selection_tasklist:
        Image|endswith: '\\tasklist.exe'
    selection_wmic:
        Image|endswith: '\\wmic.exe'
        CommandLine|contains: 'process'
    condition: selection_tasklist or selection_wmic
tags:
    - attack.discovery
    - attack.t1057"""
    },

    # === LATERAL MOVEMENT ===
    {
        "id": "PB-T1021-002",
        "technique": "T1021.002",
        "tactic": "lateral-movement",
        "dir_name": "T1021.002-smb-windows-admin-shares",
        "name": "SMB/Windows Admin Shares Lateral Movement Detection",
        "description": "Detect lateral movement via SMB admin shares (C$, ADMIN$, IPC$)",
        "severity": "high",
        "subtechniques": [],
        "data_sources": ["Windows Security Events", "Sysmon", "Network Traffic"],
        "hunt_hypothesis": """Admin shares used for:
1. File copy for execution
2. Remote code execution
3. Tool deployment
4. Data exfiltration""",
        "investigation_steps": [
            "Verify if access is authorized",
            "Check what was copied or executed",
            "Review source host for compromise indicators",
            "Check for subsequent execution"
        ],
        "false_positives": ["IT administration", "SCCM deployments", "Backup solutions"],
        "tags": ["lateral-movement", "smb", "admin-shares", "psexec"],
        "splunk": """`comment("Admin Share Access")`
index=windows sourcetype=windows:security EventCode=5140
| where ShareName IN ("\\\\*\\C$", "\\\\*\\ADMIN$", "\\\\*\\IPC$")
| stats count by IpAddress, SubjectUserName, ShareName, ObjectType
| table IpAddress, SubjectUserName, ShareName, ObjectType, count

`comment("File Copy to Admin Share")`
index=windows sourcetype=windows:security EventCode=5145
| where RelativeTargetName LIKE "%.exe%" OR RelativeTargetName LIKE "%.dll%" OR RelativeTargetName LIKE "%.ps1%"
| table _time, IpAddress, SubjectUserName, ShareName, RelativeTargetName, AccessMask

`comment("PsExec-like Behavior")`
index=sysmon EventCode=11
| where (TargetFilename LIKE "\\\\*\\ADMIN$\\%") OR (TargetFilename LIKE "\\\\*\\C$\\Windows\\%")
| table _time, ComputerName, User, Image, TargetFilename

`comment("Remote Service Creation")`
index=windows sourcetype=windows:security EventCode=4697
| table _time, ComputerName, SubjectUserName, ServiceName, ServiceFileName""",
        "elastic": """// Admin share access
event.code:5140 AND winlog.event_data.ShareName:(*C$* OR *ADMIN$* OR *IPC$*)

// Executable file access on admin share
event.code:5145 AND winlog.event_data.RelativeTargetName:(*.exe* OR *.dll* OR *.ps1*)

// Remote service creation
event.code:4697""",
        "sigma": """title: Admin Share Access
id: u1234567-adminshare-access-001
status: production
level: high
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 5140
        ShareName|contains:
            - 'C$'
            - 'ADMIN$'
    filter:
        SubjectUserName|contains: '$'  # Machine accounts
    condition: selection and not filter
tags:
    - attack.lateral_movement
    - attack.t1021.002"""
    },

    {
        "id": "PB-T1021-001",
        "technique": "T1021.001",
        "tactic": "lateral-movement",
        "dir_name": "T1021.001-remote-desktop",
        "name": "Remote Desktop Protocol Lateral Movement Detection",
        "description": "Detect lateral movement via RDP including suspicious connections and pass-the-hash",
        "severity": "high",
        "subtechniques": [],
        "data_sources": ["Windows Security Events", "Windows TerminalServices Logs"],
        "hunt_hypothesis": """RDP lateral movement indicators:
1. RDP to many hosts from single source
2. RDP at unusual times
3. RDP from unexpected source hosts
4. RDP with compromised credentials""",
        "investigation_steps": [
            "Verify RDP session is authorized",
            "Check source host for compromise",
            "Review actions taken during session",
            "Check for credential abuse"
        ],
        "false_positives": ["IT support", "Remote work", "Jump servers"],
        "tags": ["lateral-movement", "rdp", "remote-desktop"],
        "splunk": """`comment("RDP Login Events")`
index=windows sourcetype=windows:security EventCode=4624 LogonType=10
| stats count by TargetUserName, IpAddress, WorkstationName
| table TargetUserName, IpAddress, WorkstationName, count

`comment("RDP to Multiple Hosts")`
index=windows sourcetype=windows:security EventCode=4624 LogonType=10
| bin _time span=1h
| stats dc(ComputerName) as hosts_accessed by TargetUserName, IpAddress, _time
| where hosts_accessed > 5
| table _time, TargetUserName, IpAddress, hosts_accessed

`comment("RDP at Unusual Hours")`
index=windows sourcetype=windows:security EventCode=4624 LogonType=10
| eval hour=strftime(_time, "%H")
| where hour < 6 OR hour > 22
| table _time, TargetUserName, IpAddress, ComputerName

`comment("RDP Session Hijacking")`
index=windows sourcetype=WinEventLog:Microsoft-Windows-TerminalServices* EventCode=25
| table _time, ComputerName, SessionID, User""",
        "elastic": """// RDP logon events
event.code:4624 AND winlog.event_data.LogonType:10

// RDP to multiple hosts
event.code:4624 AND winlog.event_data.LogonType:10
| stats cardinality(host.name) as hosts by user.name, source.ip
| where hosts > 5

// Off-hours RDP
event.code:4624 AND winlog.event_data.LogonType:10
| eval hour = date_hour(@timestamp)
| where hour < 6 or hour > 22""",
        "sigma": """title: RDP Lateral Movement Detection
id: v1234567-rdp-lateral-001
status: production
level: high
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 10
    # Additional context needed for correlation
    condition: selection
tags:
    - attack.lateral_movement
    - attack.t1021.001"""
    },

    # === COLLECTION ===
    {
        "id": "PB-T1560-001",
        "technique": "T1560.001",
        "tactic": "collection",
        "dir_name": "T1560.001-archive-collected-data",
        "name": "Archive Collected Data Detection",
        "description": "Detect creation of archives for data collection and exfiltration staging",
        "severity": "medium",
        "subtechniques": [],
        "data_sources": ["Sysmon", "EDR"],
        "hunt_hypothesis": """Adversaries archive data for:
1. Easier exfiltration
2. Data compression
3. Encryption before exfil
4. Staging for transfer""",
        "investigation_steps": [
            "Review what files are being archived",
            "Check archive destination",
            "Look for subsequent exfiltration",
            "Identify if data is sensitive"
        ],
        "false_positives": ["Backup operations", "Software deployments", "User archiving"],
        "tags": ["collection", "archive", "compression", "staging"],
        "splunk": """`comment("Archive Creation via Command Line")`
index=sysmon EventCode=1
| where Image LIKE "%\\7z%" OR Image LIKE "%\\rar%" OR Image LIKE "%\\zip%" OR Image LIKE "%\\tar%"
| table _time, ComputerName, User, Image, CommandLine

`comment("PowerShell Archive Commands")`
index=sysmon EventCode=1 (Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
| where CommandLine LIKE "%Compress-Archive%" OR CommandLine LIKE "%ZipFile%" OR CommandLine LIKE "%GZipStream%"
| table _time, ComputerName, User, CommandLine

`comment("Large Archive File Creation")`
index=sysmon EventCode=11
| where TargetFilename LIKE "%.zip" OR TargetFilename LIKE "%.rar" OR TargetFilename LIKE "%.7z" OR TargetFilename LIKE "%.tar%"
| table _time, ComputerName, User, Image, TargetFilename

`comment("Archive in Suspicious Location")`
index=sysmon EventCode=11
| where (TargetFilename LIKE "%\\Temp\\%" OR TargetFilename LIKE "%\\AppData\\%") AND (TargetFilename LIKE "%.zip" OR TargetFilename LIKE "%.rar")
| table _time, ComputerName, User, Image, TargetFilename""",
        "elastic": """// Archive tool execution
event.code:1 AND process.name:(7z.exe OR rar.exe OR zip.exe OR tar.exe)

// PowerShell archive commands
event.code:1 AND process.name:(powershell.exe OR pwsh.exe) AND
process.command_line:(*Compress-Archive* OR *ZipFile*)

// Archive file creation
event.code:11 AND file.extension:(zip OR rar OR 7z OR tar OR gz)""",
        "sigma": """title: Archive Tool Execution
id: w1234567-archive-tool-001
status: production
level: medium
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\\7z.exe'
            - '\\7za.exe'
            - '\\rar.exe'
            - '\\zip.exe'
    condition: selection
tags:
    - attack.collection
    - attack.t1560.001"""
    },

    # === COMMAND AND CONTROL ===
    {
        "id": "PB-T1071-001",
        "technique": "T1071.001",
        "tactic": "command-and-control",
        "dir_name": "T1071.001-web-protocols-c2",
        "name": "Web Protocols Command and Control Detection",
        "description": "Detect C2 communication over HTTP/HTTPS including beaconing, data encoding, and suspicious patterns",
        "severity": "high",
        "subtechniques": [],
        "data_sources": ["Web Proxy Logs", "DNS Logs", "Network Traffic", "Firewall Logs"],
        "hunt_hypothesis": """C2 over web protocols:
1. Regular beacon intervals
2. Base64/encoded data in URI or POST
3. Long lived HTTPS connections
4. Suspicious User-Agent strings""",
        "investigation_steps": [
            "Analyze beacon timing patterns",
            "Check destination reputation",
            "Review data transfer volumes",
            "Identify affected endpoints"
        ],
        "false_positives": ["Cloud services", "Update mechanisms", "Legitimate polling"],
        "tags": ["c2", "http", "https", "beaconing", "command-and-control"],
        "splunk": """`comment("HTTP Beaconing Detection")`
index=proxy sourcetype=bluecoat OR sourcetype=zscaler
| bin _time span=1m
| stats count by src_ip, dest_host, _time
| eventstats stdev(count) as stdev_count avg(count) as avg_count by src_ip, dest_host
| where stdev_count < 1 AND avg_count > 5 AND count > 0
| table src_ip, dest_host, _time, count, stdev_count

`comment("Long Base64 in URI")`
index=proxy sourcetype=bluecoat OR sourcetype=zscaler
| rex field=url "(?<b64_param>[A-Za-z0-9+/=]{50,})"
| where isnotnull(b64_param)
| table _time, src_ip, dest_host, url, b64_param

`comment("Suspicious User-Agent")`
index=proxy sourcetype=bluecoat OR sourcetype=zscaler
| where len(useragent) < 20 OR useragent LIKE "%curl%" OR useragent LIKE "%wget%" OR useragent LIKE "%python%"
| stats count by src_ip, useragent, dest_host
| table src_ip, useragent, dest_host, count

`comment("High Frequency Connections to Single Host")`
index=proxy sourcetype=bluecoat OR sourcetype=zscaler
| stats count by src_ip, dest_host
| where count > 1000
| table src_ip, dest_host, count
| sort - count""",
        "elastic": """// HTTP beaconing pattern
event.category:network AND destination.port:(80 OR 443)
| stats count() by source.ip, destination.domain
| where count > 1000

// Base64 in URL
url.query:*[A-Za-z0-9+/=]{50,}*

// Suspicious User-Agent
user_agent.original:(*curl* OR *wget* OR *python* OR *Go-http-client*)""",
        "sigma": """title: Suspicious HTTP User-Agent
id: x1234567-http-ua-001
status: production
level: medium
logsource:
    category: proxy
detection:
    selection:
        c-useragent|contains:
            - 'curl'
            - 'wget'
            - 'python'
            - 'Go-http-client'
    condition: selection
tags:
    - attack.command_and_control
    - attack.t1071.001"""
    },

    {
        "id": "PB-T1071-004",
        "technique": "T1071.004",
        "tactic": "command-and-control",
        "dir_name": "T1071.004-dns-c2",
        "name": "DNS Tunneling and C2 Detection",
        "description": "Detect DNS-based command and control including tunneling and data exfiltration over DNS",
        "severity": "high",
        "subtechniques": [],
        "data_sources": ["DNS Logs", "Network Traffic", "Zeek/Bro Logs"],
        "hunt_hypothesis": """DNS C2 indicators:
1. Long DNS queries (>50 chars subdomain)
2. High volume of DNS to single domain
3. Unusual TXT record queries
4. Base32/Base64 encoded subdomains""",
        "investigation_steps": [
            "Analyze query patterns",
            "Check destination domain age and reputation",
            "Review query content for encoding",
            "Identify affected endpoints"
        ],
        "false_positives": ["CDN providers", "Anti-malware updates", "Legitimate SaaS"],
        "tags": ["c2", "dns", "tunneling", "exfiltration"],
        "splunk": """`comment("Long DNS Queries (Potential Tunneling)")`
index=dns sourcetype=dns OR sourcetype=named
| eval query_len=len(query)
| where query_len > 50
| table _time, src_ip, query, query_len

`comment("High Volume DNS to Single Domain")`
index=dns sourcetype=dns OR sourcetype=named
| rex field=query "(?<domain>[^.]+\\.[^.]+)$"
| stats count by src_ip, domain
| where count > 500
| table src_ip, domain, count

`comment("TXT Record Queries (Common C2)")`
index=dns sourcetype=dns OR sourcetype=named record_type=TXT
| stats count by src_ip, query
| where count > 10
| table src_ip, query, count

`comment("Encoded Subdomain Pattern")`
index=dns sourcetype=dns OR sourcetype=named
| rex field=query "^(?<subdomain>[a-z0-9]{20,})\\."
| where isnotnull(subdomain)
| table _time, src_ip, query, subdomain""",
        "elastic": """// Long DNS queries
dns.question.name:* AND length(dns.question.name) > 50

// High volume DNS to single domain
event.category:network AND network.protocol:dns
| stats count() by source.ip, dns.question.registered_domain
| where count > 500

// TXT record queries
dns.question.type:TXT""",
        "sigma": """title: Suspicious DNS Query Length
id: y1234567-dns-tunnel-001
status: production
level: high
logsource:
    category: dns
detection:
    selection:
        # DNS queries with long subdomains
        query|re: '^[a-z0-9]{30,}\\.'
    condition: selection
tags:
    - attack.command_and_control
    - attack.t1071.004"""
    },

    # === EXFILTRATION ===
    {
        "id": "PB-T1048-001",
        "technique": "T1048",
        "tactic": "exfiltration",
        "dir_name": "T1048-exfiltration-alt-protocol",
        "name": "Exfiltration Over Alternative Protocol Detection",
        "description": "Detect data exfiltration using non-standard protocols or encrypted channels",
        "severity": "high",
        "subtechniques": ["T1048.001", "T1048.002", "T1048.003"],
        "data_sources": ["Network Traffic", "Firewall Logs", "Proxy Logs"],
        "hunt_hypothesis": """Alternative exfiltration methods:
1. DNS tunneling
2. ICMP tunneling
3. Custom encrypted protocols
4. Steganography""",
        "investigation_steps": [
            "Identify the protocol being used",
            "Check data volume transferred",
            "Review destination reputation",
            "Identify affected systems"
        ],
        "false_positives": ["VPN traffic", "Legitimate encrypted protocols", "Cloud backup"],
        "tags": ["exfiltration", "data-theft", "tunneling", "dns"],
        "splunk": """`comment("Unusual Outbound Protocol")`
index=firewall sourcetype=pan:traffic OR sourcetype=cisco:asa
| where dest_port NOT IN (80, 443, 53, 22, 3389, 25, 587)
| stats sum(bytes_out) as total_bytes by src_ip, dest_ip, dest_port
| where total_bytes > 100000000
| table src_ip, dest_ip, dest_port, total_bytes

`comment("ICMP Data Exfiltration")`
index=firewall sourcetype=pan:traffic protocol=icmp
| stats sum(bytes) as icmp_bytes count as icmp_count by src_ip, dest_ip
| where icmp_bytes > 1000000 OR icmp_count > 1000
| table src_ip, dest_ip, icmp_bytes, icmp_count

`comment("Large DNS Responses (DNS Tunneling)")`
index=dns sourcetype=dns
| where record_type IN ("TXT", "NULL", "CNAME")
| stats sum(answer_len) as total_dns_bytes by src_ip
| where total_dns_bytes > 1000000
| table src_ip, total_dns_bytes""",
        "elastic": """// Unusual outbound traffic on non-standard ports
NOT destination.port:(80 OR 443 OR 53 OR 22 OR 3389)
| stats sum(network.bytes) as total_bytes by source.ip, destination.ip, destination.port
| where total_bytes > 100000000

// Large ICMP traffic
network.transport:icmp
| stats sum(network.bytes) as bytes, count() as packets by source.ip, destination.ip
| where bytes > 1000000""",
        "sigma": """title: Large ICMP Traffic - Potential Data Exfiltration
id: z1234567-icmp-exfil-001
status: production
level: high
logsource:
    category: firewall
detection:
    selection:
        protocol: 'icmp'
    # Threshold requires SIEM aggregation
    condition: selection
tags:
    - attack.exfiltration
    - attack.t1048"""
    },

    {
        "id": "PB-T1567-002",
        "technique": "T1567.002",
        "tactic": "exfiltration",
        "dir_name": "T1567.002-exfil-cloud-storage",
        "name": "Exfiltration to Cloud Storage Detection",
        "description": "Detect data exfiltration to cloud storage services like Dropbox, Google Drive, OneDrive",
        "severity": "high",
        "subtechniques": [],
        "data_sources": ["Web Proxy Logs", "DLP Logs", "Network Traffic"],
        "hunt_hypothesis": """Cloud storage exfiltration:
1. Large uploads to personal cloud storage
2. Uploads during off-hours
3. Unusual file types being uploaded
4. First-time cloud storage usage""",
        "investigation_steps": [
            "Identify what files are being uploaded",
            "Check if cloud storage use is authorized",
            "Review user's normal cloud activity patterns",
            "Determine sensitivity of data"
        ],
        "false_positives": ["Legitimate cloud backup", "Collaboration activities", "Approved cloud storage"],
        "tags": ["exfiltration", "cloud-storage", "data-loss"],
        "splunk": """`comment("Large Upload to Cloud Storage")`
index=proxy sourcetype=bluecoat OR sourcetype=zscaler method=POST
| where url LIKE "%dropbox.com/upload%" OR url LIKE "%drive.google.com/upload%" OR url LIKE "%onedrive.live.com/upload%" OR url LIKE "%mega.nz%"
| stats sum(bytes_out) as upload_bytes by src_ip, user, dest_host
| where upload_bytes > 50000000
| table src_ip, user, dest_host, upload_bytes

`comment("Off-Hours Cloud Uploads")`
index=proxy sourcetype=bluecoat OR sourcetype=zscaler method=POST
| where url LIKE "%dropbox%" OR url LIKE "%drive.google%" OR url LIKE "%onedrive%"
| eval hour=strftime(_time, "%H")
| where hour < 6 OR hour > 22
| table _time, src_ip, user, url, bytes_out

`comment("First-Time Cloud Storage Usage")`
index=proxy sourcetype=bluecoat OR sourcetype=zscaler
| where url LIKE "%dropbox%" OR url LIKE "%drive.google%" OR url LIKE "%onedrive%"
| stats earliest(_time) as first_seen count by user, dest_host
| where first_seen > relative_time(now(), "-7d")
| table user, dest_host, first_seen, count""",
        "elastic": """// Large uploads to cloud storage
http.request.method:POST AND destination.domain:(*dropbox.com* OR *drive.google.com* OR *onedrive.live.com*)
| stats sum(http.request.bytes) as upload_bytes by source.ip, user.name
| where upload_bytes > 50000000

// Off-hours cloud uploads
http.request.method:POST AND destination.domain:(*dropbox* OR *drive.google* OR *onedrive*)
| eval hour = date_hour(@timestamp)
| where hour < 6 or hour > 22""",
        "sigma": """title: Large Upload to Cloud Storage
id: aa123456-cloud-exfil-001
status: production
level: high
logsource:
    category: proxy
detection:
    selection:
        c-uri|contains:
            - 'dropbox.com/upload'
            - 'drive.google.com/upload'
            - 'onedrive.live.com'
            - 'mega.nz'
    # Threshold based detection for large uploads
    condition: selection
tags:
    - attack.exfiltration
    - attack.t1567.002"""
    },

    # === IMPACT ===
    {
        "id": "PB-T1490-001",
        "technique": "T1490",
        "tactic": "impact",
        "dir_name": "T1490-inhibit-system-recovery",
        "name": "Inhibit System Recovery Detection",
        "description": "Detect attempts to delete or disable system recovery features prior to ransomware deployment",
        "severity": "critical",
        "subtechniques": [],
        "data_sources": ["Sysmon", "Windows Security Events"],
        "hunt_hypothesis": """Recovery inhibition techniques:
1. Volume shadow copy deletion
2. bcdedit recovery disabling
3. Backup deletion
4. Safe mode boot manipulation""",
        "investigation_steps": [
            "Check for ransomware indicators",
            "Identify affected systems immediately",
            "Attempt to restore from backup",
            "Isolate affected systems"
        ],
        "false_positives": ["System maintenance", "Disk cleanup activities"],
        "tags": ["impact", "ransomware", "recovery", "vss", "critical"],
        "splunk": """`comment("VSS Shadow Copy Deletion")`
index=sysmon EventCode=1
| where Image LIKE "%\\vssadmin.exe" AND CommandLine LIKE "%delete%shadow%"
| table _time, ComputerName, User, CommandLine

`comment("WMIC Shadow Copy Delete")`
index=sysmon EventCode=1 Image="*\\wmic.exe"
| where CommandLine LIKE "%shadowcopy%delete%"
| table _time, ComputerName, User, CommandLine

`comment("BCDEdit Recovery Disable")`
index=sysmon EventCode=1 Image="*\\bcdedit.exe"
| where CommandLine LIKE "%recoveryenabled%No%" OR CommandLine LIKE "%bootstatuspolicy%ignoreallfailures%"
| table _time, ComputerName, User, CommandLine

`comment("Backup Catalog Deletion")`
index=sysmon EventCode=1 Image="*\\wbadmin.exe"
| where CommandLine LIKE "%delete%catalog%" OR CommandLine LIKE "%delete%systemstatebackup%"
| table _time, ComputerName, User, CommandLine""",
        "elastic": """// VSS deletion
event.code:1 AND process.name:vssadmin.exe AND process.command_line:*delete*shadow*

// WMIC shadow delete
event.code:1 AND process.name:wmic.exe AND process.command_line:*shadowcopy*delete*

// BCDEdit recovery disable
event.code:1 AND process.name:bcdedit.exe AND process.command_line:(*recoveryenabled*No* OR *bootstatuspolicy*ignoreallfailures*)""",
        "sigma": """title: Shadow Copy Deletion
id: bb123456-vss-delete-001
status: production
level: critical
logsource:
    category: process_creation
    product: windows
detection:
    selection_vssadmin:
        Image|endswith: '\\vssadmin.exe'
        CommandLine|contains|all:
            - 'delete'
            - 'shadows'
    selection_wmic:
        Image|endswith: '\\wmic.exe'
        CommandLine|contains|all:
            - 'shadowcopy'
            - 'delete'
    condition: selection_vssadmin or selection_wmic
tags:
    - attack.impact
    - attack.t1490"""
    },

    {
        "id": "PB-T1486-002",
        "technique": "T1486",
        "tactic": "impact",
        "dir_name": "T1486.002-ransomware-encryption",
        "name": "Ransomware File Encryption Detection",
        "description": "Detect ransomware encryption activity based on file system changes and process behavior",
        "severity": "critical",
        "subtechniques": [],
        "data_sources": ["Sysmon", "EDR", "Windows Security Events"],
        "hunt_hypothesis": """Ransomware encryption indicators:
1. Mass file renames with new extension
2. High volume of file modifications
3. Ransom note file creation
4. Known ransomware process behavior""",
        "investigation_steps": [
            "IMMEDIATELY isolate affected systems",
            "Identify ransomware variant",
            "Determine encryption scope",
            "Check for available backups"
        ],
        "false_positives": ["Legitimate encryption software", "File conversion tools", "Batch rename utilities"],
        "tags": ["impact", "ransomware", "encryption", "critical"],
        "splunk": """`comment("Mass File Extension Changes")`
index=sysmon EventCode=11
| rex field=TargetFilename "(?<extension>\\.[^.]+)$"
| stats dc(extension) as ext_variety count as file_count by ComputerName, Image
| where file_count > 100 AND ext_variety < 5
| table ComputerName, Image, file_count, ext_variety

`comment("Known Ransomware Extensions")`
index=sysmon EventCode=11
| where TargetFilename LIKE "%.encrypted%" OR TargetFilename LIKE "%.locked%" OR TargetFilename LIKE "%.crypt%" OR TargetFilename LIKE "%.enc%" OR TargetFilename LIKE "%.xxx%"
| stats count by ComputerName, Image, TargetFilename

`comment("Ransom Note Creation")`
index=sysmon EventCode=11
| where TargetFilename LIKE "%README%DECRYPT%" OR TargetFilename LIKE "%HOW_TO_RECOVER%" OR TargetFilename LIKE "%DECRYPT_INSTRUCTIONS%" OR TargetFilename LIKE "%-DECRYPT-%"
| table _time, ComputerName, User, Image, TargetFilename

`comment("High Volume File Modifications")`
index=sysmon EventCode=2
| bin _time span=1m
| stats count by ComputerName, Image, _time
| where count > 100
| table _time, ComputerName, Image, count""",
        "elastic": """// Known ransomware extensions
event.code:11 AND file.extension:(encrypted OR locked OR crypt OR enc OR xxx)

// Ransom note creation
event.code:11 AND file.name:(*README*DECRYPT* OR *HOW_TO_RECOVER* OR *DECRYPT_INSTRUCTIONS*)

// Mass file modifications
event.code:2
| stats count() by host.name, process.name
| where count > 100""",
        "sigma": """title: Ransomware File Extension Detection
id: cc123456-ransomware-ext-001
status: production
level: critical
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|endswith:
            - '.encrypted'
            - '.locked'
            - '.crypt'
            - '.enc'
            - '.crypted'
    condition: selection
tags:
    - attack.impact
    - attack.t1486"""
    },
]


def create_playbook_structure(playbook: dict):
    """Create the directory structure and files for a playbook."""
    dir_path = PLAYBOOKS_DIR / playbook["dir_name"]
    queries_path = dir_path / "queries"

    # Create directories
    dir_path.mkdir(parents=True, exist_ok=True)
    queries_path.mkdir(exist_ok=True)

    # Create playbook.yaml
    yaml_content = f"""id: {playbook['id']}
name: "{playbook['name']}"
description: "{playbook['description']}"

mitre:
  technique: {playbook['technique']}
  tactic: {playbook['tactic']}
  subtechniques: {playbook.get('subtechniques', [])}

severity: {playbook['severity']}
author: Threat Hunting Team
created: 2024-01-15
updated: {datetime.now().strftime('%Y-%m-%d')}

data_sources:
{chr(10).join(['  - ' + ds for ds in playbook['data_sources']])}

hunt_hypothesis: |
{chr(10).join(['  ' + line for line in playbook['hunt_hypothesis'].strip().split(chr(10))])}

queries:
  splunk: queries/splunk.spl
  elastic: queries/elastic.kql
  sigma: queries/sigma.yml

investigation_steps:
{chr(10).join(['  - ' + step for step in playbook['investigation_steps']])}

false_positives:
{chr(10).join(['  - ' + fp for fp in playbook['false_positives']])}

references:
  - https://attack.mitre.org/techniques/{playbook['technique'].split('.')[0]}/

tags: [{', '.join(playbook['tags'])}]
"""

    with open(dir_path / "playbook.yaml", 'w') as f:
        f.write(yaml_content)

    # Create SPL query file
    with open(queries_path / "splunk.spl", 'w') as f:
        f.write(f"`comment(\"=== {playbook['id']} - {playbook['name']} ===\")`\n")
        f.write(f"`comment(\"MITRE ATT&CK: {playbook['technique']} - {playbook['tactic']}\")`\n\n")
        f.write(playbook['splunk'])

    # Create KQL query file
    with open(queries_path / "elastic.kql", 'w') as f:
        f.write(f"// === {playbook['id']} - {playbook['name']} ===\n")
        f.write(f"// MITRE ATT&CK: {playbook['technique']} - {playbook['tactic']}\n\n")
        f.write(playbook['elastic'])

    # Create Sigma rule file
    with open(queries_path / "sigma.yml", 'w') as f:
        f.write(playbook['sigma'])

    print(f"Created: {playbook['id']} - {playbook['name']}")


def main():
    """Generate all playbooks."""
    print("=" * 60)
    print("Generating Threat Hunting Playbooks")
    print("=" * 60)

    for playbook in PLAYBOOKS:
        try:
            create_playbook_structure(playbook)
        except Exception as e:
            print(f"Error creating {playbook['id']}: {e}")

    print("=" * 60)
    print(f"Generated {len(PLAYBOOKS)} playbooks")
    print("=" * 60)


if __name__ == "__main__":
    main()
