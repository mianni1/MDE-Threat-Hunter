param (
    [Parameter(Mandatory=$true)]
    [string]$InputPath,
    
    [Parameter(Mandatory=$true)]
    [string]$OutputPath,
    
    [Parameter(Mandatory=$false)]
    [string]$ReportTitle = "Microsoft Defender for Endpoint Threat Hunting Report",
    
    [Parameter(Mandatory=$false)]
    [string]$SecurityAlertPath,
    
    [Parameter(Mandatory=$false)]
    [string]$CsvPath
)

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12, [Net.SecurityProtocolType]::Tls13

function Write-Log {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "WARNING", "ERROR", "DEBUG")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        "ERROR"   { Write-Host $logMessage -ForegroundColor Red }
        "WARNING" { Write-Host $logMessage -ForegroundColor Yellow }
        "DEBUG"   { Write-Host $logMessage -ForegroundColor Cyan }
        default   { Write-Host $logMessage }
    }
}

function Get-DetectionDescription {
    param (
        [Parameter(Mandatory=$true)]
        [string]$QueryName,
        
        [Parameter(Mandatory=$false)]
        [array]$Results = @()
    )
    
    # Detailed technical descriptions for each detection type including specific indicators and MITRE ATT&CK techniques
    $descriptions = @{
        "lolbas_execution" = @{
            Description = "Detection of Living Off the Land Binaries and Scripts (LOLBAS) execution. These are legitimate Windows tools that can be abused by attackers for malicious purposes."
            Technical = "This alert triggers when a known legitimate Windows tool is used with suspicious parameters or execution context. Detected binaries include: certutil.exe with -encode/-decode flags, regsvr32.exe with suspicious DLL loads, mshta.exe loading remote HTA files, rundll32.exe with non-standard entry points, or unusual uses of bitsadmin.exe, installutil.exe, or msbuild.exe with non-standard parameters."
            MitreAttack = "T1218 (Signed Binary Proxy Execution), T1036 (Masquerading), T1059 (Command and Scripting Interpreter)"
            Impact = "This may indicate an attacker is using legitimate system tools to evade detection while performing malicious activities."
            Remediation = "Investigate the process execution context, command line arguments, and user account. Consider implementing application control policies."
        }
        "windows_credential_dumping" = @{
            Description = "Detection of possible credential harvesting activities on Windows systems, including mimikatz, lsass memory access, or registry extraction."
            Technical = "Alert triggered by one of the following high-risk indicators: (1) Process accessing LSASS memory via MiniDump APIs, (2) Use of tools like mimikatz, procdump, pwdump, secretsdump, or wce with specific command line parameters targeting credential access, (3) Registry commands targeting HKLM\\SAM, HKLM\\SYSTEM, or HKLM\\SECURITY hives, (4) Memory dumping commands containing MiniDump, DuplicateHandle, LogonPasswords, sekurlsa, or wdigest parameters."
            MitreAttack = "T1003 (OS Credential Dumping), T1552 (Unsecured Credentials), T1555 (Credentials from Password Stores)"
            Impact = "Attackers may be attempting to extract passwords, hashes, or tickets to escalate privileges or move laterally."
            Remediation = "Isolate the affected system, investigate the process involved, and consider credential rotation for compromised accounts."
        }
        "windows_defense_evasion" = @{
            Description = "Detection of techniques used to bypass security controls, disable defenses, or hide malicious activities on Windows systems."
            Technical = "This alert is triggered by: (1) Commands that stop or disable security services like Windows Defender, firewall services, or other EDR solutions, (2) Tampering with Windows Event Logging or security monitoring, (3) Use of known AMSI bypass techniques, (4) Process hollowing or injection indicators such as unusual memory allocations in remote processes via VirtualAllocEx or WriteProcessMemory, (5) Unusual driver loading operations with suspicious digital signatures."
            MitreAttack = "T1562 (Impair Defenses), T1112 (Modify Registry), T1070 (Indicator Removal on Host), T1055 (Process Injection)"
            Impact = "Security tools may be compromised, allowing attackers to operate undetected."
            Remediation = "Verify integrity of security tools, review disabled services, and investigate suspicious registry modifications."
        }
        "linux_privilege_escalation" = @{
            Description = "Detection of attempts to gain higher-level permissions on Linux systems through vulnerabilities, misconfigurations, or credential theft."
            Technical = "Alert triggered by: (1) Commands that modify permissions like 'chmod u+s', 'setuid', 'setgid', or 'chown root', (2) Manipulation of sensitive files including '/etc/passwd', '/etc/shadow', '/etc/sudoers', (3) Changes to sudo groups via 'usermod -G sudo/wheel/admin', (4) Use of LD_PRELOAD for library hijacking, (5) Modifications to capabilities via 'cap_set', or (6) Operations involving SUID/SGID binaries. Each event contains the specific command, initiating process, and user context."
            MitreAttack = "T1548 (Abuse Elevation Control Mechanism), T1169 (Sudo), T1068 (Exploitation for Privilege Escalation)"
            Impact = "Attackers may gain root-level access, allowing complete system compromise."
            Remediation = "Patch system vulnerabilities, review sudo configurations, and audit user permissions. Specifically check for unauthorized SUID/SGID binaries and unexpected entries in sudoers."
        }
        "macos_malware_detection" = @{
            Description = "Detection of known malicious software or suspicious behavior patterns on macOS systems."
            Technical = "This detection is triggered by multiple indicators: (1) Binary execution from non-standard locations like /tmp, /var/tmp, or ~/Downloads with suspicious entitlements, (2) Unsigned executables or executables with invalid signatures, (3) Processes with suspicious networking behavior establishing connections to known C2 domains or unusual ports, (4) Processes executing with suspicious command line parameters that indicate obfuscation techniques, (5) Creation or modification of launch agents/daemons in non-standard paths."
            MitreAttack = "T1204 (User Execution), T1059.004 (Command and Scripting Interpreter: Unix Shell), T1553.001 (Subvert Trust Controls: Gatekeeper Bypass)"
            Impact = "System may be compromised, potentially allowing data theft, ransomware, or use as an attack platform."
            Remediation = "Isolate the affected system, scan with updated antimalware tools, and investigate persistence mechanisms. Check for unauthorized launch agents and daemon files."
        }
        "ransomware_detection" = @{
            Description = "Detection of possible ransomware activity, including mass file modifications, encryption behaviors, or ransom notes."
            Technical = "Alert triggered by: (1) High rates of file modifications with extensions changing to known ransomware patterns (.encrypted, .locked, .crypted, etc.), (2) Commands or processes accessing cryptographic APIs followed by multiple file writes, (3) Creation of known ransomware artifacts like DECRYPT_INSTRUCTION.TXT, README.txt with ransom language, (4) Volume Shadow Copy deletion via vssadmin, wmic, or PowerShell, (5) Processes exhibiting entropy changes in file writing operations indicative of encryption."
            MitreAttack = "T1486 (Data Encrypted for Impact), T1490 (Inhibit System Recovery), T1485 (Data Destruction)"
            Impact = "Critical data may be encrypted and held for ransom, causing operational disruption."
            Remediation = "Immediately isolate affected systems, restore from clean backups if available, and identify the initial infection vector."
        }
        "anomalous_logon_behavior" = @{
            Description = "Detection of unusual authentication patterns such as off-hours access, multiple failed attempts, or authentications from unusual locations."
            Technical = "This detection analyzes multiple authentication factors against established baselines: (1) Authentications occurring outside typical working hours (>2 standard deviations from historical patterns), (2) Multiple failed logon attempts followed by success, (3) Authentication from IP addresses, ASNs, or geographies never seen before, (4) Unusual user-agent strings in authentication requests, (5) Authentication to systems outside typical job function, or (6) Deviations in logon frequency, timing, or session duration compared to historical patterns."
            MitreAttack = "T1078 (Valid Accounts), T1110 (Brute Force), T1550 (Use Alternate Authentication Material)"
            Impact = "May indicate compromised credentials or an unauthorized access attempt."
            Remediation = "Verify legitimacy with the user, force password resets for affected accounts, and enable MFA where available."
        }
        "identity_privilege_changes" = @{
            Description = "Detection of unexpected changes to user permissions, group memberships, or privilege assignments."
            Technical = "Alert triggered by: (1) Addition of users to privileged groups (Administrators, Domain Admins, Schema Admins, Enterprise Admins), (2) Assignment of sensitive user rights via Local Security Policy or Group Policy (SeDebugPrivilege, SeTcbPrivilege, etc.), (3) Unexpected changes to security descriptors of privileged groups, (4) Modification of AdminSDHolder container in Active Directory, (5) Unusual operations involving privileged certificate templates or certificate authorities."
            MitreAttack = "T1098 (Account Manipulation), T1484 (Domain Policy Modification), T1134 (Access Token Manipulation)"
            Impact = "Attackers may be elevating permissions to gain greater access to systems and data."
            Remediation = "Revert unauthorized changes, investigate the account that made the changes, and review access control policies."
        }
        "linux_unusual_connections" = @{
            Description = "Detection of network connections from Linux hosts to suspicious external addresses or unusual ports."
            Technical = "This detection identifies: (1) Outbound connections to known malicious IPs, TOR exit nodes, or suspicious geographic regions, (2) Connections using unusual ports not associated with standard services (not 80, 443, 22, etc.), (3) Connections from unexpected system processes like bash, python, perl directly to external IPs, (4) Unexpected DNS resolution patterns like DNS tunneling or domain generation algorithms, (5) Network command execution (wget, curl, nc) from non-standard locations or with obfuscated payloads."
            MitreAttack = "T1571 (Non-Standard Port), T1572 (Protocol Tunneling), T1105 (Ingress Tool Transfer), T1041 (Exfiltration Over C2 Channel)"
            Impact = "May indicate command and control communications or data exfiltration."
            Remediation = "Investigate the process establishing connections, analyze the destination for malicious reputation, and consider network controls."
        }
        "macos_persistence_mechanisms" = @{
            Description = "Detection of techniques used by attackers to maintain access to macOS systems across reboots or credential changes."
            Technical = "Alert triggered by: (1) Creation or modification of launch agents or daemons in /Library/LaunchAgents, /Library/LaunchDaemons, ~/Library/LaunchAgents with unusual code or command execution patterns, (2) Modifications to login items in ~/Library/Application Support/com.apple.backgroundtaskmanagementagent/, (3) Unauthorized login hooks in /Library/LoginHook, (4) Suspicious kernel extensions or system extensions, (5) Creation of new privileged helper tools with unusual code signing properties, (6) Modification of startup items in /Library/StartupItems."
            MitreAttack = "T1547.011 (Boot or Logon Autostart Execution: Plist Modification), T1543.001 (Create or Modify System Process: Launch Agent), T1537 (Transfer Files to Cloud Account)"
            Impact = "Attackers may retain access even after remediation attempts."
            Remediation = "Remove unauthorized launch agents, startup items, and cronjobs, and verify system integrity."
        }
        "macos_suspicious_binaries" = @{
            Description = "Detection of unsigned, newly created, or modified executable files on macOS with suspicious characteristics."
            Technical = "This detection looks for: (1) Unsigned binaries executed outside standard directories, (2) Binaries with tampered signatures or explicit GateKeeper bypasses, (3) Binaries with suspicious entitlements requesting unusual permissions, (4) Mach-O files with indicators of obfuscation such as packed sections or string encryption, (5) Binaries observed using suspicious syscalls (ptrace, task_for_pid) for monitoring or process injection, (6) Binaries dynamically loading unexpected libraries or frameworks."
            MitreAttack = "T1204 (User Execution), T1553 (Subvert Trust Controls), T1027 (Obfuscated Files or Information), T1564 (Hide Artifacts)"
            Impact = "May indicate presence of malicious code or tampering with system files."
            Remediation = "Quarantine and analyze suspicious files, verify code signatures, and check for known malware indicators."
        }
        "suspicious_powershell_commands" = @{
            Description = "Detection of PowerShell commands with suspicious parameters, encoding, or known malicious patterns."
            Technical = "Alert triggers on: (1) Execution with encoded commands (-enc, -encodedcommand) with base64 payloads, (2) Use of obfuscation techniques including character substitution, string concatenation, or reversing, (3) PowerShell downgrade attacks bypassing ScriptBlock logging (-version 2.0), (4) Use of reflection to access low-level .NET APIs or shellcode injection, (5) Commands featuring known malicious patterns like Invoke-Mimikatz, Invoke-Expression with web requests, or commands disabling security features, (6) PowerShell execution with unusual parent processes."
            MitreAttack = "T1059.001 (Command and Scripting Interpreter: PowerShell), T1027 (Obfuscated Files or Information), T1562.001 (Impair Defenses: Disable or Modify Tools)"
            Impact = "PowerShell is commonly used for post-exploitation activities due to its power and flexibility."
            Remediation = "Review command content, implement script block logging, and consider constrained language mode."
        }
        "suspicious_cloud_activity" = @{
            Description = "Detection of unusual access patterns or configuration changes in cloud environments."
            Technical = "This detection identifies: (1) First-time privileged API calls from users, especially from new IP addresses, (2) Security configuration changes such as disabling MFA, logging, or security controls, (3) Mass data access operations not matching historical patterns, (4) Unusual permission changes giving excessive access rights, (5) Creation of backdoor access methods like service principals or new admin accounts, (6) Geographic anomalies in API access locations, (7) Unusual infrastructure changes like outbound firewall rule modifications or unusual resource deployments."
            MitreAttack = "T1078.004 (Valid Accounts: Cloud Accounts), T1136 (Create Account), T1530 (Data from Cloud Storage Object), T1537 (Transfer Files to Cloud Account)"
            Impact = "May indicate unauthorized access to cloud resources or preparation for data exfiltration."
            Remediation = "Review IAM permissions, enable additional monitoring, and verify the legitimacy of configuration changes."
        }
        "unusual_network_connections" = @{
            Description = "Detection of network connections to rare destinations, known bad IP ranges, or with unusual timing patterns."
            Technical = "Alert triggered by: (1) Connections to IPs with low prevalence scores in your environment, (2) Connections to known malicious IP addresses or newly registered domains, (3) Connections to countries or regions not typically seen in your network traffic, (4) Internal systems establishing connections using unusual protocols or ports, (5) Connections showing signs of beaconing behavior with regular timing patterns, (6) Connections with unusual bandwidth consumption patterns indicating potential data exfiltration."
            MitreAttack = "T1071 (Application Layer Protocol), T1043 (Commonly Used Port), T1571 (Non-Standard Port), T1090 (Proxy), T1572 (Protocol Tunneling)"
            Impact = "May indicate lateral movement attempts, command and control activity, or data exfiltration."
            Remediation = "Investigate the source process, analyze traffic patterns, and consider implementing network segmentation."
        }
        "data_exfiltration_detection" = @{
            Description = "Detection of potential data being moved outside the organization through unusual channels or volumes."
            Technical = "This detection identifies: (1) Large outbound data transfers exceeding normal baselines for users or systems, (2) Data transfers to new or unusual domains/IP addresses, particularly file sharing or storage services, (3) Suspicious file encryption or compression before data transfer, (4) Use of non-standard ports or protocols for outbound communication, (5) DNS tunneling patterns with abnormal DNS request sizes or frequencies, (6) Unusual web uploads via HTTP POST methods with large payloads, (7) Email patterns showing attachments sent to external addresses with unusual file types or volumes."
            MitreAttack = "T1048 (Exfiltration Over Alternative Protocol), T1567 (Exfiltration Over Web Service), T1041 (Exfiltration Over C2 Channel), T1052 (Exfiltration Over Physical Medium)"
            Impact = "Sensitive information may be being stolen or transferred to unauthorized locations."
            Remediation = "Identify the data being transferred, block suspicious destinations, and implement DLP controls."
        }
        "windows_lateral_movement" = @{
            Description = "Detection of techniques used to move from one system to another within the network environment."
            Technical = "Alert triggered by: (1) Remote process creation via WMI, PowerShell remoting, or PsExec, (2) Remote service creation or manipulation, (3) Pass-the-hash or pass-the-ticket techniques with credential reuse across systems, (4) SMB traffic patterns indicating lateral movement such as admin$ share access followed by executable writes, (5) RDP connections from unusual source systems, (6) Evidence of remote Windows Management Instrumentation (WMI) execution, (7) Use of tools like LaZagne, mimikatz, or Bloodhound for privilege escalation and lateral movement."
            MitreAttack = "T1021 (Remote Services), T1550 (Use Alternate Authentication Material), T1570 (Lateral Tool Transfer), T1563 (Remote Service Session Hijacking)"
            Impact = "Attackers may be expanding their foothold in the environment after initial compromise."
            Remediation = "Segment networks, implement least privilege, and monitor for pass-the-hash or pass-the-ticket attacks."
        }
        "windows_persistence_mechanisms" = @{
            Description = "Detection of techniques used by attackers to maintain access to Windows systems across reboots or credential changes."
            Technical = "This detection looks for: (1) Registry modifications to run/runonce keys, (2) Scheduled task creation with unusual command execution or timing, (3) Windows service installations or modifications with suspicious binaries or parameters, (4) WMI event subscription creation for persistence, (5) Startup folder additions, (6) COM hijacking via registry modifications, (7) Boot or logon autostart execution through various Windows-specific mechanisms, (8) DLL search order hijacking attempts, or (9) Changes to Group Policy Objects for persistence."
            MitreAttack = "T1547 (Boot or Logon Autostart Execution), T1543 (Create or Modify System Process), T1546 (Event Triggered Execution), T1037 (Boot or Logon Initialization Scripts)"
            Impact = "Attackers may retain access even after initial remediation attempts."
            Remediation = "Clean startup locations, scheduled tasks, and registry persistence points, and monitor for suspicious WMI subscriptions."
        }
    }
    
    # Get base name without extension and path
    $baseName = ($QueryName -split '/')[-1] -replace '\.kql$|-' -replace '\.csv$', ''
    
    # Try to match with existing descriptions
    foreach ($key in $descriptions.Keys) {
        if ($baseName -match $key) {
            # Extract specific technical indicators from results if available
            if ($Results -and $Results.Count -gt 0) {
                # Try to extract the most relevant fields for this detection type
                $specificIndicators = @()
                
                # Look for common fields that might contain specific indicators
                $relevantFields = @(
                    "FileName", "ProcessCommandLine", "RemoteIP", "AccountName",
                    "RegistryKey", "RegistryValueName"
                )
                
                foreach ($field in $relevantFields) {
                    $values = $Results | ForEach-Object {
                        if ($_.PSObject.Properties.Name -contains $field) {
                            $_.$field
                        }
                    } | Where-Object { $_ } | Select-Object -Unique -First 3
                    
                    if ($values) {
                        foreach ($value in $values) {
                            if ($value -and $value -ne "REDACTED" -and $value -ne "MASKED") {
                                $specificIndicators += "• $field`: $value"
                            }
                        }
                    }
                }
                
                if ($specificIndicators.Count -gt 0) {
                    $descriptions[$key]["SpecificIndicators"] = "Specific indicators from this detection include:`n" + ($specificIndicators -join "`n")
                }
            }
            
            return $descriptions[$key]
        }
    }
    
    # Default description if no match found
    return @{
        Description = "Detection of potentially suspicious activity related to $($baseName -replace '_', ' ')."
        Technical = "This detection identifies abnormal or potentially malicious behaviors that match patterns associated with $($baseName -replace '_', ' ') techniques."
        Impact = "The security impact depends on the specific activity detected. Further investigation is recommended."
        Remediation = "Review the specific events detected and investigate the involved systems and accounts."
    }
}

function Format-MarkdownTable {
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject[]]$Data,
        
        [Parameter(Mandatory=$false)]
        [string[]]$IncludeProperties = @()
    )
    
    if ($Data.Count -eq 0) {
        return ""
    }
    
    # If no properties specified, use all properties from the first item
    if ($IncludeProperties.Count -eq 0) {
        $IncludeProperties = $Data[0].PSObject.Properties.Name
    }
    
    # Create header
    $table = "| " + ($IncludeProperties -join " | ") + " |`n"
    $table += "| " + (($IncludeProperties | ForEach-Object { "-" * $_.Length }) -join " | ") + " |`n"
    
    # Add rows
    foreach ($item in $Data) {
        $row = "| "
        foreach ($prop in $IncludeProperties) {
            $value = if ($item.$prop) { $item.$prop } else { "" }
            $row += "$value | "
        }
        $table += "$row`n"
    }
    
    return $table
}

function New-HTMLReport {
    [CmdletBinding()]

    param (
        [Parameter(Mandatory=$true)]
        [hashtable]$QueryResults,
        
        [Parameter(Mandatory=$true)]
        [string]$OutputPath,
        
        [Parameter(Mandatory=$false)]
        [string]$ReportTitle = "Microsoft Defender for Endpoint Threat Hunting Report"
    )
    
    try {
        Write-Log "Generating HTML report"
        
        $reportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $totalFindings = 0
        foreach ($key in $QueryResults.Keys) {
            $totalFindings += $QueryResults[$key].Count
        }
        
        $htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$ReportTitle</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;
            margin: 20px;
            color: #333;
            line-height: 1.6;
        }
        .header {
            background-color: #0078d4;
            color: white;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .summary {
            background-color: #f0f0f0;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .findings-section {
            margin-bottom: 30px;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 15px;
        }
        .findings-section h2 {
            margin-top: 0;
            border-bottom: 1px solid #ddd;
            padding-bottom: 10px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 15px;
        }
        th, td {
            text-align: left;
            padding: 8px;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f2f2f2;
        }
        .severity-high {
            background-color: #ffdddd;
        }
        .severity-medium {
            background-color: #ffffcc;
        }
        .severity-low {
            background-color: #e6f7ff;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
        .footer {
            text-align: center;
            margin-top: 20px;
            font-size: 12px;
            color: #666;
        }
        .status-badge {
            display: inline-block;
            padding: 5px 10px;
            border-radius: 15px;
            font-weight: bold;
            color: white;
        }
        .status-healthy {
            background-color: #4CAF50;
        }
        .status-warning {
            background-color: #FF9800;
        }
        .status-critical {
            background-color: #F44336;
        }
        .chart-container {
            height: 250px;
            margin-bottom: 20px;
        }
        .detection-details {
            margin-top: 15px;
            padding: 10px;
            background-color: #f9f9f9;
            border: 1px solid #ddd;
            border-radius: 5px;
        }
        .technical-details {
            margin-top: 10px;
            padding: 10px;
            background-color: #f0f0f0;
            border: 1px solid #ccc;
            border-radius: 5px;
        }
        .mitre-techniques {
            margin-top: 10px;
            font-weight: bold;
        }
        .specific-indicators {
            margin-top: 10px;
            padding: 10px;
            background-color: #e8f5e9;
            border: 1px solid #a5d6a7;
            border-radius: 5px;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>$ReportTitle</h1>
        <p>Generated on $reportDate</p>
    </div>
    <div class="summary">
        <h2>Executive Summary</h2>
        <p>
            This report contains results from Microsoft Defender for Endpoint Advanced Hunting queries. 
            Total findings: <strong>$totalFindings</strong> across <strong>$($QueryResults.Keys.Count)</strong> query types.
        </p>
"@

        if ($totalFindings -eq 0) {
            $htmlContent += '<p><span class="status-badge status-healthy">No Security Findings</span></p>'
        }
        elseif ($totalFindings -lt 10) {
            $htmlContent += '<p><span class="status-badge status-warning">Findings Detected</span></p>'
        }
        else {
            $htmlContent += '<p><span class="status-badge status-critical">Multiple Findings</span></p>'
        }

        $htmlContent += '</div>'
        
        foreach ($queryName in $QueryResults.Keys) {
            $results = $QueryResults[$queryName]
            
            if ($results -and $results.Count -gt 0) {
                $displayName = $queryName -replace '_', ' ' -replace '.kql', '' -replace '.csv', ''
                $displayName = (Get-Culture).TextInfo.ToTitleCase($displayName)
                
                $severity = "Medium"
                $severityClass = "severity-medium"
                if ($queryName -match "(credential_dumping|defense_evasion|ransomware|malware|privilege)") {
                    $severity = "High"
                    $severityClass = "severity-high"
                }
                elseif ($queryName -match "(monitoring|activity)") {
                    $severity = "Low"
                    $severityClass = "severity-low"
                }

                $detectionDescription = Get-DetectionDescription -QueryName $queryName
                
                $htmlContent += @"
    <div class="findings-section">
        <h2>$displayName</h2>
        <p>Results: <strong>$($results.Count)</strong> | Severity: <strong>$severity</strong></p>
        
        <!-- Add detailed detection description section with technical details -->
        <div class="detection-details">
            <h3>Detection Details</h3>
            <p>$($detectionDescription.Description)</p>
            
            <h4>Technical Indicators</h4>
            <div class="technical-details">
                <p>$($detectionDescription.Technical)</p>
                
                <div class="mitre-techniques">
                    <strong>MITRE ATT&CK Techniques:</strong> $($detectionDescription.MitreAttack)
                </div>
                
                $(if ($detectionDescription.SpecificIndicators) {
                    "<div class='specific-indicators'><h5>Observed Indicators in This Detection</h5><pre>$($detectionDescription.SpecificIndicators)</pre></div>"
                })
            </div>
            
            <h4>Potential Impact</h4>
            <p>$($detectionDescription.Impact)</p>
            
            <h4>Recommended Actions</h4>
            <p>$($detectionDescription.Remediation)</p>
        </div>
        
        <h3>Detected Events</h3>
        <table>
            <tr>
"@
                if ($results.Count -gt 0) {
                    $headers = $results[0].PSObject.Properties.Name
                    foreach ($header in $headers) {
                        $htmlContent += "<th>$header</th>"
                    }
                }
                
                $htmlContent += "</tr>"
                
                $limitedResults = $results | Select-Object -First 100
                foreach ($row in $limitedResults) {
                    $htmlContent += "<tr class=`"$severityClass`">"
                    foreach ($header in $headers) {
                        $value = $row.$header -replace '<', '&lt;' -replace '>', '&gt;'
                        
                        if ($header -in @("DeviceName", "DeviceId", "AccountName", "AccountDomain", "IPAddress", "RemoteIP", "CommandLine", "FilePath", "RegistryKey")) {
                            $value = switch ($header) {
                                "DeviceName" { "DEVICE-NAME" }
                                "DeviceId" { "DEVICE-ID" }
                                "AccountName" { "USERNAME" }
                                "AccountDomain" { "DOMAIN" }
                                "IPAddress" { "0.0.0.0" }
                                "RemoteIP" { "0.0.0.0" }
                                "CommandLine" { "COMMAND-LINE" }
                                "FilePath" { "FILE-PATH" }
                                "RegistryKey" { "REGISTRY-KEY" }
                                default { "REDACTED" }
                            }
                        }
                        
                        $htmlContent += "<td>$value</td>"
                    }
                    $htmlContent += "</tr>"
                }
                
                if ($results.Count -gt 100) {
                    $htmlContent += @"
            <tr>
                <td colspan="$($headers.Count)" style="text-align: center; font-style: italic;">
                    Showing 100 of $($results.Count) results. See exported CSV for complete data.
                </td>
            </tr>
"@
                }
                
                $htmlContent += @"
        </table>
    </div>
"@
            }
        }
        
        $htmlContent += @"
    <div class="footer">
        <p>Generated by AutoThreatHunts | Powered by Microsoft Defender for Endpoint Advanced Hunting</p>
    </div>
</body>
</html>
"@
        
        $outputDir = Split-Path -Path $OutputPath -Parent
        if (-not (Test-Path $outputDir)) {
            New-Item -Path $outputDir -ItemType Directory -Force | Out-Null
        }
        
        Set-Content -Path $OutputPath -Value $htmlContent -Force
        Write-Log "HTML report generated successfully at $OutputPath"
        return $true
    }
    catch {
        Write-Log "Error generating HTML report: $_" -Level ERROR
        return $false
    }
}

function New-SecurityAlertReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [hashtable]$QueryResults
    )
    
    try {
        Write-Log "Generating SARIF report for GitHub Security tab"
        
        $sarif = @{
            '$schema' = "https://json.schemastore.org/sarif-2.1.0.json"
            version = "2.1.0"
            runs = @(
                @{
                    runAutomationDetails = @{
                        id = "security-scan/$(Get-Date -Format 'yyyyMMdd')"
                        guid = [Guid]::NewGuid().ToString()
                        correlationGuid = [Guid]::NewGuid().ToString()
                    }
                    tool = @{
                        driver = @{
                            name = "Security Analysis Tool"
                            version = "1.0"
                            informationUri = "https://github.com/security"
                            semanticVersion = "1.0.0"
                            downloadUri = $null
                            organisation = "Security"
                            supportedTaxonomies = @(
                                @{
                                    name = "Security"
                                    index = 0
                                }
                            )
                            rules = @()
                        }
                    }
                    results = @()
                    originalUriBaseIds = @{
                        SRCROOT = @{
                            uri = "file:///"
                            description = @{
                                text = "Base file path for all source files"
                            }
                        }
                    }
                }
            )
        }
        
        $ruleIndex = 1
        foreach ($queryName in $QueryResults.Keys) {
            $results = $QueryResults[$queryName]
            
            if ($results -and $results.Count -gt 0) {
                $displayName = $queryName -replace '_', ' ' -replace '.kql', '' -replace '.csv', ''
                $displayName = (Get-Culture).TextInfo.ToTitleCase($displayName)
                
                $severity = "warning"
                if ($queryName -match "(credential_dumping|defense_evasion|ransomware|malware|privilege)") {
                    $severity = "error"
                }
                elseif ($queryName -match "(monitoring|activity)") {
                    $severity = "note"
                }
                
                $ruleId = "MDE$ruleIndex"
                $detectionDescription = Get-DetectionDescription -QueryName $queryName
                $rule = @{
                    id = $ruleId
                    name = $displayName.Replace(" ", "")
                    shortDescription = @{
                        text = $displayName
                    }
                    fullDescription = @{
                        text = "$($detectionDescription.Description) Technical details: $($detectionDescription.Technical)"
                    }
                    help = @{
                        text = "Technical Details: $($detectionDescription.Technical)\n\nImpact: $($detectionDescription.Impact)\n\nMITRE ATT&CK: $($detectionDescription.MitreAttack)\n\nRemediation: $($detectionDescription.Remediation)"
                        markdown = "## Detection Details\n\n### Technical Indicators\n$($detectionDescription.Technical)\n\n### MITRE ATT&CK Mapping\n$($detectionDescription.MitreAttack)\n\n### Impact\n$($detectionDescription.Impact)\n\n### Recommended Actions\n$($detectionDescription.Remediation)"
                    }
                    helpUri = "https://github.com/security"
                    properties = @{
                        precision = "high"
                        tags = @("security", "defender", "hunting")
                        "security-severity" = switch ($severity) {
                            "error" { "8.0" }
                            "warning" { "5.5" }
                            "note" { "3.0" }
                            default { "5.5" }
                        }
                        "security-notes" = $detectionDescription.Impact
                    }
                    defaultConfiguration = @{
                        level = $severity
                        enabled = $true
                        rank = -1
                    }
                }
                
                $sarif.runs[0].tool.driver.rules += $rule
                
                foreach ($detection in $results) {
                    $timestamp = (Get-Date).Date.ToString("yyyy-MM-dd")
                    $deviceName = "DEVICE-NAME"
                    $deviceId = "DEVICE-ID"
                    $accountName = "USERNAME"
                    $message = "$displayName detection (see Security tab for details)"
                    
                    $result = @{
                        ruleId = $ruleId
                        level = $severity
                        message = @{
                            text = $message
                        }
                        locations = @(
                            @{
                                physicalLocation = @{
                                    artifactLocation = @{
                                        uri = "file.ext"
                                        uriBaseId = "SRCROOT"
                                    }
                                    region = @{
                                        startLine = 1
                                        startColumn = 1
                                        endLine = 1
                                        endColumn = 1
                                    }
                                }
                            }
                        )
                        partialFingerprints = @{
                            "primaryLocationLineHash" = [System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes("$ruleId-$timestamp"))).Replace("-", "").ToLower()
                        }
                        properties = @{
                            deviceName = $deviceName
                            deviceId = $deviceId
                            timestamp = $timestamp
                            queryName = $queryName
                            isPrivateResult = $true
                        }
                    }
                    
                    foreach ($prop in $detection.PSObject.Properties) {
                        $sanitisedValue = switch ($prop.Name) {
                            "DeviceName" { "DEVICE-NAME" }
                            "DeviceId" { "DEVICE-ID" }
                            "Timestamp" { $timestamp }
                            "TimeGenerated" { $timestamp }
                            "CommandLine" { "COMMAND-LINE" }
                            "AccountName" { "USERNAME" }
                            "AccountDomain" { "DOMAIN" }
                            "FileName" { "FILE-NAME" }
                            "FilePath" { "FILE-PATH" }
                            "RegistryKey" { "REGISTRY-KEY" }
                            "PreviousRegistryKey" { "REGISTRY-KEY" }
                            "RegistryValueName" { "REGISTRY-VALUE" }
                            "IPAddress" { "0.0.0.0" }
                            "RemoteIP" { "0.0.0.0" }
                            "RemoteUrl" { "https://example.com" }
                            default { 
                                if ($prop.Value -is [string] -and ($prop.Value -match "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}" -or 
                                                                   $prop.Value -match "([A-Za-z0-9]+[\.-])+[A-Za-z0-9]{2,}" -or
                                                                   $prop.Value -match "[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}")) {
                                    "REDACTED"
                                } else {
                                    $prop.Value
                                }
                            }
                        }
                        if ($prop.Name -notin @("DeviceName", "DeviceId", "Timestamp", "TimeGenerated")) {
                            $result.properties[$prop.Name] = $sanitisedValue
                        }
                    }
                    
                    $sarif.runs[0].results += $result
                }
                
                $ruleIndex++
            }
        }
        
        $outputDir = Split-Path -Path $SecurityAlertPath -Parent
        if (-not (Test-Path $outputDir)) {
            New-Item -Path $outputDir -ItemType Directory -Force | Out-Null
        }
        
        $sarifJson = $sarif | ConvertTo-Json -Depth 10 -Compress
        Set-Content -Path $SecurityAlertPath -Value $sarifJson -Force
        
        Write-Log "SARIF report generated successfully at $SecurityAlertPath"
        return $true
    }
    catch {
        Write-Log "Error generating SARIF report: $_" -Level ERROR
        return $false
    }
}

function Export-FindingsToCsv {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [hashtable]$QueryResults,
        
        [Parameter(Mandatory=$true)]
        [string]$CsvPath
    )
    
    try {
        Write-Log "Exporting findings to consolidated CSV file: $CsvPath"
        
        $allFindings = @()
        
        foreach ($queryName in $QueryResults.Keys) {
            $results = $QueryResults[$queryName]
            
            if ($results -and $results.Count -gt 0) {
                foreach ($finding in $results) {
                    $findingObj = [PSCustomObject]@{
                        QueryName = $queryName
                        Timestamp = $finding.Timestamp
                    }
                    
                    # Copy all properties from the finding
                    foreach ($prop in $finding.PSObject.Properties) {
                        if ($prop.Name -ne "Timestamp") { # Already added
                            $sanitizedValue = switch ($prop.Name) {
                                "DeviceName" { "DEVICE-NAME" }
                                "DeviceId" { "DEVICE-ID" }
                                "AccountName" { "USERNAME" }
                                "AccountDomain" { "DOMAIN" }
                                "IPAddress" { "0.0.0.0" }
                                "RemoteIP" { "0.0.0.0" }
                                "CommandLine" { "COMMAND-LINE" }
                                "FilePath" { "FILE-PATH" }
                                "RegistryKey" { "REGISTRY-KEY" }
                                default { 
                                    if ($prop.Value -is [string] -and ($prop.Value -match "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}" -or 
                                                                       $prop.Value -match "([A-Za-z0-9]+[\.-])+[A-Za-z0-9]{2,}" -or
                                                                       $prop.Value -match "[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}")) {
                                        "REDACTED"
                                    } else {
                                        $prop.Value
                                    }
                                }
                            }
                            $findingObj | Add-Member -MemberType NoteProperty -Name $prop.Name -Value $sanitizedValue
                        }
                    }
                    
                    $allFindings += $findingObj
                }
            }
        }
        
        if ($allFindings.Count -gt 0) {
            $outputDir = Split-Path -Path $CsvPath -Parent
            if (-not (Test-Path $outputDir)) {
                New-Item -Path $outputDir -ItemType Directory -Force | Out-Null
            }
            
            $allFindings | Export-Csv -Path $CsvPath -NoTypeInformation -Force
            Write-Log "Exported $($allFindings.Count) findings to $CsvPath"
            return $true
        }
        else {
            Write-Log "No findings to export to CSV" -Level WARNING
            return $false
        }
    }
    catch {
        Write-Log "Error exporting findings to CSV: $_" -Level ERROR
        return $false
    }
}

try {
    Write-Log "Starting report generation from: $InputPath" -Level "INFO"
    
    Write-Log "Searching for CSV result files in $InputPath"
    $csvFiles = Get-ChildItem -Path $InputPath -Filter "*.csv" -ErrorAction SilentlyContinue
    
    if (-not $csvFiles -or $csvFiles.Count -eq 0) {
        Write-Log "No CSV files found in $InputPath" -Level WARNING
        exit 0
    }
    
    $queryResults = @{}
    
    foreach ($csvFile in $csvFiles) {
        $queryName = $csvFile.BaseName
        Write-Log "Processing query results: $queryName"
        
        $results = Import-Csv -Path $csvFile.FullName -ErrorAction SilentlyContinue
        
        if ($results -and $results.Count -gt 0) {
            $queryResults[$queryName] = $results
            Write-Log "Loaded $($results.Count) results for query $queryName"
        }
    }
    
    if ($queryResults.Count -eq 0) {
        Write-Log "No results found in any CSV files" -Level WARNING
        
        $noFindingsHtml = @"
<!DOCTYPE html>
<html>
<head>
    <title>$ReportTitle</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #0078d4; color: white; padding: 20px; border-radius: 5px; }
        .content { margin-top: 20px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>$ReportTitle</h1>
    </div>
    <div class="content">
        <h2>No Security Findings</h2>
        <p>No security findings were detected in the latest scan.</p>
        <p>Report generated on $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
    </div>
</body>
</html>
"@
        Set-Content -Path $OutputPath -Value $noFindingsHtml -Force
        Write-Log "Generated 'No Findings' HTML report at $OutputPath"
        exit 0
    }
    
    $htmlSuccess = New-HTMLReport -QueryResults $queryResults -OutputPath $OutputPath -ReportTitle $ReportTitle
    if (-not $htmlSuccess) {
        Write-Log "Failed to generate HTML report" -Level ERROR
    }
    
    if ($SecurityAlertPath) {
        $sarifSuccess = New-SecurityAlertReport -QueryResults $queryResults
        if (-not $sarifSuccess) {
            Write-Log "Failed to generate SARIF report" -Level ERROR
        }
    }
    
    if ($CsvPath) {
        $csvSuccess = Export-FindingsToCsv -QueryResults $queryResults -CsvPath $CsvPath
        if (-not $csvSuccess) {
            Write-Log "Failed to export findings to CSV" -Level WARNING
        }
    }
    
    Write-Log "Report generation completed" -Level INFO
    
    exit 0
}
catch {
    Write-Log "Error in report generation: $_" -Level ERROR
    exit 1
}