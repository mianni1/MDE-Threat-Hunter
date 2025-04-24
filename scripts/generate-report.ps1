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
    
    $baseName = ($QueryName -split '/')[-1] -replace '\.kql$|-' -replace '\.csv$', ''
    $queryPath = Join-Path (Split-Path -Parent $PSScriptRoot) "queries\$baseName.kql"
    
    if (Test-Path $queryPath) {
        Write-Log "Extracting description from KQL file: $queryPath" -Level "INFO"
        
        $content = Get-Content -Path $queryPath -Raw
        $descriptionData = @{ }
        
        $sections = @{
            "Description" = [regex]::Match($content, "(?m)//\s*DESCRIPTION:\s*(.*?)(?=//\s*TECHNICAL:|$)", [System.Text.RegularExpressions.RegexOptions]::Singleline)
            "Technical" = [regex]::Match($content, "(?m)//\s*TECHNICAL:\s*(.*?)(?=//\s*MITRE_ATTACK:|$)", [System.Text.RegularExpressions.RegexOptions]::Singleline)
            "MitreAttack" = [regex]::Match($content, "(?m)//\s*MITRE_ATTACK:\s*(.*?)(?=//\s*IMPACT:|$)", [System.Text.RegularExpressions.RegexOptions]::Singleline)
            "Impact" = [regex]::Match($content, "(?m)//\s*IMPACT:\s*(.*?)(?=//\s*REMEDIATION:|$)", [System.Text.RegularExpressions.RegexOptions]::Singleline)
            "Remediation" = [regex]::Match($content, "(?m)//\s*REMEDIATION:\s*(.*?)(?=//\s*END_DESCRIPTION|$)", [System.Text.RegularExpressions.RegexOptions]::Singleline)
        }
        
        foreach ($key in $sections.Keys) {
            if ($sections[$key].Success) {
                $value = $sections[$key].Groups[1].Value
                $value = $value -replace "(?m)^\s*//\s*", "" -replace "(?m)\r?\n\s*", " "
                $value = $value.Trim()
                $descriptionData[$key] = $value
            }
        }
        
        if ($descriptionData.ContainsKey("Description")) {
            Write-Log "Found description metadata in KQL file for $baseName" -Level "INFO"
            
            if ($Results -and $Results.Count -gt 0) {
                $specificIndicators = @()
                
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
                    $descriptionData["SpecificIndicators"] = "Specific indicators from this detection include:`n" + ($specificIndicators -join "`n")
                }
            }
            
            return $descriptionData
        }
    }
    
    $formattedName = $baseName -replace '_', ' '
    return @{
        Description = "Detection of potentially suspicious activity related to $formattedName."
        Technical = "This detection identifies abnormal or potentially malicious behaviors that match patterns associated with $formattedName techniques."
        Impact = "The security impact depends on the specific activity detected. Further investigation is recommended."
        Remediation = "Review the specific events detected and investigate the involved systems and accounts."
    }
}

function Get-EnhancedThreatContext {
    param (
        [Parameter(Mandatory=$true)]
        [array]$Results,
        
        [Parameter(Mandatory=$false)]
        [string]$QueryName
    )
    
    $context = @{
        AffectedDevices = @{ }
        AffectedUsers = @{ }
        Timeline = @()
        ThreatIndicators = @()
        RiskScore = 50
        MostRecentDetection = $null
        FirstDetection = $null
    }
    
    if (-not $Results -or $Results.Count -eq 0) {
        return $context
    }
    
    foreach ($result in $Results) {
        if ($result.PSObject.Properties.Name -contains "DeviceName" -and $result.DeviceName) {
            $deviceName = $result.DeviceName
            
            if (-not $context.AffectedDevices.ContainsKey($deviceName)) {
                $context.AffectedDevices[$deviceName] = @{
                    Count = 0
                    Activities = @{ }
                    FirstSeen = $null
                    LastSeen = $null
                    ProcessesInvolved = @{ }
                }
            }
            
            $context.AffectedDevices[$deviceName].Count++
            
            $processes = @()
            if ($result.PSObject.Properties.Name -contains "FileName" -and $result.FileName) {
                $processes += $result.FileName
            }
            if ($result.PSObject.Properties.Name -contains "InitiatingProcessFileName" -and $result.InitiatingProcessFileName) {
                $processes += $result.InitiatingProcessFileName
            }
            
            foreach ($process in $processes) {
                if (-not $context.AffectedDevices[$deviceName].ProcessesInvolved.ContainsKey($process)) {
                    $context.AffectedDevices[$deviceName].ProcessesInvolved[$process] = 0
                }
                $context.AffectedDevices[$deviceName].ProcessesInvolved[$process]++
            }
            
            if ($result.PSObject.Properties.Name -contains "Timestamp" -and $result.Timestamp) {
                $timestamp = $null
                try {
                    $timestamp = [DateTime]$result.Timestamp
                    
                    $timelineItem = [PSCustomObject]@{
                        Time = $timestamp
                        Device = $deviceName
                        Event = $result.ActionType ?? "Detection"
                        Details = if ($result.ProcessCommandLine) { 
                            $result.ProcessCommandLine 
                        } elseif ($result.FileName) {
                            $result.FileName
                        } else {
                            $QueryName -replace "_", " " -replace ".kql", ""
                        }
                    }
                    $context.Timeline += $timelineItem
                    
                    if (-not $context.AffectedDevices[$deviceName].FirstSeen -or 
                        $timestamp -lt $context.AffectedDevices[$deviceName].FirstSeen) {
                        $context.AffectedDevices[$deviceName].FirstSeen = $timestamp
                    }
                    
                    if (-not $context.AffectedDevices[$deviceName].LastSeen -or 
                        $timestamp -gt $context.AffectedDevices[$deviceName].LastSeen) {
                        $context.AffectedDevices[$deviceName].LastSeen = $timestamp
                    }
                    
                    if (-not $context.FirstDetection -or $timestamp -lt $context.FirstDetection) {
                        $context.FirstDetection = $timestamp
                    }
                    
                    if (-not $context.MostRecentDetection -or $timestamp -gt $context.MostRecentDetection) {
                        $context.MostRecentDetection = $timestamp
                    }
                }
                catch {
                }
            }
            
            if ($result.PSObject.Properties.Name -contains "ActionType" -and $result.ActionType) {
                $activity = $result.ActionType
                if (-not $context.AffectedDevices[$deviceName].Activities.ContainsKey($activity)) {
                    $context.AffectedDevices[$deviceName].Activities[$activity] = 0
                }
                $context.AffectedDevices[$deviceName].Activities[$activity]++
            }
        }
        
        if ($result.PSObject.Properties.Name -contains "AccountName" -and $result.AccountName) {
            $accountName = $result.AccountName
            $domain = if ($result.PSObject.Properties.Name -contains "AccountDomain" -and $result.AccountDomain) {
                $result.AccountDomain
            } else { "Unknown" }
            
            $userKey = "$domain\\$accountName"
            
            if (-not $context.AffectedUsers.ContainsKey($userKey)) {
                $context.AffectedUsers[$userKey] = @{
                    Count = 0
                    Devices = @{ }
                    Activities = @{ }
                    IsAdmin = $false
                }
            }
            
            $context.AffectedUsers[$userKey].Count++
            
            if ($result.PSObject.Properties.Name -contains "IsAdmin" -or $result.PSObject.Properties.Name -contains "IsLocalAdmin") {
                $isAdmin = $result.IsAdmin -or $result.IsLocalAdmin
                if ($isAdmin) {
                    $context.AffectedUsers[$userKey].IsAdmin = $true
                }
            }
            
            if ($result.PSObject.Properties.Name -contains "DeviceName" -and $result.DeviceName) {
                if (-not $context.AffectedUsers[$userKey].Devices.ContainsKey($result.DeviceName)) {
                    $context.AffectedUsers[$userKey].Devices[$result.DeviceName] = 0
                }
                $context.AffectedUsers[$userKey].Devices[$result.DeviceName]++
            }
            
            if ($result.PSObject.Properties.Name -contains "ActionType" -and $result.ActionType) {
                $activity = $result.ActionType
                if (-not $context.AffectedUsers[$userKey].Activities.ContainsKey($activity)) {
                    $context.AffectedUsers[$userKey].Activities[$activity] = 0
                }
                $context.AffectedUsers[$userKey].Activities[$activity]++
            }
        }
        
        $threatIndicators = @()
        
        if ($result.PSObject.Properties.Name -contains "ProcessCommandLine" -and $result.ProcessCommandLine) {
            $threatIndicators += @{
                Type = "Command Line"
                Value = $result.ProcessCommandLine
                Context = "Process execution with potentially suspicious parameters"
            }
        }
        
        if ($result.PSObject.Properties.Name -contains "RemoteIP" -and $result.RemoteIP) {
            $port = if ($result.PSObject.Properties.Name -contains "RemotePort" -and $result.RemotePort) {
                $result.RemotePort
            } else { "Unknown" }
            
            $threatIndicators += @{
                Type = "Network Connection"
                Value = "Connection to $($result.RemoteIP):$port"
                Context = "Potential C2 communication or data exfiltration attempt"
            }
        }
        
        if ($result.PSObject.Properties.Name -contains "FileName" -and $result.FileName) {
            $filePath = if ($result.PSObject.Properties.Name -contains "FolderPath" -and $result.FolderPath) {
                $result.FolderPath
            } else { "Unknown location" }
            
            $threatIndicators += @{
                Type = "File"
                Value = "$filePath\\$($result.FileName)"
                Context = "Potentially malicious file detected"
            }
        }
        
        if ($result.PSObject.Properties.Name -contains "RegistryKey" -and $result.RegistryKey) {
            $regValue = if ($result.PSObject.Properties.Name -contains "RegistryValueName" -and $result.RegistryValueName) {
                $result.RegistryValueName
            } else { "Unknown" }
            
            $threatIndicators += @{
                Type = "Registry"
                Value = "$($result.RegistryKey)\\$regValue"
                Context = "Potentially suspicious registry modification"
            }
        }
        
        foreach ($indicator in $threatIndicators) {
            $exists = $false
            foreach ($existingIndicator in $context.ThreatIndicators) {
                if ($existingIndicator.Value -eq $indicator.Value) {
                    $exists = $true
                    break
                }
            }
            
            if (-not $exists) {
                $context.ThreatIndicators += $indicator
            }
        }
    }
    
    $deviceScore = [Math]::Min(25, $context.AffectedDevices.Count * 5)
    $adminUserCount = ($context.AffectedUsers.GetEnumerator() | Where-Object { $_.Value.IsAdmin -eq $true }).Count
    $adminScore = [Math]::Min(25, $adminUserCount * 10)
    $severityScore = 0
    if ($QueryName -match "(credential_dumping|defense_evasion|ransomware|malware|privilege|lateral_movement)") {
        $severityScore = 25
    }
    elseif ($QueryName -match "(suspicious|anomalous)") {
        $severityScore = 15
    }
    elseif ($QueryName -match "(unusual)") {
        $severityScore = 10
    }
    $persistenceScore = 0
    if ($context.FirstDetection -and $context.MostRecentDetection) {
        $detectionSpan = ($context.MostRecentDetection - $context.FirstDetection).TotalHours
        $persistenceScore = [Math]::Min(25, $detectionSpan * 0.5)
    }
    $context.RiskScore = [Math]::Min(100, $deviceScore + $adminScore + $severityScore + $persistenceScore)
    $context.Timeline = $context.Timeline | Sort-Object Time
    
    return $context
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
    
    if ($IncludeProperties.Count -eq 0) {
        $IncludeProperties = $Data[0].PSObject.Properties.Name
    }
    
    $table = "| " + ($IncludeProperties -join " | ") + " |`n"
    $table += "| " + (($IncludeProperties | ForEach-Object { "-" * $_.Length }) -join " | ") + " |`n"
    
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

function New-SecurityAlertReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [hashtable]$QueryResults,
        
        [Parameter(Mandatory=$false)]
        [string]$Category = "mde-threat-hunting",
        
        [Parameter(Mandatory=$true)]
        [string]$SecurityAlertPath
    )
    
    try {
        Write-Log "Generating SARIF report for GitHub Security tab"
        
        $sarif = @{
            '$schema' = "https://json.schemastore.org/sarif-2.1.0.json"
            version = "2.1.0"
            runs = @(
                @{
                    runAutomationDetails = @{
                        id = "security-scan/$Category/$(Get-Date -Format 'yyyyMMdd')"
                        guid = [Guid]::NewGuid().ToString()
                        correlationGuid = [Guid]::NewGuid().ToString()
                    }
                    tool = @{
                        driver = @{
                            name = "MDE Threat Hunter"
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
                $enhancedContext = Get-EnhancedThreatContext -Results $results -QueryName $queryName
                
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
                $detectionDescription = Get-DetectionDescription -QueryName $queryName -Results $results
                
                $riskLevel = if ($enhancedContext.RiskScore -ge 80) {
                    "Critical"
                } elseif ($enhancedContext.RiskScore -ge 60) {
                    "High"
                } elseif ($enhancedContext.RiskScore -ge 40) {
                    "Medium"
                } else {
                    "Low"
                }
                
                $affectedResourcesText = ""
                if ($enhancedContext.AffectedDevices.Keys.Count -gt 0) {
                    $affectedResourcesText += "### Affected Devices ($($enhancedContext.AffectedDevices.Keys.Count))\n\n"
                    $deviceList = @()
                    foreach ($device in $enhancedContext.AffectedDevices.Keys | Select-Object -First 5) {
                        $deviceData = $enhancedContext.AffectedDevices[$device]
                        $deviceList += "* $device - $($deviceData.Count) events"
                    }
                    if ($enhancedContext.AffectedDevices.Keys.Count -gt 5) {
                        $deviceList += "* ... and $($enhancedContext.AffectedDevices.Keys.Count - 5) more devices"
                    }
                    $affectedResourcesText += "$($deviceList -join "\n")\n\n"
                }
                
                if ($enhancedContext.AffectedUsers.Keys.Count -gt 0) {
                    $affectedResourcesText += "### Affected Users ($($enhancedContext.AffectedUsers.Keys.Count))\n\n"
                    $userList = @()
                    
                    $adminUsers = $enhancedContext.AffectedUsers.GetEnumerator() | 
                        Where-Object { $_.Value.IsAdmin -eq $true } | 
                        Select-Object -First 3 -ExpandProperty Key
                        
                    foreach ($user in $adminUsers) {
                        $userList += "* $user - **ADMIN USER**"
                    }
                    
                    $regularUsers = $enhancedContext.AffectedUsers.GetEnumerator() | 
                        Where-Object { $_.Value.IsAdmin -ne $true } | 
                        Select-Object -First (5 - $adminUsers.Count) -ExpandProperty Key
                        
                    foreach ($user in $regularUsers) {
                        $userList += "* $user"
                    }
                    
                    if ($enhancedContext.AffectedUsers.Keys.Count -gt 5) {
                        $userList += "* ... and $($enhancedContext.AffectedUsers.Keys.Count - 5) more users"
                    }
                    $affectedResourcesText += "$($userList -join "\n")\n\n"
                }
                
                $threatIndicatorsText = ""
                if ($enhancedContext.ThreatIndicators.Count -gt 0) {
                    $threatIndicatorsText = "### Key Threat Indicators\n\n"
                    foreach ($indicator in $enhancedContext.ThreatIndicators | Select-Object -First 5) {
                        $threatIndicatorsText += "* **$($indicator.Type)**: $($indicator.Value)\n"
                    }
                    $threatIndicatorsText += "\n"
                }
                
                $detectionTimeText = ""
                if ($enhancedContext.FirstDetection -and $enhancedContext.MostRecentDetection) {
                    $detectionPeriod = ($enhancedContext.MostRecentDetection - $enhancedContext.FirstDetection)
                    $detectionTimeText = "### Detection Timeline\n\n"
                    $detectionTimeText += "* First detected: $($enhancedContext.FirstDetection.ToString('yyyy-MM-dd HH:mm:ss'))\n"
                    $detectionTimeText += "* Most recent: $($enhancedContext.MostRecentDetection.ToString('yyyy-MM-dd HH:mm:ss'))\n"
                    $detectionTimeText += "* Duration: $([Math]::Floor($detectionPeriod.TotalHours)) hours, $($detectionPeriod.Minutes) minutes\n\n"
                }
                
                $rule = @{
                    id = $ruleId
                    name = $displayName.Replace(" ", "")
                    shortDescription = @{
                        text = "$displayName (Risk: $riskLevel)"
                    }
                    fullDescription = @{
                        text = "$($detectionDescription.Description) Technical details: $($detectionDescription.Technical)"
                    }
                    help = @{
                        text = "Technical Details: $($detectionDescription.Technical)\n\nImpact: $($detectionDescription.Impact)\n\nMITRE ATT&CK: $($detectionDescription.MitreAttack)\n\nRemediation: $($detectionDescription.Remediation)"
                        markdown = "## Detection Details\n\n$($detectionDescription.Description)\n\n### Technical Indicators\n$($detectionDescription.Technical)\n\n### MITRE ATT&CK Mapping\n$($detectionDescription.MitreAttack)\n\n$detectionTimeText$affectedResourcesText$threatIndicatorsText### Impact\n$($detectionDescription.Impact)\n\n### Recommended Actions\n$($detectionDescription.Remediation)"
                    }
                    helpUri = "https://github.com/security"
                    properties = @{
                        precision = "high"
                        tags = @("security", "defender", "hunting")
                        category = $Category
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
                
                $rule.properties["risk-score"] = $enhancedContext.RiskScore.ToString()
                
                $sarif.runs[0].tool.driver.rules += $rule
                
                $result = @{
                    ruleId = $ruleId
                    level = $severity
                    message = @{
                        text = "$displayName: $($results.Count) instances detected"
                    }
                    locations = @(
                        @{
                            physicalLocation = @{
                                artifactLocation = @{
                                    uri = "security-scan-results.json"
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
                        "primaryLocationLineHash" = [System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes("$ruleId-$(Get-Date -Format 'yyyyMMdd')"))).Replace("-", "").ToLower()
                    }
                    properties = @{
                        category = $Category
                        findingCount = $results.Count
                        timestamp = (Get-Date).ToString("yyyy-MM-dd")
                        queryName = $queryName
                        description = $detectionDescription.Description
                        impact = $detectionDescription.Impact
                        remediation = $detectionDescription.Remediation
                        isPrivateResult = $true
                        riskScore = $enhancedContext.RiskScore
                        riskLevel = $riskLevel
                        affectedDevices = $enhancedContext.AffectedDevices.Keys.Count
                        affectedUsers = $enhancedContext.AffectedUsers.Keys.Count
                        affectedAdminUsers = ($enhancedContext.AffectedUsers.GetEnumerator() | Where-Object { $_.Value.IsAdmin -eq $true }).Count
                    }
                }
                
                $summarizedProperties = @{ }
                
                if ($results.Count -gt 0) {
                    $firstResult = $results[0]
                    $maxExamples = [Math]::Min(5, $results.Count)
                    
                    if ($enhancedContext.AffectedDevices.Keys.Count -gt 0) {
                        $summarizedProperties["affected_devices"] = ($enhancedContext.AffectedDevices.Keys | Select-Object -First 3) -join ", "
                        if ($enhancedContext.AffectedDevices.Keys.Count -gt 3) {
                            $summarizedProperties["affected_devices"] += " (and $($enhancedContext.AffectedDevices.Keys.Count - 3) more)"
                        }
                    }
                    
                    if ($enhancedContext.AffectedUsers.Keys.Count -gt 0) {
                        $summarizedProperties["affected_users"] = ($enhancedContext.AffectedUsers.Keys | Select-Object -First 3) -join ", "
                        if ($enhancedContext.AffectedUsers.Keys.Count -gt 3) {
                            $summarizedProperties["affected_users"] += " (and $($enhancedContext.AffectedUsers.Keys.Count - 3) more)"
                        }
                    }
                    
                    if ($enhancedContext.FirstDetection -and $enhancedContext.MostRecentDetection) {
                        $summarizedProperties["first_seen"] = $enhancedContext.FirstDetection.ToString("yyyy-MM-dd HH:mm:ss")
                        $summarizedProperties["last_seen"] = $enhancedContext.MostRecentDetection.ToString("yyyy-MM-dd HH:mm:ss")
                    }
                    
                    if ($enhancedContext.ThreatIndicators.Count -gt 0) {
                        $summarizedProperties["example_indicators"] = ($enhancedContext.ThreatIndicators | 
                            Select-Object -First 3 | 
                            ForEach-Object { "$($_.Type): $($_.Value)" }) -join "; "
                    }
                }
                
                foreach ($key in $summarizedProperties.Keys) {
                    $result.properties[$key] = $summarizedProperties[$key]
                }
                
                $sarif.runs[0].results += $result
                
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
        $summaryFindings = @()
        
        foreach ($queryName in $QueryResults.Keys) {
            $results = $QueryResults[$queryName]
            
            if ($results -and $results.Count -gt 0) {
                $enhancedContext = Get-EnhancedThreatContext -Results $results -QueryName $queryName
                $detectionDescription = Get-DetectionDescription -QueryName $queryName -Results $results
                
                foreach ($finding in $results) {
                    $findingObj = [PSCustomObject]@{
                        DetectionType = $queryName
                        DetectionCategory = if ($queryName -match "(credential_dumping|defense_evasion|ransomware|malware|privilege|lateral_movement)") { 
                            "High Severity" 
                        } elseif ($queryName -match "(suspicious|anomalous)") { 
                            "Medium Severity" 
                        } else { 
                            "Low Severity" 
                        }
                        Timestamp = $finding.Timestamp
                    }
                    
                    foreach ($prop in $finding.PSObject.Properties) {
                        if ($prop.Name -ne "Timestamp") {
                            $findingObj | Add-Member -MemberType NoteProperty -Name $prop.Name -Value $prop.Value
                        }
                    }
                    
                    $findingObj | Add-Member -MemberType NoteProperty -Name "DetectionDescription" -Value $detectionDescription.Description
                    $findingObj | Add-Member -MemberType NoteProperty -Name "MitreAttack" -Value $detectionDescription.MitreAttack
                    
                    $allFindings += $findingObj
                }
                
                $summaryObj = [PSCustomObject]@{
                    DetectionType = $queryName
                    EventCount = $results.Count
                    RiskScore = $enhancedContext.RiskScore
                    FirstSeen = $enhancedContext.FirstDetection
                    LastSeen = $enhancedContext.MostRecentDetection
                    AffectedDevices = $enhancedContext.AffectedDevices.Keys.Count
                    AffectedUsers = $enhancedContext.AffectedUsers.Keys.Count
                    AffectedAdminUsers = ($enhancedContext.AffectedUsers.GetEnumerator() | Where-Object { $_.Value.IsAdmin -eq $true }).Count
                    Description = $detectionDescription.Description
                    TechnicalDetails = $detectionDescription.Technical
                    Remediation = $detectionDescription.Remediation
                    MitreAttack = $detectionDescription.MitreAttack
                }
                
                if ($enhancedContext.AffectedDevices.Keys.Count -gt 0) {
                    $devicesList = ($enhancedContext.AffectedDevices.Keys | Select-Object -First 10) -join ", "
                    if ($enhancedContext.AffectedDevices.Keys.Count -gt 10) {
                        $devicesList += " (and $($enhancedContext.AffectedDevices.Keys.Count - 10) more)"
                    }
                    $summaryObj | Add-Member -MemberType NoteProperty -Name "DevicesList" -Value $devicesList
                }
                
                if ($enhancedContext.AffectedUsers.Keys.Count -gt 0) {
                    $usersList = ($enhancedContext.AffectedUsers.Keys | Select-Object -First 10) -join ", "
                    if ($enhancedContext.AffectedUsers.Keys.Count -gt 10) {
                        $usersList += " (and $($enhancedContext.AffectedUsers.Keys.Count - 10) more)"
                    }
                    $summaryObj | Add-Member -MemberType NoteProperty -Name "UsersList" -Value $usersList
                }
                
                if ($enhancedContext.ThreatIndicators.Count -gt 0) {
                    $indicatorsList = ($enhancedContext.ThreatIndicators | 
                        Select-Object -First 5 | 
                        ForEach-Object { "$($_.Type): $($_.Value)" }) -join "; "
                    $summaryObj | Add-Member -MemberType NoteProperty -Name "KeyIndicators" -Value $indicatorsList
                }
                
                $summaryFindings += $summaryObj
            }
        }
        
        if ($allFindings.Count -gt 0) {
            $outputDir = Split-Path -Path $CsvPath -Parent
            if (-not (Test-Path $outputDir)) {
                New-Item -Path $outputDir -ItemType Directory -Force | Out-Null
            }
            
            $allFindings | Export-Csv -Path $CsvPath -NoTypeInformation -Force
            Write-Log "Exported $($allFindings.Count) detailed findings to $CsvPath"
            
            $summaryPath = $CsvPath -replace '\.csv$', '-summary.csv'
            $summaryFindings | Export-Csv -Path $summaryPath -NoTypeInformation -Force
            Write-Log "Exported $($summaryFindings.Count) summary findings to $summaryPath"
            
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
    
    $queryResults = @{ }
    
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
        $sarifSuccess = New-SecurityAlertReport -QueryResults $queryResults -SecurityAlertPath $SecurityAlertPath
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