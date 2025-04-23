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
                
                $htmlContent += @"
    <div class="findings-section">
        <h2>$displayName</h2>
        <p>Results: <strong>$($results.Count)</strong> | Severity: <strong>$severity</strong></p>
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
                $rule = @{
                    id = $ruleId
                    name = $displayName.Replace(" ", "")
                    shortDescription = @{
                        text = $displayName
                    }
                    fullDescription = @{
                        text = "Detection of $displayName events"
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
                        "security-notes" = "Private detection alert"
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
    
    $queryResults = @{
    }
    
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