# MDE Query Execution Script
# Executes KQL queries against Microsoft Defender for Endpoint API

param(
    [Parameter(Mandatory=$false)]
    [string]$Query,
    
    [Parameter(Mandatory=$false)]
    [string]$QueryFile,
    
    [Parameter(Mandatory=$false)]
    [string]$QueryDirectory,
    
    [Parameter(Mandatory=$true)]
    [string]$OutputFile,
    
    [Parameter(Mandatory=$false)]
    [int]$MaxRetries = 3,
    
    [Parameter(Mandatory=$false)]
    [int]$RetryDelaySeconds = 10,
    
    [Parameter(Mandatory=$false)]
    [switch]$ValidateQuery,
    
    [Parameter(Mandatory=$false)]
    [string]$LookbackHours,

    [Parameter(Mandatory=$false)]
    [switch]$UseCredentials,

    [Parameter(Mandatory=$false)]
    [string]$TenantId,
    
    [Parameter(Mandatory=$false)]
    [string]$ClientId,
    
    [Parameter(Mandatory=$false)]
    [string]$ClientSecret,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipSanitization,
    
    [Parameter(Mandatory=$false)]
    [switch]$ReturnResults
)

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12, [Net.SecurityProtocolType]::Tls13

# Logs messages with timestamp and severity level
function Write-Log {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [ValidateSet("INFO","WARNING","ERROR","DEBUG")]
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    switch ($Level) {
        "ERROR"   { Write-Host "[$timestamp] [${Level}] $Message" -ForegroundColor Red }
        "WARNING" { Write-Host "[$timestamp] [${Level}] $Message" -ForegroundColor Yellow }
        "DEBUG"   { Write-Host "[$timestamp] [${Level}] $Message" -ForegroundColor Cyan }
        default   { Write-Host "[$timestamp] [${Level}] $Message" }
    }
}

# Creates output variables for GitHub Actions workflows
function Add-GithubOutput {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name,
        
        [Parameter(Mandatory=$true)]
        [string]$Value
    )
    
    try {
        if (Test-Path env:GITHUB_OUTPUT) {
            Add-Content -Path $env:GITHUB_OUTPUT -Value "$Name=$Value"
            Write-Log "Added GitHub output: $Name=$Value" -Level DEBUG
        } else {
            Write-Log "GitHub Actions environment not detected, skipping output" -Level DEBUG
        }
    } catch {
        Write-Log "Failed to add GitHub output: $_" -Level WARNING
    }
}

# Validates KQL query syntax
function Validate-QuerySyntax {
    param (
        [Parameter(Mandatory=$true)]
        [string]$QueryText
    )
    
    try {
        $scriptDir = Split-Path -Path $PSCommandPath -Parent
        $validateScriptPath = Join-Path -Path $scriptDir -ChildPath "validate-queries.ps1"
        
        if (-not (Test-Path $validateScriptPath)) {
            Write-Log "Validation script not found at $validateScriptPath" -Level WARNING
            return $true
        }
        
        $tempQueryFile = [System.IO.Path]::GetTempFileName() + ".kql"
        Set-Content -Path $tempQueryFile -Value $QueryText -Force
        
        Write-Log "Validating query syntax" -Level INFO
        
        . $validateScriptPath
        
        $validationResult = Test-KqlQuerySyntax -QueryPath $tempQueryFile
        
        Remove-Item $tempQueryFile -Force -ErrorAction SilentlyContinue
        
        if ($validationResult) {
            Write-Log "Query validation passed" -Level INFO
            return $true
        } else {
            Write-Log "Query validation failed" -Level WARNING
            return $false
        }
    }
    catch {
        Write-Log "Error during query validation: $_" -Level ERROR
        return $false
    }
}

# Retrieves authentication token for MDE API
function Get-AuthToken {
    param (
        [Parameter(Mandatory=$true)]
        [string]$TenantId,
        
        [Parameter(Mandatory=$true)]
        [string]$ClientId,
        
        [Parameter(Mandatory=$false)]
        [string]$ClientSecret
    )
    
    try {
        Write-Log "Authenticating with Microsoft Graph API" -Level INFO
        
        if($ClientSecret) {
            # Service principal auth
            $authBody = @{
                grant_type    = "client_credentials"
                client_id     = $ClientId
                client_secret = $ClientSecret
                scope         = "https://api.securitycenter.microsoft.com/.default"
            }
            
            $authResponse = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Body $authBody -ContentType "application/x-www-form-urlencoded"
            return $authResponse.access_token
        }
        else {
            # Interactive auth
            Write-Log "No client secret provided, using Microsoft Graph SDK" -Level INFO
            
            if(-not (Get-Module -ListAvailable Microsoft.Graph.Security)) {
                Write-Log "Microsoft Graph Security module not found, installing..." -Level INFO
                Install-Module Microsoft.Graph.Security -Scope CurrentUser -Force -AllowClobber
            }
            
            if(-not (Get-Module Microsoft.Graph.Security)) {
                Import-Module Microsoft.Graph.Security -ErrorAction Stop
            }
            
            Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -Scopes "https://api.securitycenter.microsoft.com/.default" -ErrorAction Stop
            
            $context = Get-MgContext
            if(-not $context) {
                throw "Failed to authenticate. No context available."
            }
            
            Write-Log "Successfully authenticated with Microsoft Graph" -Level INFO
            return $context.AccessToken
        }
    }
    catch {
        Write-Log "Authentication error: $($_.Exception.Message)" -Level ERROR
        throw
    }
}

# Executes query against MDE API and saves results
function Execute-Query {
    param (
        [Parameter(Mandatory=$true)]
        [string]$QueryText,
        
        [Parameter(Mandatory=$true)]
        [string]$OutputFilePath
    )
    
    try {
        Write-Log "Executing MDE query" -Level INFO
        
        # Add time filter if specified
        if ($LookbackHours) {
            if ($QueryText -notmatch "Timestamp\s*[><]=?\s*ago\(" -and $QueryText -notmatch "datetime_add\s*\(" -and $QueryText -notmatch "datetime\s*\([^)]*\)") {
                Write-Log "Adding time filter with lookback of $LookbackHours hours" -Level INFO
                
                $hasWhere = $QueryText -match "where"
                
                $tableMatch = [regex]::Match($QueryText, "(DeviceNetworkEvents|DeviceProcessEvents|DeviceRegistryEvents|DeviceLogonEvents|DeviceFileEvents|DeviceEvents)")
                if ($tableMatch.Success) {
                    $tableName = $tableMatch.Value
                    
                    if ($hasWhere) {
                        $QueryText = $QueryText -replace "where", "where $tableName.Timestamp > ago($($LookbackHours)h) and "
                    } else {
                        $positionAfterTableName = $tableMatch.Index + $tableName.Length
                        $QueryText = $QueryText.Insert($positionAfterTableName, "| where $tableName.Timestamp > ago($($LookbackHours)h) ")
                    }
                    
                    Write-Log "Time filter added to query" -Level INFO
                }
            }
        }
        
        Write-Log "Preparing to fetch data from MDE" -Level INFO
        
        $results = @()
        $retryCount = 0
        $success = $false
        $exponentialBackoff = $RetryDelaySeconds
        
        # Retry loop with exponential backoff
        while (-not $success -and $retryCount -lt $MaxRetries) {
            try {
                Write-Log "Query attempt $($retryCount + 1) of $MaxRetries" -Level INFO
                
                if ($UseCredentials) {
                    # Use MDE API with authentication
                    if(-not $TenantId -or -not $ClientId) {
                        Write-Log "Missing tenant ID or client ID for authentication" -Level ERROR
                        throw "Authentication credentials missing"
                    }
                    
                    try {
                        $token = Get-AuthToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
                        
                        Write-Log "Sending request to MDE API" -Level INFO
                        
                        $headers = @{
                            'Authorization' = "Bearer $token"
                            'Content-Type'  = "application/json"
                        }
                        
                        $body = @{
                            'Query' = $QueryText
                        } | ConvertTo-Json
                        
                        $apiParams = @{
                            Method      = "Post"
                            Uri         = "https://api.securitycenter.microsoft.com/api/advancedhunting/run"
                            Headers     = $headers
                            Body        = $body
                            TimeoutSec  = 300
                            ErrorAction = "Stop"
                        }
                        
                        $apiResponse = $null
                        try {
                            $apiResponse = Invoke-RestMethod @apiParams
                        }
                        catch [System.Net.WebException] {
                            $statusCode = [int]$_.Exception.Response.StatusCode
                            $statusDescription = $_.Exception.Response.StatusDescription
                            
                            # Handle specific HTTP error codes
                            if ($statusCode -eq 401) {
                                Write-Log "Authentication error (401): Token may have expired" -Level ERROR
                                if ($retryCount -lt $MaxRetries - 1) {
                                    Write-Log "Attempting to refresh authentication token" -Level INFO
                                    $token = Get-AuthToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
                                    $headers['Authorization'] = "Bearer $token"
                                    throw [System.Net.WebException]::new("Token expired, retrying with new token")
                                }
                                else {
                                    throw [System.Net.WebException]::new("Authentication failed after multiple attempts")
                                }
                            }
                            elseif ($statusCode -eq 429) {
                                Write-Log "Rate limit exceeded (429): Backing off for $exponentialBackoff seconds" -Level WARNING
                                Start-Sleep -Seconds $exponentialBackoff
                                $exponentialBackoff *= 2
                                throw [System.Net.WebException]::new("Rate limit exceeded, retrying with exponential backoff")
                            }
                            elseif ($statusCode -eq 503 -or $statusCode -eq 504) {
                                Write-Log "Service unavailable ($statusCode): Retrying in $exponentialBackoff seconds" -Level WARNING
                                Start-Sleep -Seconds $exponentialBackoff
                                $exponentialBackoff *= 2
                                throw [System.Net.WebException]::new("Service temporarily unavailable")
                            }
                            else {
                                Write-Log "API error ($statusCode): $statusDescription" -Level ERROR
                                throw
                            }
                        }
                        
                        if($apiResponse.Results) {
                            $results = $apiResponse.Results
                            Write-Log "Received $($results.Count) results from API" -Level INFO
                            $success = $true
                        } else {
                            Write-Log "API returned empty results" -Level INFO
                            $results = @()
                            $success = $true
                        }
                    }
                    catch {
                        $retryCount++
                        
                        if ($retryCount -lt $MaxRetries) {
                            Write-Log "Error occurred: $($_.Exception.Message). Retrying in $exponentialBackoff seconds..." -Level WARNING
                            Start-Sleep -Seconds $exponentialBackoff
                            $exponentialBackoff = [Math]::Min(60, $exponentialBackoff * 2)
                        } else {
                            Write-Log "Maximum retries reached, giving up" -Level ERROR
                            throw
                        }
                    }
                }
                else {
                    # Generate simulated test data when not using API
                    Write-Log "Using simulated data (no API credentials provided)" -Level WARNING
                    
                    $simulatedResults = @()
                    
                    if ($QueryText -match "DeviceProcessEvents") {
                        $simulatedResults += [PSCustomObject]@{
                            Timestamp = (Get-Date).AddHours(-1).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                            DeviceId = "00000000-0000-0000-0000-000000000001"
                            DeviceName = "DESKTOP-SIMULATE"
                            ActionType = "ProcessCreated"
                            FileName = "powershell.exe"
                            FolderPath = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0"
                            ProcessId = 1234
                            ProcessCommandLine = "powershell.exe -NonInteractive -ExecutionPolicy Bypass"
                            InitiatingProcessFileName = "cmd.exe"
                            InitiatingProcessId = 1000
                            InitiatingProcessCommandLine = "cmd.exe /c start powershell.exe"
                        }
                    }
                    elseif ($QueryText -match "DeviceNetworkEvents") {
                        $simulatedResults += [PSCustomObject]@{
                            Timestamp = (Get-Date).AddHours(-2).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                            DeviceId = "00000000-0000-0000-0000-000000000001"
                            DeviceName = "DESKTOP-SIMULATE"
                            ActionType = "ConnectionSuccess"
                            LocalIP = "192.168.1.100"
                            LocalPort = 54321
                            RemoteIP = "203.0.113.1"
                            RemotePort = 443
                            Protocol = "TCP"
                            InitiatingProcessFileName = "chrome.exe"
                            InitiatingProcessId = 2000
                        }
                    }
                    elseif ($QueryText -match "DeviceRegistryEvents") {
                        $simulatedResults += [PSCustomObject]@{
                            Timestamp = (Get-Date).AddMinutes(-30).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                            DeviceId = "00000000-0000-0000-0000-000000000001"
                            DeviceName = "DESKTOP-SIMULATE"
                            ActionType = "RegistryValueSet"
                            RegistryKey = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
                            RegistryValueName = "SimulatedStartup"
                            RegistryValueData = "C:\\simulated\\path\\startup.exe"
                            InitiatingProcessFileName = "regedit.exe"
                            InitiatingProcessId = 3000
                        }
                    }
                    elseif ($QueryText -match "DeviceFileEvents") {
                        $simulatedResults += [PSCustomObject]@{
                            Timestamp = (Get-Date).AddHours(-1).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                            DeviceId = "00000000-0000-0000-0000-000000000001"
                            DeviceName = "DESKTOP-SIMULATE"
                            ActionType = "FileCreated"
                            FileName = "suspicious-sample.exe"
                            FolderPath = "C:\\Users\\Administrator\\Downloads"
                            SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
                            SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                            FileSize = 245760
                            InitiatingProcessFileName = "browser_download.exe" 
                            InitiatingProcessId = 4000
                        }
                    }
                    else {
                        $simulatedResults += [PSCustomObject]@{
                            Timestamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                            DeviceId = "00000000-0000-0000-0000-000000000001"
                            DeviceName = "DESKTOP-SIMULATE"
                            ActionType = "SimulatedEvent"
                            FileName = "simulated-file.exe"
                            DetectionSource = "Simulated"
                        }
                    }
                    
                    if ($simulatedResults.Count -gt 0) {
                        $secondResult = $simulatedResults[0].PSObject.Copy()
                        if ($secondResult.PSObject.Properties.Name -contains "Timestamp") {
                            $secondResult.Timestamp = (Get-Date).AddHours(-3).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                        }
                        if ($secondResult.PSObject.Properties.Name -contains "DeviceId") {
                            $secondResult.DeviceId = "00000000-0000-0000-0000-000000000002"
                        }
                        if ($secondResult.PSObject.Properties.Name -contains "ProcessId") {
                            $secondResult.ProcessId = 5678
                        }
                        if ($secondResult.PSObject.Properties.Name -contains "FileName") {
                            $secondResult.FileName = "different-" + $secondResult.FileName
                        }
                        $simulatedResults += $secondResult
                    }
                    
                    $results = $simulatedResults
                    $success = $true
                    Write-Log "Simulated query executed successfully with $($results.Count) results" -Level INFO
                }
            }
            catch {
                $retryCount++
                Write-Log "Query attempt failed: $_" -Level WARNING
                
                if ($retryCount -lt $MaxRetries) {
                    Write-Log "Retrying in $exponentialBackoff seconds..." -Level INFO
                    Start-Sleep -Seconds $exponentialBackoff
                    $exponentialBackoff = [Math]::Min(60, $exponentialBackoff * 2)
                }
                else {
                    Write-Log "Maximum retries reached, giving up" -Level ERROR
                    throw
                }
            }
        }
        
        $outputDirectory = Split-Path -Path $OutputFilePath -Parent
        if (-not (Test-Path -Path $outputDirectory)) {
            New-Item -Path $outputDirectory -ItemType Directory -Force | Out-Null
            Write-Log "Created directory: $outputDirectory" -Level INFO
        }
        
        if ($results.Count -gt 0) {
            Write-Log "Processing $($results.Count) results" -Level INFO
            
            if (-not $SkipSanitization) {
                $sanitisedResults = $results | ForEach-Object {
                    $obj = [PSCustomObject]@{}
                    foreach($prop in $_.PSObject.Properties) {
                        $value = switch($prop.Name) {
                            "DeviceName" { if($UseCredentials -and $prop.Value) { $prop.Value } else { "DEVICE-NAME" } }
                            "RegistryKey" { if($UseCredentials -and $prop.Value) { $prop.Value } else { "REGISTRY-KEY" } }
                            "AccountName" { if($UseCredentials -and $prop.Value) { $prop.Value } else { "USERNAME" } }
                            "FilePath" { if($UseCredentials -and $prop.Value) { $prop.Value } else { "FILE-PATH" } }
                            "FolderPath" { if($UseCredentials -and $prop.Value) { $prop.Value } else { "FOLDER-PATH" } }
                            "IP" { if($UseCredentials -and $prop.Value) { $prop.Value } else { "0.0.0.0" } }
                            "LocalIP" { if($UseCredentials -and $prop.Value) { $prop.Value } else { "0.0.0.0" } }
                            "RemoteIP" { if($UseCredentials -and $prop.Value) { $prop.Value } else { "0.0.0.0" } }
                            "CommandLine" { if($UseCredentials -and $prop.Value) { $prop.Value } else { "COMMAND-LINE" } }
                            "ProcessCommandLine" { if($UseCredentials -and $prop.Value) { $prop.Value } else { "PROCESS-COMMAND-LINE" } }
                            "InitiatingProcessCommandLine" { if($UseCredentials -and $prop.Value) { $prop.Value } else { "INITIATING-PROCESS-COMMAND-LINE" } }
                            "DeviceId" { if($UseCredentials -and $prop.Value) { $prop.Value } else { "DEVICE-ID" } }
                            "Timestamp" { if($prop.Value) { (Get-Date $prop.Value).ToString("yyyy-MM-ddTHH:mm:ss.fffZ") } else { (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffZ") } }
                            default { $prop.Value }
                        }
                        $obj | Add-Member -MemberType NoteProperty -Name $prop.Name -Value $value
                    }
                    $obj
                }
                $exportResults = $sanitisedResults
            } else {
                $exportResults = $results
            }
        
            Write-Log "Exporting results to CSV" -Level INFO
            
            try {
                $exportResults | Export-Csv -Path $OutputFilePath -NoTypeInformation -Force -ErrorAction Stop
                Write-Log "CSV export successful: $OutputFilePath" -Level INFO
            }
            catch {
                Write-Log "Error during CSV export: $_" -Level ERROR
                
                Write-Log "Attempting manual CSV creation" -Level WARNING
                
                $headers = ($exportResults[0].PSObject.Properties | ForEach-Object { $_.Name }) -join ","
                $csvData = $headers + [Environment]::NewLine
                
                foreach ($row in $exportResults) {
                    $rowValues = ($row.PSObject.Properties | ForEach-Object { 
                        if ($null -eq $_.Value) { '""' } 
                        else { '"' + $_.Value.ToString().Replace('"', '""') + '"' }
                    }) -join ","
                    $csvData += $rowValues + [Environment]::NewLine
                }
                
                $csvData | Out-File -FilePath $OutputFilePath -Encoding utf8 -Force
                Write-Log "Manual CSV export successful" -Level INFO
            }
            
            if ($ReturnResults) {
                return $results
            }
            else {
                return $results.Count
            }
        }
        else {
            Write-Log "No results found" -Level INFO
            "" | Out-File -FilePath $OutputFilePath -Force
            
            if ($ReturnResults) {
                return @()
            }
            else {
                return 0
            }
        }
    }
    catch {
        Write-Log "Error executing query: $_" -Level ERROR
        throw
    }
}

# Executes queries in a directory
function Execute-QueryDirectory {
    param (
        [Parameter(Mandatory=$true)]
        [string]$DirectoryPath,
        
        [Parameter(Mandatory=$true)]
        [string]$OutputDirectory
    )
    
    try {
        if (-not (Test-Path -Path $DirectoryPath)) {
            Write-Log "Directory not found: $DirectoryPath" -Level ERROR
            return $false
        }
        
        if (-not (Test-Path -Path $OutputDirectory)) {
            New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
            Write-Log "Created output directory: $OutputDirectory" -Level INFO
        }
        
        Write-Log "Scanning directory for KQL queries: $DirectoryPath" -Level INFO
        $queryFiles = Get-ChildItem -Path $DirectoryPath -Filter "*.kql"
        
        if ($queryFiles.Count -eq 0) {
            Write-Log "No KQL files found in directory" -Level WARNING
            return @{}
        }
        
        Write-Log "Found $($queryFiles.Count) KQL files" -Level INFO
        $results = @{}
        $totalFindings = 0
        $successfulQueries = 0
        $failedQueries = 0
        
        foreach ($file in $queryFiles) {
            $queryName = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
            $outputFile = Join-Path -Path $OutputDirectory -ChildPath "$queryName.csv"
            
            Write-Log "Processing query: $($file.Name)" -Level INFO
            $queryContent = Get-Content -Path $file.FullName -Raw
            
            if ($ValidateQuery) {
                $validationResult = Validate-QuerySyntax -QueryText $queryContent
                if (-not $validationResult) {
                    Write-Log "Validation failed for $($file.Name), skipping" -Level WARNING
                    $failedQueries++
                    continue
                }
            }
            
            try {
                $count = Execute-Query -QueryText $queryContent -OutputFilePath $outputFile
                Write-Log "Query $($file.Name) returned $count results" -Level INFO
                $successfulQueries++
            } catch {
                Write-Log "Error executing query $($file.Name): $_" -Level WARNING
                "" | Out-File -FilePath $outputFile -Force
                $count = 0
                $failedQueries++
            }
            
            $results[$queryName] = @{
                FileName = $file.Name
                ResultCount = $count
                OutputFile = $outputFile
                Success = $true
            }
            
            $totalFindings += $count
        }
        
        Write-Log "Processed all queries: $successfulQueries succeeded, $failedQueries failed, $totalFindings total findings" -Level INFO
        
        Add-GithubOutput -Name "total_findings" -Value $totalFindings
        Add-GithubOutput -Name "successful_queries" -Value $successfulQueries
        Add-GithubOutput -Name "failed_queries" -Value $failedQueries
        Add-GithubOutput -Name "has_findings" -Value $(if ($totalFindings -gt 0) { "true" } else { "false" })
        
        return $results
    }
    catch {
        Write-Log "Error processing query directory: $_" -Level ERROR
        return @{}
    }
}

try {
    if ($QueryDirectory) {
        Write-Log "Processing directory of queries: $QueryDirectory" -Level INFO
        $directoryResults = Execute-QueryDirectory -DirectoryPath $QueryDirectory -OutputDirectory $OutputFile
        
        if ($directoryResults.Count -eq 0) {
            Write-Log "Failed to process query directory or no queries found" -Level ERROR
            exit 1
        }
        
        Write-Log "Query directory processing completed successfully" -Level INFO
    }
    elseif ($QueryFile) {
        Write-Log "Processing single query file: $QueryFile" -Level INFO
        if (-not (Test-Path -Path $QueryFile)) {
            Write-Log "Query file not found: $QueryFile" -Level ERROR
            exit 1
        }
        
        $queryContent = Get-Content -Path $QueryFile -Raw
        
        if ($ValidateQuery) {
            $validationResult = Validate-QuerySyntax -QueryText $queryContent
            if (-not $validationResult) {
                Write-Log "Query validation failed for $QueryFile" -Level ERROR
                exit 1
            }
        }
        
        try {
            if ($ReturnResults) {
                $results = Execute-Query -QueryText $queryContent -OutputFilePath $OutputFile -ReturnResults
                Write-Log "Query returned $($results.Count) results" -Level INFO
            } else {
                $count = Execute-Query -QueryText $queryContent -OutputFilePath $OutputFile
                Write-Log "Query returned $count results" -Level INFO
            }
        } catch {
            Write-Log "Error executing query: $_" -Level WARNING
            "" | Out-File -FilePath $OutputFile -Force
            if ($ReturnResults) {
                $results = @()
            } else {
                $count = 0
            }
        }
        
        Add-GithubOutput -Name "result_count" -Value $(if ($ReturnResults) { $results.Count } else { $count })
        Add-GithubOutput -Name "has_findings" -Value $(if ($ReturnResults -and $results.Count -gt 0 -or -not $ReturnResults -and $count -gt 0) { "true" } else { "false" })
    }
    elseif ($Query) {
        Write-Log "Processing inline query" -Level INFO
        
        if ($ValidateQuery) {
            $validationResult = Validate-QuerySyntax -QueryText $Query
            if (-not $validationResult) {
                Write-Log "Query validation failed" -Level ERROR
                exit 1
            }
        }
        
        try {
            if ($ReturnResults) {
                $results = Execute-Query -QueryText $Query -OutputFilePath $OutputFile -ReturnResults
                Write-Log "Query returned $($results.Count) results" -Level INFO
            } else {
                $count = Execute-Query -QueryText $Query -OutputFilePath $OutputFile
                Write-Log "Query returned $count results" -Level INFO
            }
        } catch {
            Write-Log "Error executing query: $_" -Level WARNING
            "" | Out-File -FilePath $OutputFile -Force
            if ($ReturnResults) {
                $results = @()
            } else {
                $count = 0
            }
        }
        
        Add-GithubOutput -Name "result_count" -Value $(if ($ReturnResults) { $results.Count } else { $count })
        Add-GithubOutput -Name "has_findings" -Value $(if ($ReturnResults -and $results.Count -gt 0 -or -not $ReturnResults -and $count -gt 0) { "true" } else { "false" })
    }
    else {
        Write-Log "No query source provided. Use -Query, -QueryFile or -QueryDirectory." -Level ERROR
        exit 1
    }
    
    Write-Log "Script execution completed successfully" -Level INFO
    
    if ($ReturnResults -and $results) {
        return $results
    } else {
        exit 0
    }
}
catch {
    Write-Log "Fatal error during script execution: $_" -Level ERROR
    exit 1
}