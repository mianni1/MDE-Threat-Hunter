# MDE Query Execution Script

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
    [string]$TenantId = $env:MDE_TENANT_ID,

    [Parameter(Mandatory=$false)]
    [string]$ClientId = $env:MDE_CLIENT_ID,

    [Parameter(Mandatory=$false)]
    [string]$ClientSecret = $env:MDE_CLIENT_SECRET,

    [Parameter(Mandatory=$false)]
    [string]$ApiUrl = $env:MDE_API_URL
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

function Validate-QuerySyntax {
    param (
        [Parameter(Mandatory=$true)]
        [string]$QueryText
    )
    
    try {
        $scriptDir = Split-Path -Path $PSCommandPath -Parent
        $validateScriptPath = Join-Path -Path $scriptDir -ChildPath "validate-queries.ps1"
        
        if (-not (Test-Path $validateScriptPath)) {
            Write-Log "Validation script not found at: $validateScriptPath" -Level WARNING
            return $true
        }
        
        $tempQueryFile = [System.IO.Path]::GetTempFileName() + ".kql"
        Set-Content -Path $tempQueryFile -Value $QueryText -Force
        
        Write-Log "Validating query syntax..." -Level INFO
        
        . $validateScriptPath
        
        $validationResult = Test-KqlQuerySyntax -QueryPath $tempQueryFile
        
        Remove-Item $tempQueryFile -Force -ErrorAction SilentlyContinue
        
        if ($validationResult) {
            Write-Log "Query validation passed" -Level INFO
            return $true
        } else {
            Write-Log "Query validation failed - see warnings above" -Level WARNING
            return $false
        }
    }
    catch {
        Write-Log "Error during query validation: $_" -Level ERROR
        return $false
    }
}

function Get-MdeAccessToken {
    param(
        [Parameter(Mandatory=$true)] [string]$TenantId,
        [Parameter(Mandatory=$true)] [string]$ClientId,
        [Parameter(Mandatory=$true)] [string]$ClientSecret
    )
    try {
        $body = @{ 
            client_id     = $ClientId
            scope         = 'https://api.security.microsoft.com/.default'
            client_secret = $ClientSecret
            grant_type    = 'client_credentials'
        }
        $tokenResponse = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Body $body -ContentType 'application/x-www-form-urlencoded'
        return $tokenResponse.access_token
    }
    catch {
        Write-Log "Failed to acquire access token: $_" -Level ERROR
        throw
    }
}

function Execute-Query {
    param (
        [Parameter(Mandatory=$true)]
        [string]$QueryText,
        
        [Parameter(Mandatory=$true)]
        [string]$OutputFilePath
    )
    
    try {
        Write-Log "Executing MDE query..." -Level INFO
        
        if ($LookbackHours) {
            if ($QueryText -notmatch "Timestamp\s*[><]=?\s*ago\(" -and $QueryText -notmatch "datetime_add\s*\(" -and $QueryText -notmatch "datetime\s*\([^)]*\)") {
                Write-Log "Adding time filter for last $LookbackHours hours" -Level INFO
                
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
                    
                    Write-Log "Added time filter to query" -Level INFO
                }
            }
        }
        
        Write-Log "Executing MDE query" -Level INFO

        $results = @()
        $retryCount = 0
        $success = $false

        while (-not $success -and $retryCount -lt $MaxRetries) {
            try {
                if (-not $TenantId -or -not $ClientId -or -not $ClientSecret) {
                    throw 'API credentials not provided'
                }

                $token   = Get-MdeAccessToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
                $headers = @{ Authorization = "Bearer $token" }
                $body    = @{ Query = $QueryText } | ConvertTo-Json
                $uri     = if ($ApiUrl) { $ApiUrl } else { 'https://api.security.microsoft.com/api/advancedhunting/run' }

                $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body $body -ContentType 'application/json'
                $results  = $response.Results
                $success  = $true
                Write-Log "Query executed successfully." -Level INFO
            }
            catch {
                $retryCount++
                Write-Log "Query execution attempt $retryCount failed: $_" -Level WARNING

                if ($retryCount -lt $MaxRetries) {
                    Write-Log "Retrying in $RetryDelaySeconds seconds..." -Level INFO
                    Start-Sleep -Seconds $RetryDelaySeconds
                }
                else {
                    Write-Log "Maximum retry attempts reached. Query execution failed." -Level ERROR
                    throw
                }
            }
        }
        
        $outputDirectory = Split-Path -Path $OutputFilePath -Parent
        if (-not (Test-Path -Path $outputDirectory)) {
            New-Item -Path $outputDirectory -ItemType Directory -Force | Out-Null
        }
        
        if ($results.Count -gt 0) {
            Write-Log "Exporting $($results.Count) results to $OutputFilePath"
            
            try {
                $results | Export-Csv -Path $OutputFilePath -NoTypeInformation -Force -ErrorAction Stop
                Write-Log "Results exported successfully to $OutputFilePath"
            }
            catch {
                Write-Log "Error exporting to CSV: $_" -Level ERROR
                
                Write-Log "Attempting alternative export method..." -Level WARNING
                
                $headers = ($results[0].PSObject.Properties | ForEach-Object { $_.Name }) -join ","
                $csvData = $headers + [Environment]::NewLine
                
                foreach ($row in $results) {
                    $rowValues = ($row.PSObject.Properties | ForEach-Object { 
                        if ($null -eq $_.Value) { '""' } 
                        else { '"' + $_.Value.ToString().Replace('"', '""') + '"' }
                    }) -join ","
                    $csvData += $rowValues + [Environment]::NewLine
                }
                
                $csvData | Out-File -FilePath $OutputFilePath -Encoding utf8 -Force
                Write-Log "Results exported using alternative method to $OutputFilePath"
            }
            
            return $results.Count
        }
        else {
            Write-Log "No results found, creating empty output file"
            "" | Out-File -FilePath $OutputFilePath -Force
            return 0
        }
    }
    catch {
        Write-Log "Error executing query: $_" -Level ERROR
        throw
    }
}

function Execute-QueryDirectory {
    param (
        [Parameter(Mandatory=$true)]
        [string]$DirectoryPath,

        [Parameter(Mandatory=$true)]
        [string]$OutputDirectory,

        [Parameter(Mandatory=$false)]
        [string]$TenantId,

        [Parameter(Mandatory=$false)]
        [string]$ClientId,

        [Parameter(Mandatory=$false)]
        [string]$ClientSecret,

        [Parameter(Mandatory=$false)]
        [string]$ApiUrl
    )
    
    try {
        if (-not (Test-Path -Path $DirectoryPath)) {
            Write-Log "Query directory not found: $DirectoryPath" -Level ERROR
            return $false
        }
        
        if (-not (Test-Path -Path $OutputDirectory)) {
            New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
        }
        
        Write-Log "Processing all KQL queries in $DirectoryPath" -Level INFO
        $queryFiles = Get-ChildItem -Path $DirectoryPath -Filter "*.kql"
        
        if ($queryFiles.Count -eq 0) {
            Write-Log "No KQL query files found in $DirectoryPath" -Level WARNING
            return $true
        }
        
        $results = @{}
        $totalFindings = 0
        
        foreach ($file in $queryFiles) {
            $queryName = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
            $outputFile = Join-Path -Path $OutputDirectory -ChildPath "$queryName.csv"
            
            Write-Log "Processing query: $queryName" -Level INFO
            $queryContent = Get-Content -Path $file.FullName -Raw
            
            if ($ValidateQuery) {
                $validationResult = Validate-QuerySyntax -QueryText $queryContent
                if (-not $validationResult) {
                    Write-Log "Skipping $queryName due to validation failure" -Level WARNING
                    continue
                }
            }
            
            try {
            $count = Execute-Query -QueryText $queryContent -OutputFilePath $outputFile -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -ApiUrl $ApiUrl
            } catch {
                Write-Log "Warning: Query execution failed for $($queryName): $_" -Level WARNING
                # ensure an empty output file exists
                "" | Out-File -FilePath $outputFile -Force
                $count = 0
            }
            
            $results[$queryName] = @{
                FileName = $file.Name
                ResultCount = $count
                OutputFile = $outputFile
            }
            
            $totalFindings += $count
            
            Write-Log "Query $queryName completed with $count findings" -Level INFO
        }
        
        Write-Log "All queries processed. Total findings: $totalFindings" -Level INFO
        
        Add-Content -Path $env:GITHUB_OUTPUT -Value "total_findings=$totalFindings"
        if ($totalFindings -gt 0) {
            Add-Content -Path $env:GITHUB_OUTPUT -Value "has_findings=true"
        } else {
            Add-Content -Path $env:GITHUB_OUTPUT -Value "has_findings=false"
        }
        
        return $results
    }
    catch {
        Write-Log "Error processing query directory: $_" -Level ERROR
        return $false
    }
}

try {
    if ($QueryDirectory) {
        Write-Log "Running in directory mode with directory: $QueryDirectory" -Level INFO
        $directoryResults = Execute-QueryDirectory -DirectoryPath $QueryDirectory -OutputDirectory $OutputFile -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -ApiUrl $ApiUrl
        
        if (-not $directoryResults) {
            Write-Log "Directory execution failed" -Level ERROR
            exit 1
        }
        
        Write-Log "Directory execution completed" -Level INFO
    }
    elseif ($QueryFile) {
        Write-Log "Running in file mode with query file: $QueryFile" -Level INFO
        if (-not (Test-Path -Path $QueryFile)) {
            Write-Log "Query file not found: $QueryFile" -Level ERROR
            exit 1
        }
        
        $queryContent = Get-Content -Path $QueryFile -Raw
        
        if ($ValidateQuery) {
            $validationResult = Validate-QuerySyntax -QueryText $queryContent
            if (-not $validationResult) {
                Write-Log "Exiting due to validation failure" -Level ERROR
                exit 1
            }
        }
        
        try {
            $count = Execute-Query -QueryText $queryContent -OutputFilePath $OutputFile -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -ApiUrl $ApiUrl
        } catch {
            Write-Log "Warning: Query execution failed for $($QueryFile): $_" -Level WARNING
            # ensure an empty output file
            "" | Out-File -FilePath $OutputFile -Force
            $count = 0
        }
        Write-Log "Query completed with $count results" -Level INFO
        
        Add-Content -Path $env:GITHUB_OUTPUT -Value "result_count=$count"
        if ($count -gt 0) {
            Add-Content -Path $env:GITHUB_OUTPUT -Value "has_findings=true"
        } else {
            Add-Content -Path $env:GITHUB_OUTPUT -Value "has_findings=false"
        }
    }
    elseif ($Query) {
        Write-Log "Running in direct query mode" -Level INFO
        
        if ($ValidateQuery) {
            $validationResult = Validate-QuerySyntax -QueryText $Query
            if (-not $validationResult) {
                Write-Log "Exiting due to validation failure" -Level ERROR
                exit 1
            }
        }
        
        try {
            $count = Execute-Query -QueryText $Query -OutputFilePath $OutputFile -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -ApiUrl $ApiUrl
        } catch {
            Write-Log "Warning: Direct query execution failed: $_" -Level WARNING
            "" | Out-File -FilePath $OutputFile -Force
            $count = 0
        }
        Write-Log "Query completed with $count results" -Level INFO
        
        Add-Content -Path $env:GITHUB_OUTPUT -Value "result_count=$count"
        if ($count -gt 0) {
            Add-Content -Path $env:GITHUB_OUTPUT -Value "has_findings=true"
        } else {
            Add-Content -Path $env:GITHUB_OUTPUT -Value "has_findings=false"
        }
    }
    else {
        Write-Log "Error: Must provide either Query, QueryFile, or QueryDirectory parameter" -Level ERROR
        exit 1
    }
    
    Write-Log "Query execution completed successfully" -Level INFO
    exit 0
}
catch {
    Write-Log "Fatal error in run-mde-query.ps1: $_" -Level ERROR
    exit 1
}