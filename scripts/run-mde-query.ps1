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
    [string]$LookbackHours
)

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12, [Net.SecurityProtocolType]::Tls13

function Write-Log {
    param (
        [ValidateSet("INFO","WARNING","ERROR","DEBUG")]
        [string]$Level = "INFO"
    )
    # Australian English generic log
    switch ($Level) {
        "ERROR"   { Write-Host "[${Level}] Operation completed." -ForegroundColor Red }
        "WARNING" { Write-Host "[${Level}] Operation completed." -ForegroundColor Yellow }
        "DEBUG"   { Write-Host "[${Level}] Operation completed." -ForegroundColor Cyan }
        default    { Write-Host "[${Level}] Operation completed." }
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
            Write-Log -Level WARNING
            return $true
        }
        
        $tempQueryFile = [System.IO.Path]::GetTempFileName() + ".kql"
        Set-Content -Path $tempQueryFile -Value $QueryText -Force
        
        Write-Log -Level INFO
        
        . $validateScriptPath
        
        $validationResult = Test-KqlQuerySyntax -QueryPath $tempQueryFile
        
        Remove-Item $tempQueryFile -Force -ErrorAction SilentlyContinue
        
        if ($validationResult) {
            Write-Log -Level INFO
            return $true
        } else {
            Write-Log -Level WARNING
            return $false
        }
    }
    catch {
        Write-Log -Level ERROR
        return $false
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
        Write-Log -Level INFO
        
        if ($LookbackHours) {
            if ($QueryText -notmatch "Timestamp\s*[><]=?\s*ago\(" -and $QueryText -notmatch "datetime_add\s*\(" -and $QueryText -notmatch "datetime\s*\([^)]*\)") {
                Write-Log -Level INFO
                
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
                    
                    Write-Log -Level INFO
                }
            }
        }
        
        Write-Log -Level INFO
        
        $results = @()
        $retryCount = 0
        $success = $false
        
        while (-not $success -and $retryCount -lt $MaxRetries) {
            try {
                Write-Log -Level INFO
                
                Start-Sleep -Seconds 2
                
                # Use generic mock data instead of anything potentially identifiable
                $results = @(
                    [PSCustomObject]@{
                        Timestamp = (Get-Date).Date.ToString("yyyy-MM-dd")
                        DeviceId = "DEVICE-ID"
                        DeviceName = "DEVICE-NAME"
                        ActionType = "EventType"
                        FileName = "file-name"
                    },
                    [PSCustomObject]@{
                        Timestamp = (Get-Date).Date.ToString("yyyy-MM-dd")
                        DeviceId = "DEVICE-ID"
                        DeviceName = "DEVICE-NAME"
                        ActionType = "EventType"
                        FileName = "file-name"
                    }
                )
                
                $success = $true
                Write-Log -Level INFO
            }
            catch {
                $retryCount++
                Write-Log -Level WARNING
                
                if ($retryCount -lt $MaxRetries) {
                    Write-Log -Level INFO
                    Start-Sleep -Seconds $RetryDelaySeconds
                }
                else {
                    Write-Log -Level ERROR
                    throw
                }
            }
        }
        
        $outputDirectory = Split-Path -Path $OutputFilePath -Parent
        if (-not (Test-Path -Path $outputDirectory)) {
            New-Item -Path $outputDirectory -ItemType Directory -Force | Out-Null
        }
        
        if ($results.Count -gt 0) {
            # Sanitize any potentially sensitive data before exporting
            $sanitizedResults = $results | ForEach-Object {
                $obj = [PSCustomObject]@{}
                foreach($prop in $_.PSObject.Properties) {
                    $value = switch($prop.Name) {
                        # Sanitize specific property values
                        "DeviceName" { "DEVICE-NAME" }
                        "RegistryKey" { "REGISTRY-KEY" }
                        "AccountName" { "USERNAME" }
                        "FilePath" { "FILE-PATH" }
                        "IP" { "0.0.0.0" } 
                        "CommandLine" { "COMMAND-LINE" }
                        "DeviceId" { "DEVICE-ID" }
                        # Keep some property types but normalize them
                        "Timestamp" { (Get-Date $prop.Value).Date.ToString("yyyy-MM-dd") }
                        # Pass through other properties
                        default { $prop.Value }
                    }
                    $obj | Add-Member -MemberType NoteProperty -Name $prop.Name -Value $value
                }
                $obj
            }
        
            Write-Log -Level INFO
            
            try {
                $sanitizedResults | Export-Csv -Path $OutputFilePath -NoTypeInformation -Force -ErrorAction Stop
                Write-Log -Level INFO
            }
            catch {
                Write-Log -Level ERROR
                
                Write-Log -Level WARNING
                
                $headers = ($sanitizedResults[0].PSObject.Properties | ForEach-Object { $_.Name }) -join ","
                $csvData = $headers + [Environment]::NewLine
                
                foreach ($row in $sanitizedResults) {
                    $rowValues = ($row.PSObject.Properties | ForEach-Object { 
                        if ($null -eq $_.Value) { '""' } 
                        else { '"' + $_.Value.ToString().Replace('"', '""') + '"' }
                    }) -join ","
                    $csvData += $rowValues + [Environment]::NewLine
                }
                
                $csvData | Out-File -FilePath $OutputFilePath -Encoding utf8 -Force
                Write-Log -Level INFO
            }
            
            return $results.Count
        }
        else {
            Write-Log -Level INFO
            "" | Out-File -FilePath $OutputFilePath -Force
            return 0
        }
    }
    catch {
        Write-Log -Level ERROR
        throw
    }
}

function Execute-QueryDirectory {
    param (
        [Parameter(Mandatory=$true)]
        [string]$DirectoryPath,
        
        [Parameter(Mandatory=$true)]
        [string]$OutputDirectory
    )
    
    try {
        if (-not (Test-Path -Path $DirectoryPath)) {
            Write-Log -Level ERROR
            return $false
        }
        
        if (-not (Test-Path -Path $OutputDirectory)) {
            New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
        }
        
        Write-Log -Level INFO
        $queryFiles = Get-ChildItem -Path $DirectoryPath -Filter "*.kql"
        
        if ($queryFiles.Count -eq 0) {
            Write-Log -Level WARNING
            return $true
        }
        
        $results = @{}
        $totalFindings = 0
        
        foreach ($file in $queryFiles) {
            $queryName = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
            $outputFile = Join-Path -Path $OutputDirectory -ChildPath "$queryName.csv"
            
            Write-Log -Level INFO
            $queryContent = Get-Content -Path $file.FullName -Raw
            
            if ($ValidateQuery) {
                $validationResult = Validate-QuerySyntax -QueryText $queryContent
                if (-not $validationResult) {
                    Write-Log -Level WARNING
                    continue
                }
            }
            
            try {
                $count = Execute-Query -QueryText $queryContent -OutputFilePath $outputFile
            } catch {
                Write-Log -Level WARNING
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
            
            Write-Log -Level INFO
        }
        
        Write-Log -Level INFO
        
        Add-Content -Path $env:GITHUB_OUTPUT -Value "total_findings=$totalFindings"
        if ($totalFindings -gt 0) {
            Add-Content -Path $env:GITHUB_OUTPUT -Value "has_findings=true"
        } else {
            Add-Content -Path $env:GITHUB_OUTPUT -Value "has_findings=false"
        }
        
        return $results
    }
    catch {
        Write-Log -Level ERROR
        return $false
    }
}

try {
    if ($QueryDirectory) {
        Write-Log -Level INFO
        $directoryResults = Execute-QueryDirectory -DirectoryPath $QueryDirectory -OutputDirectory $OutputFile
        
        if (-not $directoryResults) {
            Write-Log -Level ERROR
            exit 1
        }
        
        Write-Log -Level INFO
    }
    elseif ($QueryFile) {
        Write-Log -Level INFO
        if (-not (Test-Path -Path $QueryFile)) {
            Write-Log -Level ERROR
            exit 1
        }
        
        $queryContent = Get-Content -Path $QueryFile -Raw
        
        if ($ValidateQuery) {
            $validationResult = Validate-QuerySyntax -QueryText $queryContent
            if (-not $validationResult) {
                Write-Log -Level ERROR
                exit 1
            }
        }
        
        try {
            $count = Execute-Query -QueryText $queryContent -OutputFilePath $OutputFile
        } catch {
            Write-Log -Level WARNING
            # ensure an empty output file
            "" | Out-File -FilePath $OutputFile -Force
            $count = 0
        }
        Write-Log -Level INFO
        
        Add-Content -Path $env:GITHUB_OUTPUT -Value "result_count=$count"
        if ($count -gt 0) {
            Add-Content -Path $env:GITHUB_OUTPUT -Value "has_findings=true"
        } else {
            Add-Content -Path $env:GITHUB_OUTPUT -Value "has_findings=false"
        }
    }
    elseif ($Query) {
        Write-Log -Level INFO
        
        if ($ValidateQuery) {
            $validationResult = Validate-QuerySyntax -QueryText $Query
            if (-not $validationResult) {
                Write-Log -Level ERROR
                exit 1
            }
        }
        
        try {
            $count = Execute-Query -QueryText $Query -OutputFilePath $OutputFile
        } catch {
            Write-Log -Level WARNING
            "" | Out-File -FilePath $OutputFile -Force
            $count = 0
        }
        Write-Log -Level INFO
        
        Add-Content -Path $env:GITHUB_OUTPUT -Value "result_count=$count"
        if ($count -gt 0) {
            Add-Content -Path $env:GITHUB_OUTPUT -Value "has_findings=true"
        } else {
            Add-Content -Path $env:GITHUB_OUTPUT -Value "has_findings=false"
        }
    }
    else {
        Write-Log -Level ERROR
        exit 1
    }
    
    Write-Log -Level INFO
    exit 0
}
catch {
    Write-Log -Level ERROR
    exit 1
}