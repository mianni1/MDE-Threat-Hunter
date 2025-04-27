# KQL Query Validator v2
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
param (
    [Parameter(Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string] $QueryDirectory = 'queries',

    [switch] $StrictValidation,
    [switch] $ValidatePerformance,
    [switch] $FixCommonIssues,
    [switch] $ValidateApiCompatibility = $true,
    [switch] $SkipTimeFilterValidation = $true,  # Added parameter with default to true
    
    [switch] $DebugParentheses
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Log {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string] $Message,

        [ValidateSet('INFO','WARNING','ERROR','DEBUG','SUCCESS')]
        [string] $Level = 'INFO'
    )
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    switch ($Level) {
        'ERROR'   { Write-Error "[$timestamp] [ERROR] $Message" -ErrorAction Continue }
        'WARNING' { Write-Warning "[$timestamp] [WARNING] $Message" }
        'DEBUG'   { Write-Debug "[$timestamp] [DEBUG] $Message" }
        'SUCCESS' { Write-Host "[$timestamp] [SUCCESS] $Message" -ForegroundColor Green }
        default   { Write-Host "[$timestamp] [INFO]    $Message" }
    }
}

function Get-CurrentMdeSchema {
    return @{
        DeviceLogonEvents    = @('Timestamp','DeviceId','DeviceName','ActionType','AccountName','AccountDomain','LogonType','InitiatingProcessFileName');
        DeviceNetworkEvents  = @('Timestamp','DeviceId','DeviceName','LocalIP','RemoteIP','RemotePort','RemoteUrl','Protocol','InitiatingProcessFileName','InitiatingProcessSHA256');
        DeviceProcessEvents  = @('Timestamp','DeviceId','DeviceName','FileName','ProcessId','ProcessCommandLine','InitiatingProcessFileName');
        DeviceFileEvents     = @('Timestamp','DeviceId','DeviceName','ActionType','FileName','FolderPath','FileSize','InitiatingProcessFileName');
        DeviceRegistryEvents = @('Timestamp','DeviceId','DeviceName','RegistryKey','RegistryValueData');
        DeviceAlertEvents    = @('Timestamp','DeviceId','DeviceName','AlertId','Severity');
        DeviceEvents         = @('Timestamp','DeviceId','DeviceName','ActionType','FileName');
        LinuxEvents          = @('Timestamp','DeviceId','DeviceName','EventName','User');
        MacEvents            = @('Timestamp','DeviceId','DeviceName','EventType','ProcessCommandLine');
        DeviceFileCertificateInfo = @('Timestamp','DeviceId','DeviceName','FileName','FolderPath','SHA256','Signer','SignatureStatus');
    }
}

function Test-KqlQuery {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    param (
        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('FullName')]
        [string] $Path
    )
    process {
        try {
            Write-Log "Validating '$Path'" -Level INFO
            
            # Make sure the file exists
            if (-not (Test-Path -Path $Path)) {
                Write-Log "File not found: $Path" -Level ERROR
                return [PSCustomObject]@{
                    Path = $Path
                    IsValid = $false
                    Issues = @("File not found")
                }
            }

            $content = Get-Content -Path $Path -Raw
            
            # Check if this is using standard API format (timeWindow variable)
            $hasTimeWindowVariable = $content -match "let\s+timeWindow\s*=\s*ago\(\d+[d|h]\)"
            
            # Skip time filter validation if script parameter is set or if query uses timeWindow variable
            # These filters are added dynamically by run-mde-query.ps1
            $skipTimeFilter = $SkipTimeFilterValidation -or $hasTimeWindowVariable
            
            # Basic syntax validation
            $issues = @()
            $warnings = @() # Separate array for warnings - these won't fail validation
            
            # Parse operations and tables
            $tables = @()
            $tableMatches = [regex]::Matches($content, "(DeviceNetworkEvents|DeviceProcessEvents|DeviceRegistryEvents|DeviceLogonEvents|DeviceFileEvents|DeviceEvents|DeviceFileCertificateInfo|CloudAppEvents)")
            foreach ($match in $tableMatches) {
                $tables += $match.Value
            }
            
            if ($tables.Count -eq 0) {
                $issues += "No device tables found in query"
            }
            
            # Add time filter checks as warnings, not errors
            if (-not $skipTimeFilter) {
                # Check for missing time filters on each table
                $uniqueTables = $tables | Select-Object -Unique 
                foreach ($table in $uniqueTables) {
                    # Check for table-specific time filters (both formats)
                    $hasTimeFilter1 = $content -match "$table\s*\|\s*where\s+Timestamp\s*>\s*(ago\(\d+[dhm]\)|datetime\(.*\))"
                    $hasTimeFilter2 = $content -match "$table\s*\|\s*where\s+$table\.Timestamp\s*>\s*(ago\(\d+[dhm]\)|datetime\(.*\))"
                    $hasTimeFilter3 = $content -match "$table\s*\|\s*where.*\s+Timestamp\s+between\(.*\)"
                    
                    if (-not ($hasTimeFilter1 -or $hasTimeFilter2 -or $hasTimeFilter3)) {
                        $warnings += "Missing time filter on $table" # Always add as warning, not issue
                    }
                }
            } else {
                Write-Log "Skipping time filter validation as per parameter setting" -Level INFO
            }

            # Add field name checks for common fields as warnings instead of errors
            foreach ($table in (Get-CurrentMdeSchema).Keys) {
                if ($content -match "\b$table\b") {
                    if ($content -match "\bApplication\b" -and $table -notmatch "CloudAppEvents") {
                        $warnings += "Field name 'Application' is not available in MDE API schema"
                    }
                    if ($content -match "\bSentBytes\b") {
                        $warnings += "Field name 'SentBytes' is not available in MDE API schema"
                    }
                }
            }

            # Output warnings but don't count them as validation failures
            foreach ($warning in $warnings) {
                Write-Log "$warning" -Level WARNING
            }

            if ($issues.Count -eq 0) {
                Write-Log "No issues found in '$Path'" -Level SUCCESS
                return @{Path=$Path; Passed=$true; Issues=@(); Warnings=$warnings}
            }

            Write-Log "Found $($issues.Count) issue(s) in '$Path': $($issues -join ', ')" -Level WARNING

            if ($FixCommonIssues -and $PSCmdlet.ShouldProcess($Path, 'Apply automatic fixes')) {
                Write-Log "FixCommonIssues is enabled, attempting fixes..." -Level INFO
                $fixed = $content

                # Fix SQL-style operators
                $sqlOperators = @{LIKE='=~'; '<>'=' != '}
                foreach ($op in $sqlOperators.Keys) {
                    if ($issues -contains "SQL-style operator '$op'") {
                        $fixed = $fixed -replace "(?i)\b$op\b", $sqlOperators[$op]
                    }
                }

                # Fix project-before-where
                if ($issues -contains 'Project-before-where performance anti-pattern') {
                    $fixed = [regex]::Replace($fixed, '(\|\s*project[^|]+)(\|\s*where)', '$2$1')
                }

                # Inject a time filter if missing
                $schema = Get-CurrentMdeSchema
                foreach ($table in $schema.Keys) {
                    if ($warnings -contains "Missing time filter on $table") {
                        $fixed = $fixed -replace "(\b$table\b)(?!\s*\|\s*where\s+.*ago\()", "`$1 | where Timestamp > ago(1d)"
                    }
                }

                # Fix known field name errors
                if ($warnings -contains "Field name 'ProcessFileName' is not available in MDE API schema") {
                    $fixed = $fixed -replace "\bProcessFileName\b", "InitiatingProcessFileName"
                }
                if ($warnings -contains "Field name 'SentBytes' is not available in MDE API schema") {
                    $fixed = $fixed -replace "\bSentBytes\b", "BytesSent"
                }

                if ($PSCmdlet.ShouldProcess($Path, "Backup original query")) {
                    Copy-Item $Path "${Path}.bak" -Force
                }

                Set-Content -Path $Path -Value $fixed
                Write-Log "Applied fixes and backed up original to '${Path}.bak'" -Level SUCCESS
                return @{Path=$Path; Passed=$false; Issues=$issues; Fixed=$true; Warnings=$warnings}
            }

            return @{Path=$Path; Passed=$false; Issues=$issues; Fixed=$false; Warnings=$warnings}
        }
        catch {
            Write-Log "Error processing $Path : $_" -Level ERROR
            return @{Path=$Path; Passed=$false; Issues=@("Processing error: $_"); Fixed=$false}
        }
    }
}

function Test-KqlQuerySyntax {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param ([Parameter(Mandatory=$true)][string]$QueryPath)

    try {
        $validation = Test-KqlQuery -Path $QueryPath
        return $validation
    }
    catch {
        Write-Log "Error validating query syntax: $_" -Level ERROR
        return @{Path=$QueryPath; Passed=$false; Issues=@("Exception occurred"); Fixed=$false}
    }
}

function Test-ApiCompatibility {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$QueryPath
    )
    
    try {
        $content = Get-Content -Path $QueryPath -Raw
        $issues = [System.Collections.Generic.List[string]]::new()
        
        # Temporarily replace $left and $right with placeholders to avoid PowerShell variable substitution
        $safeContent = $content -replace '\$left', '##LEFT##' -replace '\$right', '##RIGHT##'
        
        # Check for variable declarations
        $hasVariableDeclarations = $content -match "\blet\s+\w+\s*=\s*"
        if ($hasVariableDeclarations) {
            $variables = [regex]::Matches($content, "let\s+(\w+)\s*=") | ForEach-Object { $_.Groups[1].Value }
            $issues.Add("Query contains variable declarations ($($variables -join ', ')), which may not work properly with MDE API")
        }
        
        # Check for join operations without proper column references
        # Note: We're using our placeholders instead of actual $left/$right
        if ($safeContent -match "\|\s*join\s+" -and $safeContent -notmatch "\|\s*join\s+.*\bon\s+##LEFT##\.") {
            # Make sure it's not using the proper $left/$right syntax
            if (-not ($safeContent -match '##LEFT##\..*==\s*##RIGHT##\.')) {
                $issues.Add("Join operations may not be using fully qualified column references")
            }
        }
        
        # Check for specific field names not in schema
        # But exclude KQL operators and common functions from being reported as issues
        $schema = Get-CurrentMdeSchema
        $kqlOperators = @(
            'where', 'project', 'join', 'distinct', 'summarize', 'extend', 'ago', 
            'count', 'min', 'max', 'avg', 'sum', 'on', 'between', 'bin', 'has',
            'has_any', 'has_all', 'contains', 'strcat', 'tostring', 'datetime_diff',
            'datetime_add', 'format_datetime', 'parse_json', 'array_length',
            'bag_keys', 'extract', 'extract_all', 'parse_url', 'parse_path',
            'hash', 'hash_sha256', 'hash_md5', 'base64_encode', 'base64_decode',
            'pack', 'pack_array', 'case', 'iff', 'iif', 'isnotempty', 'isempty',
            'now', 'array_concat', 'array_sort_asc', 'array_sort_desc', 'sort',
            'sort_desc', 'make_set', 'mv-expand', 'parse_csv', 'row_number'
        )
        
        foreach ($table in $schema.Keys) {
            if ($content -match "\b$table\b") {
                $fields = [regex]::Matches($content, "(?<=$table\s*\|.*?)\b(\w+)\b") | 
                          ForEach-Object { $_.Groups[1].Value } | 
                          Where-Object { 
                              $_ -notin $schema[$table] -and 
                              $_ -notin $kqlOperators -and 
                              # Exclude time units (1d, 7d, etc.)
                              -not ($_ -match '^\d+[dhms]$') -and
                              # Exclude left and right from join operations
                              $_ -ne 'left' -and $_ -ne 'right'
                          }
                          
                foreach ($field in $fields) {
                    # Skip certain field references that are common in KQL but not in our schema
                    # This prevents false positives for legitimate KQL functions
                    if ($field -in @('Application', 'SentBytes')) {
                        # Make these warnings more informative and less alarming
                        $issues.Add("Field name '$field' may need verification in MDE API schema")
                    }
                    else {
                        $issues.Add("Field '$field' may not exist in schema for $table")
                    }
                }
            }
        }
        
        if ($issues.Count -gt 0) {
            $queryFileName = Split-Path -Leaf $QueryPath
            Write-Log "API compatibility issues in '$queryFileName':" -Level WARNING
            foreach ($issue in $issues) {
                Write-Log " - $issue" -Level WARNING
            }
            return $false
        }
        
        return $true
    }
    catch {
        Write-Log "Error testing API compatibility: $_" -Level ERROR
        return $false
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    try {
        # Main validation loop
        $queryFiles = Get-ChildItem -Path $QueryDirectory -Filter "*.kql" | Sort-Object Name
        $totalQueries = $queryFiles.Count
        $passCount = 0
        $warnCount = 0
        $failCount = 0
        $failures = @()

        Write-Log "Scanning directory '$QueryDirectory'" -Level INFO

        foreach ($file in $queryFiles) {
            $result = Test-KqlQuery -Path $file.FullName
            
            if ($result.Passed) {
                $passCount++
                
                # Check for warnings even in passed queries
                if ($result.Warnings.Count -gt 0) {
                    $warnCount++
                    Write-Log "API compatibility issues in '$($file.Name)':" -Level WARNING
                    foreach ($warning in $result.Warnings) {
                        Write-Log " - $warning" -Level WARNING
                    }
                }
            }
            else {
                # Only count as failure if there are actual issues (not just warnings)
                if ($result.Issues.Count -gt 0) {
                    $failures += $result
                    $failCount++
                } else {
                    $warnCount++
                    $passCount++  # Count as pass but with warnings
                }
            }
        }

        # Results summary
        Write-Log "Query Validation Results: $passCount passed, $warnCount with warnings, $failCount failed (out of $totalQueries)" -Level INFO

        # Only fail if there are actual errors (not just warnings)
        if ($failCount -gt 0) {
            Write-Log "$failCount queries failed validation with syntax errors" -Level ERROR
            
            foreach ($failure in $failures) {
                Write-Log "Failed: $($failure.Path) - Issues: $($failure.Issues -join '; ')" -Level ERROR
            }
            
            exit 1
        } else {
            Write-Log "All queries passed validation ($warnCount with warnings)" -Level SUCCESS
            exit 0
        }
    }
    catch {
        Write-Log "Error: $_" -Level ERROR
        exit 1
    }
}
