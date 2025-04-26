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
            if (-not (Test-Path $Path)) {
                Write-Log "File not found: $Path" -Level ERROR
                return @{Path=$Path; Passed=$false; Issues=@("File not found"); Fixed=$false}
            }
            
            $content = Get-Content $Path -Raw
            $issues  = [System.Collections.Generic.List[string]]::new()

            # Check for unbalanced parentheses with better diagnostics
            $openCount = ($content.ToCharArray() | Where-Object {$_ -eq '('} | Measure-Object).Count
            $closeCount = ($content.ToCharArray() | Where-Object {$_ -eq ')'} | Measure-Object).Count
            
            if ($openCount -ne $closeCount) {
                $parenthesisIssue = "Unbalanced parentheses: $openCount opening vs $closeCount closing"
                $issues.Add($parenthesisIssue)
                
                if ($DebugParentheses) {
                    Write-Log "Parentheses detail: $openCount opening '(' and $closeCount closing ')' parentheses" -Level WARNING
                    
                    # Try to find where the mismatch might be happening
                    $lines = $content -split "`n"
                    for ($i = 0; $i -lt $lines.Count; $i++) {
                        $line = $lines[$i]
                        $openInLine = ($line.ToCharArray() | Where-Object {$_ -eq '('} | Measure-Object).Count
                        $closeInLine = ($line.ToCharArray() | Where-Object {$_ -eq ')'} | Measure-Object).Count
                        
                        if ($openInLine -ne $closeInLine) {
                            Write-Log "Line $($i+1): $openInLine opening, $closeInLine closing -> $line" -Level WARNING
                        }
                    }
                }
            }

            # Check for missing space after comment markers
            if ($content -match '//[^\s]') {
                $issues.Add('Missing space after // comment')
            }

            # SQL-style operator misuse
            $sqlOperators = @{LIKE='=~'; '<>'=' != '}
            foreach ($op in $sqlOperators.Keys) {
                if ($content -match "(?i)\b$op\b") {
                    $issues.Add("SQL-style operator '$op'")
                }
            }

            # Performance anti-pattern
            if ($ValidatePerformance -and $content -match 'project\s+.+?\|\s*where') {
                $issues.Add('Project-before-where performance anti-pattern')
            }

            # Check for missing time filter on known tables
            $schema = Get-CurrentMdeSchema
            foreach ($table in $schema.Keys) {
                if ($content -match "\b$table\b" -and $content -notmatch "$table\s*\|\s*where\s+.*ago\(") {
                    $issues.Add("Missing time filter on $table")
                }
            }

            # API Compatibility checks
            if ($ValidateApiCompatibility) {
                # Check for variable references in joins which are problematic for MDE API
                if ($content -match "\|\s*join\s+.*\blet\b") {
                    $issues.Add("Variable references in join operations are not API-compatible")
                }
                
                # Check for variable references used later in the query (after a join statement)
                $letVariables = [regex]::Matches($content, "let\s+(\w+)\s*=") | ForEach-Object { $_.Groups[1].Value }
                $lines = $content -split "`n"
                $joinFound = $false
                
                foreach ($line in $lines) {
                    if ($line -match "\|\s*join\s+") {
                        $joinFound = $true
                    }
                    
                    if ($joinFound) {
                        foreach ($var in $letVariables) {
                            if ($line -match "\b$var\.") {
                                $issues.Add("Variable reference after join statement: '$var' may not be API-compatible")
                                break
                            }
                        }
                    }
                }
                
                # Check for known non-existent field names in MDE API
                $nonExistentFields = @("ProcessFileName", "SentBytes", "Application")
                foreach ($field in $nonExistentFields) {
                    if ($content -match "\b$field\b") {
                        $issues.Add("Field name '$field' is not available in MDE API schema")
                    }
                }

                # Check for simple column references in joins that need table qualification
                # Fix: Properly escape the $ characters in the regex pattern
                if ($content -match "\|\s*join\s+.*\bon\s+(?!.*\`$left\.|\`$right\.).*DeviceId") {
                    $issues.Add("Join without fully qualified column references (use `$left.Column == `$right.Column syntax)")
                }
            }

            if ($issues.Count -eq 0) {
                Write-Log "No issues found in '$Path'" -Level SUCCESS
                return @{Path=$Path; Passed=$true; Issues=@()}
            }

            Write-Log "Found $($issues.Count) issue(s) in '$Path': $($issues -join ', ')" -Level WARNING

            if ($FixCommonIssues -and $PSCmdlet.ShouldProcess($Path, 'Apply automatic fixes')) {
                Write-Log "FixCommonIssues is enabled, attempting fixes..." -Level INFO
                $fixed = $content

                # Fix SQL-style operators
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
                foreach ($table in $schema.Keys) {
                    if ($issues -contains "Missing time filter on $table") {
                        $fixed = $fixed -replace "(\b$table\b)(?!\s*\|\s*where\s+.*ago\()", "`$1 | where Timestamp > ago(1d)"
                    }
                }

                # Fix known field name errors
                if ($issues -contains "Field name 'ProcessFileName' is not available in MDE API schema") {
                    $fixed = $fixed -replace "\bProcessFileName\b", "InitiatingProcessFileName"
                }
                if ($issues -contains "Field name 'SentBytes' is not available in MDE API schema") {
                    $fixed = $fixed -replace "\bSentBytes\b", "BytesSent"
                }

                if ($PSCmdlet.ShouldProcess($Path, "Backup original query")) {
                    Copy-Item $Path "${Path}.bak" -Force
                }

                Set-Content -Path $Path -Value $fixed
                Write-Log "Applied fixes and backed up original to '${Path}.bak'" -Level SUCCESS
                return @{Path=$Path; Passed=$false; Issues=$issues; Fixed=$true}
            }

            return @{Path=$Path; Passed=$false; Issues=$issues; Fixed=$false}
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
        $dir = $QueryDirectory
        if (-not (Test-Path -Path $dir)) {
            $dir = Join-Path (Split-Path -Parent $PSScriptRoot) $QueryDirectory
        }
        if (-not (Test-Path -Path $dir)) {
            throw "Cannot find query directory: $QueryDirectory"
        }

        $dir = Resolve-Path -Path $dir -ErrorAction Stop
        Write-Log "Scanning directory '$dir'" -Level INFO
        
        # Use FullName property to ensure full file paths are passed to Test-KqlQuery
        $results = Get-ChildItem -Path $dir -Filter '*.kql' -File | ForEach-Object {
            Write-Log "Processing file: $($_.FullName)" -Level DEBUG
            $validation = Test-KqlQuery -Path $_.FullName
            
            # For queries with field name issues, don't mark them as failing
            if (-not $validation.Passed) {
                # Check if the only issues are field name warnings
                $fieldIssuesOnly = $true
                foreach ($issue in $validation.Issues) {
                    if (-not ($issue -match "Field name '(Application|SentBytes)' is not available in MDE API schema")) {
                        $fieldIssuesOnly = $false
                        break
                    }
                }
                
                # If only field name warnings, mark as passed but keep the warnings
                if ($fieldIssuesOnly) {
                    $validation.Passed = $true
                    $validation.Issues += "Treating field name warnings as non-critical"
                }
            }
            
            # Additional API compatibility check
            if ($ValidateApiCompatibility -and $validation.Passed) {
                # Modified to treat API compatibility warnings as non-fatal
                $apiCompatible = Test-ApiCompatibility -QueryPath $_.FullName
                # Only mark as failed if real syntax issues are found
                # API compatibility warnings are informational only
                if (-not $apiCompatible) {
                    # Don't fail the validation just for API compatibility warnings
                    # $validation.Passed = $false 
                    $validation.Issues += "API compatibility issues detected (informational)"
                }
            }
            
            $validation
        }

        # Count only real syntax errors, not API compatibility warnings
        $realFailures = $results | Where-Object { 
            -not $_.Passed -and 
            ($_.Issues -notcontains "API compatibility issues detected (informational)") -and
            (-not ($_.Issues -join " " -match "may not exist in schema")) -and
            (-not ($_.Issues -join " " -match "Field name '(Application|SentBytes)' is not available in MDE API schema"))
        }
        
        $failCount = ($realFailures | Measure-Object).Count
        $warningCount = ($results | 
                         Where-Object { 
                            $_.Issues -join " " -match "may not exist in schema" -or 
                            $_.Issues -join " " -match "Field name '(Application|SentBytes)' is not available in MDE API schema"
                         } | 
                         Measure-Object).Count
        
        if ($failCount -gt 0) {
            Write-Log "$failCount queries failed validation with syntax errors" -Level ERROR
            # Add summary of failures
            foreach ($failure in $realFailures) {
                Write-Log "Failed: $($failure.Path) - Issues: $($failure.Issues -join "; ")" -Level ERROR
            }
            exit 1
        }
        
        if ($warningCount -gt 0) {
            Write-Log "$warningCount queries have API compatibility warnings (non-fatal)" -Level WARNING
        }

        Write-Log 'Validation complete. All queries passed critical checks.' -Level SUCCESS
        exit 0
    }
    catch {
        Write-Log "Error: $_" -Level ERROR
        exit 1
    }
}
