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
        
        # Check for variable declarations
        $hasVariableDeclarations = $content -match "\blet\s+\w+\s*=\s*"
        if ($hasVariableDeclarations) {
            $variables = [regex]::Matches($content, "let\s+(\w+)\s*=") | ForEach-Object { $_.Groups[1].Value }
            $issues.Add("Query contains variable declarations ($($variables -join ', ')), which may not work properly with MDE API")
        }
        
        # Check for column references in joins
        if ($content -match "\|\s*join\s+" -and $content -notmatch "\|\s*join\s+.*\bon\s+\`\$left\.") {
            $issues.Add("Join operations may not be using fully qualified column references")
        }
        
        # Check for specific field names not in schema
        $schema = Get-CurrentMdeSchema
        foreach ($table in $schema.Keys) {
            if ($content -match "\b$table\b") {
                $fields = [regex]::Matches($content, "(?<=$table\s*\|.*?)\b(\w+)\b") | ForEach-Object { $_.Groups[1].Value } | Where-Object { $_ -notin $schema[$table] -and $_ -ne "where" -and $_ -ne "project" -and $_ -ne "join" -and $_ -ne "distinct" -and $_ -ne "summarize" -and $_ -ne "extend" }
                foreach ($field in $fields) {
                    $issues.Add("Field '$field' may not exist in schema for $table")
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
            
            # Additional API compatibility check
            if ($ValidateApiCompatibility -and $validation.Passed) {
                $apiCompatible = Test-ApiCompatibility -QueryPath $_.FullName
                if (-not $apiCompatible) {
                    $validation.Passed = $false
                    $validation.Issues += "API compatibility issues detected"
                }
            }
            
            $validation
        }

        $failCount = ($results | Where-Object { -not $_.Passed } | Measure-Object).Count
        if ($failCount -gt 0) {
            Write-Log "$failCount queries failed validation" -Level ERROR
            exit 1
        }

        Write-Log 'Validation complete. All queries passed.' -Level SUCCESS
        exit 0
    }
    catch {
        Write-Log "Error: $_" -Level ERROR
        exit 1
    }
}
