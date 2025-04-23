# KQL Query Validator Script
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
param (
    [Parameter(Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string] $QueryDirectory = 'queries',

    [switch] $StrictValidation,
    [switch] $ValidatePerformance,
    [switch] $FixCommonIssues
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Log {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)] [string] $Message,
        [ValidateSet('INFO','WARNING','ERROR','DEBUG','SUCCESS')] [string] $Level = 'INFO'
    )
    $timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
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
        DeviceLogonEvents    = @('Timestamp','DeviceId','ActionType','AccountName','InitiatingProcessFileName');
        DeviceNetworkEvents  = @('Timestamp','DeviceId','RemoteIP','Protocol','InitiatingProcessSHA256');
        DeviceProcessEvents  = @('Timestamp','DeviceId','FileName','ProcessId','ProcessCommandLine');
        DeviceFileEvents     = @('Timestamp','DeviceId','ActionType','FileName','FileSize');
        DeviceRegistryEvents = @('Timestamp','DeviceId','RegistryKey','RegistryValueData');
        DeviceAlertEvents    = @('Timestamp','DeviceId','AlertId','Severity');
        DeviceEvents         = @('Timestamp','DeviceId','ActionType','FileName');
        LinuxEvents          = @('Timestamp','DeviceId','EventName','User');
        MacEvents            = @('Timestamp','DeviceId','EventType','ProcessCommandLine')
    }
}

function Test-KqlQuery {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    param (
        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string] $Path
    )
    process {
        try {
            Write-Log "Validating '$Path'" -Level INFO
            $content = Get-Content $Path -Raw
            $issues  = [System.Collections.Generic.List[string]]::new()

            if ($content -match 'let\s+\w+\s*=.+?[^;]\s*let') { $issues.Add('Missing semicolons between let statements') }
            if (($content.ToCharArray() | Where-Object {$_ -eq '('}).Count -ne ($content.ToCharArray() | Where-Object {$_ -eq ')'}).Count) {
                $issues.Add('Unbalanced parentheses')
            }
            if ($content -match '//[^ ]') { $issues.Add('Missing space after // comment') }

            $sqlOperators = @{LIKE='=~'; '<>'=' != '}
            foreach ($op in $sqlOperators.Keys) {
                if ($content -match "(?i)\b$op\b") {
                    $issues.Add("SQL-style operator '$op'")
                }
            }

            if ($ValidatePerformance -and $content -match 'project\s+.+?\|\s*where') {
                $issues.Add("Project-before-where performance anti-pattern")
            }

            $schemaKeys = (Get-CurrentMdeSchema).Keys -join '|'
            $timeFilterPattern = "\b($schemaKeys)\b"
            if ($content -match $timeFilterPattern -and -not ($content -match 'ago\(')) {
                $issues.Add('Missing time filter')
            }

            if ($issues.Count -eq 0) {
                Write-Log "No issues found in '$Path'" -Level SUCCESS
                return @{Path=$Path; Passed=$true; Issues=@()}
            }

            Write-Log "Found $($issues.Count) issue(s) in '$Path': $($issues -join ', ')" -Level WARNING

            if ($FixCommonIssues) {
                if ($PSCmdlet.ShouldProcess($Path, 'Fix issues')) {
                    $fixed = $content
                    if ($issues -contains 'Missing semicolons between let statements') {
                        $fixed = $fixed -replace '(let\s+\w+\s*=.+?)(?<!;)(?=\s*let)','`$1;'
                    }
                    foreach ($op in $sqlOperators.Keys) {
                        if ($issues -contains "SQL-style operator '$op'") {
                            $fixed = $fixed -replace "(?i)\b$op\b", $sqlOperators[$op]
                        }
                    }
                    if ($issues -contains 'Project-before-where performance anti-pattern') {
                        $fixed = [regex]::Replace($fixed,'(\|\s*project[^|]+)(\|\s*where)','$2$1')
                    }
                    if ($issues -contains 'Missing time filter') {
                        $tbl = (Get-CurrentMdeSchema).Keys | Where-Object { $fixed -match "\b$_\b" } | Select-Object -First 1
                        if ($tbl) { $fixed = $fixed -replace "\b$tbl\b","$tbl | where $tbl.Timestamp > ago(1d)" }
                    }
                    Copy-Item $Path "${Path}.bak" -Force
                    Set-Content -Path $Path -Value $fixed
                    Write-Log "Applied fixes and backed up original to '${Path}.bak'" -Level SUCCESS
                    return @{Path=$Path; Passed=$false; Issues=$issues; Fixed=$true}
                }
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
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$QueryPath)
    try {
        $validation = Test-KqlQuery -Path $QueryPath
        return $validation.Passed
    }
    catch {
        Write-Log "Error validating query syntax: $_" -Level ERROR
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
        $results = Get-ChildItem -Path $dir -Filter '*.kql' -File | Test-KqlQuery -Verbose
        
        $failCount = ($results | Where-Object { -not $_.Passed }).Count
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
