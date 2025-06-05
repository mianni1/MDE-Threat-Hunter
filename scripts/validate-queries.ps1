# KQL Query Validator Script
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
param (
    [Parameter(Mandatory, Position = 0)]
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
        'ERROR'   { Write-Error "[$timestamp] [ERROR] $Message" }
        'WARNING' { Write-Warning "[$timestamp] [WARNING] $Message" }
        'DEBUG'   { Write-Debug "[$timestamp] [DEBUG] $Message" }
        'SUCCESS' { Write-Verbose "[$timestamp] [SUCCESS] $Message" }
        default   { Write-Verbose "[$timestamp] [INFO]    $Message" }
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
        Write-Log "Validating '$Path'" -Level INFO
        $content = Get-Content $Path -Raw
        $issues  = [System.Collections.Generic.List[string]]::new()

        if ($content -match '(?ms)let\s+\w+\s*=[^;\r\n]+\r?\n\s*let') {
            $issues.Add('Missing semicolons between let statements')
        }
        if (($content.ToCharArray() | Where-Object {$_ -eq '('}).Count -ne ($content.ToCharArray() | Where-Object {$_ -eq ')'}).Count) {
            $issues.Add('Unbalanced parentheses')
        }
        if ($content -match '//(?!\s)') {
            $issues.Add('Missing space after // comment')
        }

        $sqlOperators = @{LIKE='=~'; '<>'=' != '}
        foreach ($op in $sqlOperators.Keys) {
            if ($content -match "(?i)\b$op\b") {
                $issues.Add("SQL-style operator '$op'")
            }
        }

        if ($ValidatePerformance -and $content -match 'project\s+.+?\|\s*where') {
            $issues.Add("Project-before-where performance anti-pattern")
        }

        $schemaKeys        = (Get-CurrentMdeSchema).Keys -join '|'
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
                    $fixed = [regex]::Replace($fixed,'(?ms)(let\s+\w+\s*=[^;\r\n]+)(\r?\n\s*let)','$1;$2')
                }
                if ($issues -contains 'Missing space after // comment') {
                    $fixed = $fixed -replace '//(\S)','// $1'
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
}

function Test-KqlQuerySyntax {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$QueryPath)
    $validation = Test-KqlQuery -Path $QueryPath
    return $validation.Passed
}

try {
    $dir = Resolve-Path -Path $QueryDirectory -ErrorAction Stop
    Write-Log "Scanning directory '$dir'" -Level INFO
    Get-ChildItem -Path $dir -Filter '*.kql' -File | Test-KqlQuery -Verbose
    Write-Log 'Validation complete.' -Level INFO
    exit 0
} catch {
    Write-Log "Error: $_" -Level ERROR
    exit 1
}
