# PowerShell Environment Setup Script for Self-hosted Runners
# This script prepares the PowerShell environment for MDE Threat Hunter GitHub Actions
# It ensures required modules are installed and available

[CmdletBinding()]
param (
    [Parameter()]
    [switch] $ForceUpdate,
    
    [Parameter()]
    [switch] $Cleanup
)

# Configure strict mode and error handling
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$VerbosePreference = if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"]) { 'Continue' } else { 'SilentlyContinue' }
$ProgressPreference = 'SilentlyContinue'  # Suppress progress bars for performance

# Required modules with versions
$requiredModules = @(
    @{Name = "Microsoft.Graph.Security"; MinVersion = "1.0.0"; Required = $true},
    @{Name = "PSWriteHTML"; MinVersion = "0.0.0"; Required = $false},
    @{Name = "ImportExcel"; MinVersion = "0.0.0"; Required = $false}
)

# Log function to handle different message types
function Write-EnvLog {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string] $Message,
        
        [Parameter()]
        [ValidateSet('INFO', 'WARNING', 'ERROR', 'SUCCESS', 'VERBOSE')]
        [string] $Level = 'INFO'
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logMessage = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        'ERROR'   { Write-Error $logMessage -ErrorAction Continue }
        'WARNING' { Write-Warning $logMessage }
        'SUCCESS' { Write-Host $logMessage -ForegroundColor Green }
        'VERBOSE' { Write-Verbose $logMessage }
        default   { Write-Host $logMessage }
    }
}

function Initialize-PSRepository {
    try {
        # Configure PSGallery as trusted
        Write-EnvLog "Configuring PSGallery repository" -Level VERBOSE
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop
        Write-EnvLog "PSGallery repository configured successfully" -Level SUCCESS
    }
    catch {
        Write-EnvLog "Failed to configure PSGallery repository: $_" -Level WARNING
        # Try to register the repository if it doesn't exist
        try {
            Register-PSRepository -Default -ErrorAction Stop
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop
            Write-EnvLog "PSGallery repository registered and configured" -Level SUCCESS
        }
        catch {
            Write-EnvLog "Critical failure configuring PSGallery: $_" -Level ERROR
            return $false
        }
    }
    return $true
}

function Get-ModuleStatus {
    param (
        [Parameter(Mandatory)]
        [hashtable] $ModuleInfo
    )
    
    $moduleName = $ModuleInfo.Name
    $minVersion = $ModuleInfo.MinVersion
    
    try {
        $installedModule = Get-Module -Name $moduleName -ListAvailable | 
            Sort-Object Version -Descending | 
            Select-Object -First 1
            
        if (-not $installedModule) {
            Write-EnvLog "Module '$moduleName' is not installed" -Level WARNING
            return @{
                Installed = $false
                CurrentVersion = $null
                NeedsUpdate = $true
            }
        }
        
        Write-EnvLog "Module '$moduleName' found: v$($installedModule.Version)" -Level VERBOSE
        
        # Check if update is available (only if we have network connectivity)
        try {
            $onlineModule = Find-Module -Name $moduleName -Repository PSGallery -ErrorAction Stop
            $needsUpdate = $onlineModule.Version -gt $installedModule.Version
            
            if ($needsUpdate) {
                Write-EnvLog "Update available for '$moduleName': v$($installedModule.Version) -> v$($onlineModule.Version)" -Level INFO
            }
            else {
                Write-EnvLog "Module '$moduleName' is up to date (v$($installedModule.Version))" -Level VERBOSE
            }
        }
        catch {
            Write-EnvLog "Couldn't check online version for '$moduleName': $_" -Level WARNING
            $needsUpdate = $false
        }
        
        # Special version checking logic if minimum version is specified
        if ($minVersion -ne "0.0.0") {
            $requiredVersion = [System.Version]$minVersion
            if ($installedModule.Version -lt $requiredVersion) {
                Write-EnvLog "Module '$moduleName' version $($installedModule.Version) is below required minimum $minVersion" -Level WARNING
                $needsUpdate = $true
            }
        }
        
        return @{
            Installed = $true
            CurrentVersion = $installedModule.Version
            NeedsUpdate = $needsUpdate
        }
    }
    catch {
        Write-EnvLog "Error checking module '$moduleName' status: $_" -Level WARNING
        return @{
            Installed = $false
            CurrentVersion = $null
            NeedsUpdate = $true
            Error = $_
        }
    }
}

function Update-PSModule {
    param (
        [Parameter(Mandatory)]
        [hashtable] $ModuleInfo,
        
        [Parameter()]
        [switch] $Force
    )
    
    $moduleName = $ModuleInfo.Name
    $minVersion = $ModuleInfo.MinVersion
    $status = Get-ModuleStatus -ModuleInfo $ModuleInfo
    
    # Only proceed if module needs installation or update
    if (-not $status.Installed -or $status.NeedsUpdate -or $Force) {
        try {
            if (-not $status.Installed) {
                Write-EnvLog "Installing module '$moduleName'" -Level INFO
                if ($minVersion -ne "0.0.0") {
                    Install-Module -Name $moduleName -MinimumVersion $minVersion -Force -Scope CurrentUser -ErrorAction Stop
                }
                else {
                    Install-Module -Name $moduleName -Force -Scope CurrentUser -ErrorAction Stop
                }
            }
            else {
                Write-EnvLog "Updating module '$moduleName' from v$($status.CurrentVersion)" -Level INFO
                Update-Module -Name $moduleName -Force -ErrorAction Stop
            }
            
            # Verify installation
            $newStatus = Get-ModuleStatus -ModuleInfo $ModuleInfo
            if ($newStatus.Installed) {
                Write-EnvLog "Module '$moduleName' v$($newStatus.CurrentVersion) installed successfully" -Level SUCCESS
                return $true
            }
            else {
                Write-EnvLog "Failed to verify '$moduleName' installation" -Level ERROR
                return $false
            }
        }
        catch {
            Write-EnvLog "Error installing/updating module '$moduleName': $_" -Level ERROR
            return $false
        }
    }
    else {
        Write-EnvLog "Module '$moduleName' v$($status.CurrentVersion) is already up to date" -Level INFO
        return $true
    }
}

function Remove-OldModuleVersions {
    param (
        [Parameter()]
        [switch] $AggressiveCleanup
    )
    
    Write-EnvLog "Checking for old module versions to clean up" -Level INFO
    
    try {
        $modulesToCheck = if ($AggressiveCleanup) {
            Get-Module -ListAvailable | Group-Object -Property Name
        }
        else {
            $requiredModules | ForEach-Object { 
                Get-Module -Name $_.Name -ListAvailable -ErrorAction SilentlyContinue | Group-Object -Property Name
            }
        }
        
        $versionsRemoved = 0
        
        foreach ($moduleGroup in $modulesToCheck) {
            if ($moduleGroup.Count -gt 1) {
                # Keep the newest version and remove others
                $modulesToRemove = $moduleGroup.Group | Sort-Object Version -Descending | Select-Object -Skip 1
                foreach ($moduleToRemove in $modulesToRemove) {
                    try {
                        $modulePath = (Get-Item $moduleToRemove.Path).Directory.FullName
                        Write-EnvLog "Removing $($moduleToRemove.Name) v$($moduleToRemove.Version)" -Level VERBOSE
                        Remove-Item -Path $modulePath -Recurse -Force -ErrorAction Stop
                        $versionsRemoved++
                    }
                    catch {
                        Write-EnvLog "Failed to remove $($moduleToRemove.Name) v$($moduleToRemove.Version): $_" -Level WARNING
                    }
                }
            }
        }
        
        if ($versionsRemoved -gt 0) {
            Write-EnvLog "Removed $versionsRemoved old module version(s)" -Level SUCCESS
        }
        else {
            Write-EnvLog "No old module versions to remove" -Level INFO
        }
    }
    catch {
        Write-EnvLog "Error during module cleanup: $_" -Level WARNING
    }
}

function Get-ModuleCacheSize {
    # Use $PSVersionTable to determine proper module paths for different PowerShell versions
    $psModulePath = if ($IsWindows -or $PSVersionTable.PSEdition -eq "Desktop") {
        if ($PSVersionTable.PSEdition -eq "Desktop") {
            # Windows PowerShell 5.1
            "$env:USERPROFILE\Documents\WindowsPowerShell\Modules"
        } else {
            # PowerShell Core on Windows
            "$env:USERPROFILE\Documents\PowerShell\Modules"
        }
    } else {
        # PowerShell Core on Linux/macOS
        "$HOME/.local/share/powershell/Modules"
    }
    
    # Also check system-wide modules on Linux
    $systemModulePath = if (-not $IsWindows -and -not $PSVersionTable.Platform -eq "Win32NT") {
        "/usr/local/share/powershell/Modules"
    } else {
        $null
    }
    
    if (-not (Test-Path $psModulePath)) {
        return @{
            SizeBytes = 0
            SizeMB = 0
            Path = $psModulePath
        }
    }
    
    try {
        $size = (Get-ChildItem $psModulePath -Recurse -File | Measure-Object -Property Length -Sum).Sum
        $sizeMB = [Math]::Round($size / 1MB, 2)
        
        return @{
            SizeBytes = $size
            SizeMB = $sizeMB
            Path = $psModulePath
        }
    }
    catch {
        Write-EnvLog "Error calculating module cache size: $_" -Level WARNING
        return @{
            SizeBytes = 0
            SizeMB = 0
            Path = $psModulePath
            Error = $_
        }
    }
}

function Export-EnvironmentSummary {
    param (
        [Parameter()]
        [string] $OutputPath
    )
    
    $summary = [PSCustomObject]@{
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Modules = @()
        ModuleCacheSize = (Get-ModuleCacheSize).SizeMB
        ModulePath = (Get-ModuleCacheSize).Path
    }
    
    foreach ($module in $requiredModules) {
        $status = Get-ModuleStatus -ModuleInfo $module
        $summary.Modules += [PSCustomObject]@{
            Name = $module.Name
            Required = $module.Required
            MinVersion = $module.MinVersion
            Installed = $status.Installed
            CurrentVersion = if ($status.CurrentVersion) { $status.CurrentVersion.ToString() } else { "Not installed" }
        }
    }
    
    if ($OutputPath) {
        $summary | ConvertTo-Json -Depth 3 | Out-File -FilePath $OutputPath -Encoding utf8
        Write-EnvLog "Environment summary exported to $OutputPath" -Level INFO
    }
    
    return $summary
}

function Write-GitHubOutput {
    param (
        [Parameter(Mandatory)]
        [string] $Name,
        
        [Parameter(Mandatory)]
        [string] $Value
    )
    
    if ($env:GITHUB_OUTPUT) {
        try {
            "$Name=$Value" | Out-File -FilePath $env:GITHUB_OUTPUT -Encoding utf8 -Append
            Write-EnvLog "GitHub output variable set: $Name=$Value" -Level VERBOSE
        }
        catch {
            Write-EnvLog "Failed to write GitHub output variable: $_" -Level WARNING
        }
    }
    else {
        Write-EnvLog "GITHUB_OUTPUT environment variable not set, skipping output" -Level VERBOSE
    }
}

# MAIN EXECUTION

Write-EnvLog "PowerShell Environment Setup Starting" -Level INFO
Write-EnvLog "PowerShell Version: $($PSVersionTable.PSVersion)" -Level INFO

# Initialize PSGallery
if (-not (Initialize-PSRepository)) {
    Write-EnvLog "Failed to initialize PowerShell repository" -Level ERROR
    exit 1
}

# Check current module cache size
$initialCacheSize = Get-ModuleCacheSize
Write-EnvLog "Initial module cache size: $($initialCacheSize.SizeMB) MB" -Level INFO

# Process modules
$updateResults = @()
$requiredMissing = $false

foreach ($module in $requiredModules) {
    $result = Update-PSModule -ModuleInfo $module -Force:$ForceUpdate
    $updateResults += $result
    
    if (-not $result -and $module.Required) {
        $requiredMissing = $true
        Write-EnvLog "Required module '$($module.Name)' failed to install" -Level ERROR
    }
}

# Clean up old module versions if requested or cache is large
if ($Cleanup -or $initialCacheSize.SizeMB -gt 500) {
    Write-EnvLog "Performing module cleanup" -Level INFO
    Remove-OldModuleVersions -AggressiveCleanup:($initialCacheSize.SizeMB -gt 1000)
}

# Compare cache size after operations
$finalCacheSize = Get-ModuleCacheSize
$cacheDifference = $finalCacheSize.SizeMB - $initialCacheSize.SizeMB

if ([Math]::Abs($cacheDifference) -gt 0.1) {
    if ($cacheDifference -gt 0) {
        Write-EnvLog "Module cache size increased by $([Math]::Round($cacheDifference, 2)) MB" -Level INFO
    }
    else {
        Write-EnvLog "Module cache size decreased by $([Math]::Round([Math]::Abs($cacheDifference), 2)) MB" -Level SUCCESS
    }
}

# Export environment summary
$summary = Export-EnvironmentSummary -OutputPath "$PSScriptRoot\..\logs\powershell-env-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"

# Set GitHub outputs if in GitHub Actions
if ($env:GITHUB_ACTIONS -eq "true") {
    Write-GitHubOutput -Name "environment_ready" -Value $(if ($requiredMissing) { "false" } else { "true" })
    Write-GitHubOutput -Name "cache_size_mb" -Value $finalCacheSize.SizeMB
    
    # Create detailed module report for GitHub
    $moduleReport = $summary.Modules | ForEach-Object { "$($_.Name):$($_.CurrentVersion)" }
    Write-GitHubOutput -Name "modules_report" -Value $($moduleReport -join "|")
}

if ($requiredMissing) {
    Write-EnvLog "PowerShell environment setup completed with errors" -Level ERROR
    exit 1
}
else {
    Write-EnvLog "PowerShell environment setup completed successfully" -Level SUCCESS
    exit 0
}