#!/bin/bash
# Runner utilities script

# Detect script directory using various methods for cross-platform compatibility
if [ -z "$WORKSPACE_DIR" ]; then
    if [ -n "$GITHUB_WORKSPACE" ]; then
        WORKSPACE_DIR="$GITHUB_WORKSPACE"
    elif [ -n "$PWD" ]; then
        WORKSPACE_DIR="$PWD"
    else
        WORKSPACE_DIR="$(pwd)"
    fi
fi

LOG_DIR="${WORKSPACE_DIR}/logs"
RESULTS_DIR="${WORKSPACE_DIR}/results"
SECURITY_DIR="${WORKSPACE_DIR}/.github/security"
MAX_DISK_USAGE_PERCENT=80
RETENTION_DAYS=14

# Create log directory if it doesn't exist
mkdir -p "${LOG_DIR}"

init_log() {
    local script_name=$1
    LOG_FILE="${LOG_DIR}/${script_name}-$(date +%Y%m%d-%H%M%S).log"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] Log initialized for ${script_name}" > "${LOG_FILE}"
    export LOG_FILE
}

log() {
    local level=$1
    local message=${2:-"Operation completed"}
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [${level}] ${message}" | tee -a "${LOG_FILE}"
}

is_windows() {
    case "$(uname -s)" in
        CYGWIN*|MINGW*|MSYS*|Windows_NT) return 0 ;;
        *) return 1 ;;
    esac
}

create_directories() {
    log "INFO" "Creating required directories"
    
    # Create results directories with default structure
    mkdir -p "${RESULTS_DIR}"/{daily-monitoring,weekly-hunting,critical-checks,parallel-hunting}
    
    # Create security directory for SARIF reports
    mkdir -p "${SECURITY_DIR}"
    
    # Ensure log directory exists
    mkdir -p "${LOG_DIR}"
    
    # Set appropriate permissions
    if ! is_windows; then
        chmod -R 755 "${RESULTS_DIR}" "${LOG_DIR}" "${SECURITY_DIR}" 2>/dev/null || true
    fi
    
    log "INFO" "Directory structure created successfully"
}

check_disk_usage() {
    if is_windows; then
        # Windows environment - use PowerShell to get disk info
        log "INFO" "Windows environment detected, using PowerShell for disk information"
        DISK_USAGE=$(powershell -Command "Get-PSDrive C | Select-Object -ExpandProperty Used" 2>/dev/null)
        DISK_TOTAL=$(powershell -Command "Get-PSDrive C | Select-Object -ExpandProperty Used,Free | ForEach-Object { $_.Used + $_.Free }" 2>/dev/null)
        
        # Calculate percentage
        if [ -n "$DISK_USAGE" ] && [ -n "$DISK_TOTAL" ] && [ "$DISK_TOTAL" -ne "0" ]; then
            DISK_PERCENT=$(echo "scale=0; $DISK_USAGE * 100 / $DISK_TOTAL" | bc)
            log "INFO" "Current disk usage: ${DISK_PERCENT}%"
            echo "${DISK_PERCENT}"
            return
        else
            log "WARNING" "Could not determine disk usage with PowerShell, using default value"
            echo "50"  # Default value for Windows
            return
        fi
    else
        # Linux/Unix environment
        if command -v df >/dev/null 2>&1; then
            DISK_USAGE=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')
            DISK_AVAIL=$(df -h / | awk 'NR==2 {print $4}')
            log "INFO" "Current disk usage: ${DISK_USAGE}%, available: ${DISK_AVAIL}"
            echo "${DISK_USAGE}"
            return
        else
            log "WARNING" "df command not found, using default disk usage value"
            echo "50"  # Default value when df command is not available
            return
        fi
    fi
}

check_powershell() {
    log "INFO" "Checking PowerShell availability"
    
    if is_windows; then
        # Windows should have PowerShell by default
        PWSH_VERSION=$(powershell -Command "$PSVersionTable.PSVersion.ToString()" 2>/dev/null || echo "Unknown")
        log "INFO" "Windows PowerShell detected: $PWSH_VERSION"
        
        # Check if PowerShell Core is also installed
        if command -v pwsh >/dev/null 2>&1; then
            PWSH_CORE_VERSION=$(pwsh -Command "$PSVersionTable.PSVersion.ToString()" 2>/dev/null)
            log "INFO" "PowerShell Core also detected: $PWSH_CORE_VERSION"
        fi
    else
        # On Linux/Unix, check for PowerShell Core
        if ! command -v pwsh >/dev/null 2>&1; then
            log "INFO" "PowerShell Core not found, attempting to install"
            
            if command -v apt-get >/dev/null 2>&1; then
                # Debian/Ubuntu-based systems
                if command -v lsb_release >/dev/null 2>&1; then
                    log "INFO" "Detected Debian/Ubuntu system, installing PowerShell Core"
                    
                    # Download and install Microsoft repository
                    wget -q https://packages.microsoft.com/config/ubuntu/$(lsb_release -rs)/packages-microsoft-prod.deb -O /tmp/ms-prod.deb
                    sudo dpkg -i /tmp/ms-prod.deb
                    rm /tmp/ms-prod.deb
                    
                    # Install PowerShell
                    sudo apt-get update -qq
                    sudo apt-get install -y powershell
                    
                    # Verify installation
                    if command -v pwsh >/dev/null 2>&1; then
                        PWSH_VERSION=$(pwsh --version)
                        log "INFO" "PowerShell Core installed successfully: $PWSH_VERSION"
                    else
                        log "ERROR" "Failed to install PowerShell Core"
                    fi
                else
                    log "ERROR" "Cannot determine OS version - manual PowerShell installation required"
                fi
            elif command -v yum >/dev/null 2>&1; then
                # RHEL/CentOS/Fedora
                log "INFO" "Detected RHEL/CentOS/Fedora system, installing PowerShell Core"
                sudo yum install -y https://github.com/PowerShell/PowerShell/releases/download/v7.2.1/powershell-7.2.1-1.rhel.7.x86_64.rpm
            else
                log "ERROR" "Unsupported package manager - manual PowerShell installation required"
            fi
        else
            PWSH_VERSION=$(pwsh --version 2>/dev/null)
            log "INFO" "PowerShell Core already installed: $PWSH_VERSION"
        fi
    fi
}

check_powershell_modules() {
    local modules=("$@")
    log "INFO" "Checking PowerShell modules: ${modules[*]}"
    
    # Determine which PowerShell to use
    local ps_cmd="pwsh"
    if ! command -v pwsh >/dev/null 2>&1 && is_windows && command -v powershell >/dev/null 2>&1; then
        ps_cmd="powershell"
        log "INFO" "Using Windows PowerShell instead of PowerShell Core"
    fi
    
    $ps_cmd -Command {
        $ErrorActionPreference = 'Stop'
        
        $requiredModules = $args
        
        try {
            # Set PSGallery as trusted
            if (-not (Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue).InstallationPolicy -eq 'Trusted') {
                Write-Host "[INFO] Setting PSGallery as trusted repository"
                Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
            }
            
            # Check each required module
            foreach ($module in $requiredModules) {
                if (-not (Get-Module -ListAvailable -Name $module -ErrorAction SilentlyContinue)) {
                    Write-Host "[INFO] Installing module: $module"
                    Install-Module -Name $module -Force -Scope CurrentUser
                    
                    # Verify installation
                    if (Get-Module -ListAvailable -Name $module -ErrorAction SilentlyContinue) {
                        $installedVersion = (Get-Module -ListAvailable -Name $module | Sort-Object Version -Descending | Select-Object -First 1).Version
                        Write-Host "[INFO] Module $module installed successfully (Version: $installedVersion)"
                    } else {
                        Write-Host "[ERROR] Failed to install module: $module"
                    }
                } else {
                    $currentVersion = (Get-Module -ListAvailable -Name $module | Sort-Object Version -Descending | Select-Object -First 1).Version
                    Write-Host "[INFO] Module $module is already installed (Version: $currentVersion)"
                    
                    # Check for updates if we can connect to PSGallery
                    try {
                        if (Find-Module -Name $module -Repository PSGallery -ErrorAction SilentlyContinue) {
                            $latestVersion = (Find-Module -Name $module).Version
                            if ($latestVersion -gt $currentVersion) {
                                Write-Host "[INFO] Updating $module from $currentVersion to $latestVersion"
                                Update-Module -Name $module -Force
                            }
                        }
                    } catch {
                        Write-Host "[WARNING] Could not check for updates: $_"
                    }
                }
            }
            
            # Report module cache size
            $modulePath = if ($IsWindows) { "$env:USERPROFILE\Documents\PowerShell\Modules" } else { "$HOME/.local/share/powershell/Modules" }
            if (Test-Path $modulePath) {
                $size = (Get-ChildItem $modulePath -Recurse | Measure-Object -Property Length -Sum).Sum / 1MB
                Write-Host "[INFO] PowerShell module cache size: $([Math]::Round($size, 2)) MB"
            }
        }
        catch {
            Write-Host "[ERROR] Error managing PowerShell modules: $_"
            exit 1
        }
    } ${modules[@]}
}

check_connectivity() {
    log "INFO" "Checking network connectivity"
    
    # Function to check URL with timeout
    check_url() {
        local url=$1
        local timeout=5
        local success=false
        
        if command -v curl >/dev/null 2>&1; then
            if curl -s --connect-timeout $timeout -o /dev/null -w "%{http_code}" "$url" | grep -q -E "^[23]"; then
                success=true
            fi
        elif command -v wget >/dev/null 2>&1; then
            if wget -q --timeout=$timeout --spider "$url" 2>/dev/null; then
                success=true
            fi
        elif is_windows && command -v powershell >/dev/null 2>&1; then
            if powershell -Command "try { \$null = Invoke-WebRequest -Uri '$url' -UseBasicParsing -TimeoutSec $timeout -Method Head; \$true } catch { \$false }" | grep -q "True"; then
                success=true
            fi
        fi
        
        echo $success
    }
    
    # Check Microsoft Graph API connectivity
    if [ "$(check_url 'https://graph.microsoft.com/v1.0/')" = "true" ]; then
        log "INFO" "Connectivity to Microsoft Graph API is successful"
    else
        log "WARNING" "Connectivity to Microsoft Graph API failed"
    fi
    
    # Check GitHub API connectivity
    if [ "$(check_url 'https://api.github.com')" = "true" ]; then
        log "INFO" "Connectivity to GitHub API is successful"
    else
        log "WARNING" "Connectivity to GitHub API failed"
    fi
    
    # Check general internet connectivity
    if [ "$(check_url 'https://www.microsoft.com')" = "true" ]; then
        log "INFO" "General internet connectivity is available"
    else
        log "WARNING" "Internet connectivity may be limited or unavailable"
    fi
}

validate_queries() {
    log "INFO" "Validating KQL queries"
    
    local script_path="./scripts/validate-queries.ps1"
    local queries_dir="./queries"
    
    # First check if the validation script exists
    if [ ! -f "$script_path" ]; then
        log "WARNING" "Query validation script not found at $script_path"
        return 0
    fi
    
    # Check if queries directory exists
    if [ ! -d "$queries_dir" ]; then
        log "WARNING" "Queries directory not found at $queries_dir"
        return 0
    fi
    
    # Determine which PowerShell to use
    local ps_cmd="pwsh"
    if ! command -v pwsh >/dev/null 2>&1 && is_windows && command -v powershell >/dev/null 2>&1; then
        ps_cmd="powershell"
    fi
    
    # Run the validation script
    log "INFO" "Running query validation with $ps_cmd"
    $ps_cmd -Command {
        try {
            $scriptPath = "./scripts/validate-queries.ps1"
            $queryDir = "./queries"
            
            Write-Host "[INFO] Executing validation script: $scriptPath"
            & "$scriptPath" -QueryDirectory "$queryDir" -SkipTimeFilterValidation -ErrorAction Stop
            
            if ($LASTEXITCODE -ne 0) {
                Write-Host "[ERROR] Query validation failed with exit code $LASTEXITCODE"
                exit 1
            } else {
                Write-Host "[INFO] All queries passed validation"
            }
        }
        catch {
            Write-Host "[ERROR] Error during query validation: $_"
            exit 1
        }
    }
    
    local result=$?
    if [ $result -ne 0 ]; then
        log "ERROR" "Query validation failed"
        return 1
    else
        log "INFO" "Query validation completed successfully"
        return 0
    fi
}

cleanup_old_results() {
    local retention_days=${1:-$RETENTION_DAYS}
    
    if [ -d "$RESULTS_DIR" ]; then
        log "INFO" "Cleaning up old results"
        
        find "$RESULTS_DIR" -type f \( -name "*.csv" -o -name "*.html" -o -name "*.json" -o -name "*.sarif" \) -mtime +$retention_days -delete
        
        log "INFO" "Old results cleaned up"
    else
        log "WARNING" "Results directory not found"
    fi
}

cleanup_old_logs() {
    local retention_days=${1:-$RETENTION_DAYS}
    
    if [ -d "$LOG_DIR" ]; then
        log "INFO" "Cleaning up old logs"
        find "$LOG_DIR" -type f -name "*.log" -mtime +$retention_days -delete
        log "INFO" "Old logs cleaned up"
    else
        log "INFO" "Log directory not found"
    fi
}

cleanup_system() {
    local force=${1:-false}
    local disk_usage=$(check_disk_usage)
    
    log "INFO" "Performing system cleanup"
    find /tmp -type f -mtime +1 -delete 2>/dev/null || true
    
    PWSH_MODULE_SIZE=$(du -sm ~/.local/share/powershell/Modules 2>/dev/null | cut -f1 || echo "0")
    if [ "$PWSH_MODULE_SIZE" -gt "500" ]; then
        log "WARNING" "PowerShell module cache size exceeds 500MB"
        if [ "$force" = true ] || [ "$disk_usage" -gt "90" ]; then
            log "WARNING" "Cleaning up PowerShell module cache"
            pwsh -Command {
                $modules = Get-Module -ListAvailable | Group-Object -Property Name
                foreach ($module in $modules) {
                    if ($module.Count -gt 1) {
                        $module.Group | Sort-Object Version -Descending | Select-Object -Skip 1 | ForEach-Object {
                            Write-Host "Removing old version of $($_.Name): $($_.Version)"
                            Remove-Item -Path $_.Path -Recurse -Force -ErrorAction SilentlyContinue
                        }
                    }
                }
            }
        fi
    fi
    
    if [ "$force" = true ] || [ "$disk_usage" -gt "85" ]; then
        log "INFO" "Cleaning up package manager cache"
        sudo apt-get clean -y >/dev/null 2>&1 || log "WARNING" "Failed to clean package manager cache"
        
        if [ "$disk_usage" -gt "90" ]; then
            log "WARNING" "Disk usage critical, performing autoremove"
            sudo apt-get autoremove --purge -y >/dev/null 2>&1 || log "WARNING" "Failed to autoremove packages"
        fi
    fi
}

print_environment_summary() {
    local disk_usage=$(check_disk_usage)
    local pwsh_version=$(pwsh --version 2>/dev/null || echo "Not installed")
    local git_version=$(git --version | awk '{print $3}')
    
    log "INFO" "Environment Summary:"
    log "INFO" "Disk Usage: ${disk_usage}%"
    log "INFO" "PowerShell Version: ${pwsh_version}"
    log "INFO" "Git Version: ${git_version}"
}

export -f log
export -f check_disk_usage
export -f create_directories
export -f check_powershell
export -f check_powershell_modules
export -f check_connectivity
export -f validate_queries
export -f cleanup_old_results
export -f cleanup_old_logs
export -f cleanup_system
export -f print_environment_summary