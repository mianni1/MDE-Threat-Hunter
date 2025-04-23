#!/bin/bash
# Runner utilities script

WORKSPACE_DIR="$(pwd)"
LOG_DIR="${WORKSPACE_DIR}/logs"
RESULTS_DIR="${WORKSPACE_DIR}/results"
SECURITY_DIR="${WORKSPACE_DIR}/.github/security"
MAX_DISK_USAGE_PERCENT=80
RETENTION_DAYS=14

mkdir -p "${LOG_DIR}"

init_log() {
    local script_name=$1
    LOG_FILE="${LOG_DIR}/${script_name}-$(date +%Y%m%d-%H%M%S).log"
    echo "Log initialized at $(date)" > "${LOG_FILE}"
    export LOG_FILE
}

log() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" | tee -a "${LOG_FILE}"
}

create_directories() {
    log "INFO" "Creating required directories"
    mkdir -p "${RESULTS_DIR}"/{daily-monitoring,weekly-hunting,critical-checks,parallel-hunting}
    mkdir -p "${SECURITY_DIR}"
    mkdir -p "${LOG_DIR}"
}

check_disk_usage() {
    DISK_USAGE=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')
    DISK_AVAIL=$(df -h / | awk 'NR==2 {print $4}')
    log "INFO" "Current disk usage: ${DISK_USAGE}% (Available: ${DISK_AVAIL})"
    echo "${DISK_USAGE}"
}

check_powershell() {
    if ! command -v pwsh &> /dev/null; then
        log "INFO" "PowerShell not found. Installing PowerShell..."
        
        wget -q https://packages.microsoft.com/config/ubuntu/$(lsb_release -rs)/packages-microsoft-prod.deb
        sudo dpkg -i packages-microsoft-prod.deb
        sudo apt-get update -qq
        sudo apt-get install -y powershell
        rm packages-microsoft-prod.deb
        
        PWSH_VERSION=$(pwsh --version)
        log "INFO" "PowerShell installed: $PWSH_VERSION"
    else
        PWSH_VERSION=$(pwsh --version)
        log "INFO" "PowerShell already installed: $PWSH_VERSION"
    fi
}

check_powershell_modules() {
    local modules=("$@")
    log "INFO" "Checking PowerShell modules: ${modules[*]}"
    
    pwsh -Command {
        $ErrorActionPreference = 'Stop'
        
        $requiredModules = $args
        
        if (-not (Get-PSRepository -Name PSGallery).InstallationPolicy -eq 'Trusted') {
            Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [INFO] Setting PSGallery as trusted repository"
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
        }
        
        foreach ($module in $requiredModules) {
            if (-not (Get-Module -ListAvailable -Name $module)) {
                Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [INFO] Installing module: $module"
                Install-Module -Name $module -Force -Scope CurrentUser
            } else {
                $currentVersion = (Get-Module -ListAvailable -Name $module | Sort-Object Version -Descending | Select-Object -First 1).Version
                Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [INFO] Module $module is already installed (Version: $currentVersion)"
                
                try {
                    $latestVersion = (Find-Module -Name $module -ErrorAction Stop).Version
                    if ($latestVersion -gt $currentVersion) {
                        Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [INFO] Updating $module from $currentVersion to $latestVersion"
                        Update-Module -Name $module -Force
                    }
                } catch {
                    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [WARNING] Could not check for updates: $_"
                }
            }
        }
        
        $modulePath = "$HOME/.local/share/powershell/Modules"
        if (Test-Path $modulePath) {
            $size = (Get-ChildItem $modulePath -Recurse | Measure-Object -Property Length -Sum).Sum / 1MB
            Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [INFO] PowerShell module cache size: $([Math]::Round($size, 2)) MB"
        }
    } ${modules[@]}
}

check_connectivity() {
    log "INFO" "Testing connectivity to key services:"

    if curl -s -o /dev/null -w "%{http_code}" https://graph.microsoft.com/v1.0/ | grep -q "200"; then
        log "INFO" "✓ Microsoft Graph API connectivity check passed"
    else
        log "WARNING" "× Microsoft Graph API connectivity check failed"
    fi

    if curl -s -o /dev/null -w "%{http_code}" https://api.github.com | grep -q "200"; then
        log "INFO" "✓ GitHub API connectivity check passed"
    else
        log "WARNING" "× GitHub API connectivity check failed"
    fi
}

validate_queries() {
    if [ -f "./scripts/validate-queries.ps1" ] && [ -d "./queries" ]; then
        log "INFO" "Validating KQL query syntax"
        pwsh -Command {
            & "./scripts/validate-queries.ps1" -QueryDirectory "queries"
            if ($LASTEXITCODE -ne 0) {
                Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [ERROR] Query validation failed"
                exit 1
            } else {
                Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [INFO] All queries passed validation"
            }
        }
        
        if [ $? -ne 0 ]; then
            log "ERROR" "KQL query validation failed"
            return 1
        else
            log "INFO" "KQL query validation succeeded"
            return 0
        fi
    else
        log "WARNING" "Query validation skipped - missing components"
        return 0
    fi
}

cleanup_old_results() {
    local retention_days=${1:-$RETENTION_DAYS}
    
    if [ -d "$RESULTS_DIR" ]; then
        log "INFO" "Cleaning up results older than $retention_days days..."
        
        find "$RESULTS_DIR" -type f \( -name "*.csv" -o -name "*.html" -o -name "*.json" -o -name "*.sarif" \) -mtime +$retention_days -delete
        
        log "INFO" "Completed cleaning old result files"
    else
        log "WARNING" "Results directory not found: $RESULTS_DIR"
    fi
}

cleanup_old_logs() {
    local retention_days=${1:-$RETENTION_DAYS}
    
    if [ -d "$LOG_DIR" ]; then
        log "INFO" "Cleaning up logs older than $retention_days days..."
        find "$LOG_DIR" -type f -name "*.log" -mtime +$retention_days -delete
        log "INFO" "Completed cleaning old log files"
    else
        log "INFO" "Log directory not found: $LOG_DIR"
    fi
}

cleanup_system() {
    local force=${1:-false}
    local disk_usage=$(check_disk_usage)
    
    log "INFO" "Cleaning up temporary files..."
    find /tmp -type f -mtime +1 -delete 2>/dev/null || true
    
    PWSH_MODULE_SIZE=$(du -sm ~/.local/share/powershell/Modules 2>/dev/null | cut -f1 || echo "0")
    if [ "$PWSH_MODULE_SIZE" -gt "500" ]; then
        log "WARNING" "PowerShell module cache is large ($PWSH_MODULE_SIZE MB)"
        if [ "$force" = true ] || [ "$disk_usage" -gt "90" ]; then
            log "WARNING" "Cleaning PowerShell module cache"
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
    }
    
    if [ "$force" = true ] || [ "$disk_usage" -gt "85" ]; then
        log "INFO" "Cleaning system package cache..."
        sudo apt-get clean -y >/dev/null 2>&1 || log "WARNING" "Failed to clean package cache"
        
        if [ "$disk_usage" -gt "90" ]; then
            log "WARNING" "Critical disk usage detected ($disk_usage%). Performing aggressive cleanup..."
            sudo apt-get autoremove --purge -y >/dev/null 2>&1 || log "WARNING" "Failed to autoremove packages"
        fi
    fi
}

print_environment_summary() {
    local disk_usage=$(check_disk_usage)
    local pwsh_version=$(pwsh --version 2>/dev/null || echo "Not installed")
    local git_version=$(git --version | awk '{print $3}')
    
    log "INFO" "==== Environment Summary ===="
    log "INFO" "PowerShell: $pwsh_version"
    log "INFO" "Git: $git_version"
    log "INFO" "Disk Usage: $disk_usage%"
    log "INFO" "OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d '=' -f 2 | tr -d '"')"
    log "INFO" "========================="
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