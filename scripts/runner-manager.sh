# Runner manager script

set -e
set -o pipefail

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
source "${SCRIPT_DIR}/runner-utils.sh"

init_log "runner-manager"

case "$1" in
    prepare)
        log "INFO" "Preparing runner environment"
        # Generic environment preparation
        create_directories

        disk_usage=$(check_disk_usage)

        if [ "$disk_usage" -gt "75" ]; then
            log "WARNING" "Disk usage is high. Running cleanup..."
            "${SCRIPT_DIR}/disk-manager.sh" standard
        fi

        log "INFO" "Updating package lists"
        if ! sudo apt-get update -qq; then
            log "WARNING" "Failed to update package lists"
        fi

        check_powershell

        check_powershell_modules "Microsoft.Graph.Security" "PSWriteHTML" "ImportExcel"

        if ! command -v git-lfs &> /dev/null; then
            log "INFO" "Git LFS not found. Installing Git LFS..."
            sudo apt-get install -y git-lfs
            git lfs install
            log "INFO" "Git LFS installed"
        else
            log "INFO" "Git LFS already installed"
        fi

        check_connectivity

        validate_queries

        if git diff --name-only HEAD HEAD~1 2>/dev/null | grep -q -E '\.(kql|yml|ps1|sh)$'; then
            log "INFO" "Changes detected in workflow or query files since last commit"
        fi

        print_environment_summary
        
        log "INFO" "Runner environment preparation completed successfully"
        ;;
        
    status)
        log "INFO" "Checking runner environment status"
        
        "${SCRIPT_DIR}/disk-manager.sh" status
        
        log "INFO" "Checking PowerShell modules"
        pwsh -Command {
            $modules = Get-Module -ListAvailable | Where-Object { 
                $_.Name -in ('Microsoft.Graph.Security', 'PSWriteHTML', 'ImportExcel') 
            } | Select-Object Name, Version
            
            $modules | ForEach-Object {
                Write-Host "[INFO] Module $($_.Name) version $($_.Version) is installed"
            }
        }
        
        check_connectivity
        
        print_environment_summary
        ;;
        
    cleanup)
        log "INFO" "Running environment cleanup"
        
        if [ "$2" = "force" ]; then
            "${SCRIPT_DIR}/disk-manager.sh" critical
        else
            "${SCRIPT_DIR}/disk-manager.sh" standard
        fi
        
        log "INFO" "Cleanup completed"
        ;;
        
    *)
        echo "Script usage: $0 {prepare|status|cleanup}"
        exit 1
        ;;
esac

exit 0