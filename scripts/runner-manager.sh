#!/bin/bash
# Runner manager script

set -e
set -o pipefail

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
source "${SCRIPT_DIR}/runner-utils.sh"

init_log "runner-manager"

case "$1" in
    prepare)
        log "INFO" "Preparing environment for execution"
        create_directories

        disk_usage=$(check_disk_usage)

        if [ "$disk_usage" -gt "75" ]; then
            log "WARNING" "Disk usage above 75%, performing cleanup"
            "${SCRIPT_DIR}/disk-manager.sh" standard
        fi

        log "INFO" "Updating system packages"
        if ! sudo apt-get update -qq; then
            log "WARNING" "Failed to update packages, continuing anyway"
        fi

        check_powershell

        log "INFO" "Installing required PowerShell modules"
        check_powershell_modules "Microsoft.Graph.Security" "PSWriteHTML" "ImportExcel"

        if ! command -v git-lfs &> /dev/null; then
            log "INFO" "Installing Git LFS"
            sudo apt-get install -y git-lfs
            git lfs install
            log "INFO" "Git LFS installed successfully"
        else
            log "INFO" "Git LFS is already installed"
        fi

        check_connectivity

        log "INFO" "Validating MDE queries"
        validate_queries

        if git diff --name-only HEAD HEAD~1 2>/dev/null | grep -q -E '\.(kql|yml|ps1|sh)$'; then
            log "INFO" "Changes detected in project files since last commit"
        fi

        print_environment_summary
        
        log "INFO" "Preparation completed successfully"
        ;;
        
    status)
        log "INFO" "Checking system status"
        
        "${SCRIPT_DIR}/disk-manager.sh" status
        
        log "INFO" "Checking PowerShell modules"
        pwsh -Command {
            $modules = Get-Module -ListAvailable | Where-Object { 
                $_.Name -in ('Microsoft.Graph.Security', 'PSWriteHTML', 'ImportExcel') 
            } | Select-Object Name, Version
            
            $modules | ForEach-Object {
                Write-Host "[INFO] Module $($_.Name) version $($_.Version) is installed"
            }
            
            if ($modules.Count -eq 0) {
                Write-Host "[WARNING] No required modules found"
            }
        }
        
        check_connectivity
        
        print_environment_summary
        ;;
        
    cleanup)
        log "INFO" "Starting cleanup process"
        
        if [ "$2" = "force" ]; then
            log "INFO" "Forcing critical cleanup"
            "${SCRIPT_DIR}/disk-manager.sh" critical
        else
            log "INFO" "Performing standard cleanup"
            "${SCRIPT_DIR}/disk-manager.sh" standard
        fi
        
        log "INFO" "Cleanup completed"
        ;;
        
    *)
        echo "Usage: $0 {prepare|status|cleanup [force]}"
        echo ""
        echo "Commands:"
        echo "  prepare   - Prepare the environment for execution"
        echo "  status    - Check current system status"
        echo "  cleanup   - Perform cleanup operations"
        echo "    force   - Force critical cleanup"
        exit 1
        ;;
esac

exit 0