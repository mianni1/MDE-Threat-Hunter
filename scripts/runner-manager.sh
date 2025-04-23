# Runner manager script

set -e
set -o pipefail

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
source "${SCRIPT_DIR}/runner-utils.sh"

init_log "runner-manager"

case "$1" in
    prepare)
        log "INFO"
        # Generic environment preparation
        create_directories

        disk_usage=$(check_disk_usage)

        if [ "$disk_usage" -gt "75" ]; then
            log "WARNING"
            "${SCRIPT_DIR}/disk-manager.sh" standard
        fi

        log "INFO"
        if ! sudo apt-get update -qq; then
            log "WARNING"
        fi

        check_powershell

        check_powershell_modules "Microsoft.Graph.Security" "PSWriteHTML" "ImportExcel"

        if ! command -v git-lfs &> /dev/null; then
            log "INFO"
            sudo apt-get install -y git-lfs
            git lfs install
            log "INFO"
        else
            log "INFO"
        fi

        check_connectivity

        validate_queries

        if git diff --name-only HEAD HEAD~1 2>/dev/null | grep -q -E '\.(kql|yml|ps1|sh)$'; then
            log "INFO"
        fi

        print_environment_summary
        
        log "INFO"
        ;;
        
    status)
        log "INFO"
        
        "${SCRIPT_DIR}/disk-manager.sh" status
        
        log "INFO"
        pwsh -Command {
            $modules = Get-Module -ListAvailable | Where-Object { 
                $_.Name -in ('Microsoft.Graph.Security', 'PSWriteHTML', 'ImportExcel') 
            } | Select-Object Name, Version
            
            $modules | ForEach-Object {
                Write-Host "[INFO] Operation completed."
            }
        }
        
        check_connectivity
        
        print_environment_summary
        ;;
        
    cleanup)
        log "INFO"
        
        if [ "$2" = "force" ]; then
            "${SCRIPT_DIR}/disk-manager.sh" critical
        else
            "${SCRIPT_DIR}/disk-manager.sh" standard
        fi
        
        log "INFO"
        ;;
        
    *)
        echo "Usage: $0 {prepare|status|cleanup}"
        exit 1
        ;;
esac

exit 0