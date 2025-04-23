#!/bin/bash

set -e
set -o pipefail

WORKSPACE_DIR="$(pwd)"
RESULTS_DIR="${WORKSPACE_DIR}/results"
LOG_DIR="${WORKSPACE_DIR}/logs"
LOG_FILE="${LOG_DIR}/disk-management-$(date +%Y%m%d-%H%M%S).log"
WARNING_THRESHOLD=80
CRITICAL_THRESHOLD=90

mkdir -p "$LOG_DIR"

log() {
    local level=$1
    local message=${2:-"Operation completed"}
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [${level}] ${message}" | tee -a "$LOG_FILE"
}

get_disk_usage() {
    if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
        # Windows with Git Bash or similar
        echo 50  # Default value for testing on Windows
    else
        # Linux/Unix
        df -h / | awk 'NR==2 {print $5}' | sed 's/%//'
    fi
}

get_available_space() {
    if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
        # Windows with Git Bash or similar
        echo "1G"  # Default value for testing on Windows
    else
        # Linux/Unix
        df -h / | awk 'NR==2 {print $4}'
    fi
}

get_directory_size() {
    local dir=$1
    if [ -d "$dir" ]; then
        if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
            # Windows with Git Bash or similar
            echo "$(du -sh "$dir" 2>/dev/null | cut -f1)"
        else
            # Linux/Unix
            echo "$(du -sh "$dir" 2>/dev/null | cut -f1)"
        fi
    else
        echo "0B"
    fi
}

cleanup_old_results() {
    local retention_days=${1:-30}
    
    log "INFO" "Cleaning up old results (retention: $retention_days days)"
    
    if [ -d "$RESULTS_DIR/daily-monitoring" ]; then
        log "INFO" "Processing daily-monitoring directory"
        find "$RESULTS_DIR/daily-monitoring" -type f -mtime +$((retention_days / 4)) -delete 2>/dev/null || true
    fi
    
    if [ -d "$RESULTS_DIR/weekly-monitoring" ]; then
        log "INFO" "Processing weekly-monitoring directory"
        find "$RESULTS_DIR/weekly-monitoring" -type f -mtime +$retention_days -delete 2>/dev/null || true
    fi
    
    if [ -d "$RESULTS_DIR/critical-findings" ]; then
        log "INFO" "Processing critical-findings directory"
        find "$RESULTS_DIR/critical-findings" -type f -mtime +$((retention_days * 3)) -delete 2>/dev/null || true
    fi
}

cleanup_old_logs() {
    local retention_days=${1:-14}
    
    log "INFO" "Cleaning up old logs (retention: $retention_days days)"
    find "$LOG_DIR" -type f -name "*.log" -mtime +$retention_days -delete 2>/dev/null || true
}

cleanup_system() {
    local force=$1
    log "INFO" "Performing system cleanup (force=$force)"
    
    find /tmp -type f -mtime +1 -delete 2>/dev/null || true
    
    if [ "$force" = "true" ] || [ -n "$GITHUB_ACTIONS" ]; then
        if command -v apt-get &> /dev/null; then
            log "INFO" "Cleaning apt cache"
            apt-get clean || true
            apt-get autoremove -y || true
        fi
        
        if [ -d "/home/ubuntu/actions-runner/_work" ]; then
            log "INFO" "Cleaning GitHub Actions runner cache"
            find /home/ubuntu/actions-runner/_work -mindepth 2 -maxdepth 2 -type d -mtime +3 -exec rm -rf {} \; 2>/dev/null || true
        fi
    fi
}

emergency_cleanup() {
    log "WARNING" "Performing emergency cleanup due to critical disk usage"
    
    for dir in $(find "$RESULTS_DIR" -mindepth 1 -maxdepth 1 -type d); do
        if [ -d "$dir" ]; then
            file_count=$(find "$dir" -type f | wc -l)
            if [ "$file_count" -gt 5 ]; then
                log "WARNING" "Cleaning directory with excessive files: $dir"
                find "$dir" -type f -printf '%T@ %p\n' | sort -n | head -n -5 | awk '{print $2}' | xargs rm -f
            fi
        fi
    done
    
    log "WARNING" "Cleaning temporary files"
    find /tmp -type f -delete 2>/dev/null || true
    
    log "WARNING" "Cleaning backup and temporary files"
    find "$WORKSPACE_DIR" -name "*.tmp" -o -name "*.temp" -o -name "*.bak" -delete 2>/dev/null || true
    
    if [ -d "/home/ubuntu/actions-runner/_work/_temp" ]; then
        log "WARNING" "Cleaning GitHub Actions temp directory"
        rm -rf /home/ubuntu/actions-runner/_work/_temp/* 2>/dev/null || true
    fi
}

manage_disk_space() {
    local force=$1
    local disk_usage=$(get_disk_usage)
    local disk_avail=$(get_available_space)
    
    log "INFO" "Managing disk space (usage: $disk_usage%, available: $disk_avail)"
    
    if [ "$disk_usage" -gt "$CRITICAL_THRESHOLD" ] || [ "$force" = "critical" ]; then
        log "WARNING" "Critical disk usage detected, performing emergency cleanup"
        cleanup_old_logs 7
        cleanup_old_results 14
        cleanup_system true
        emergency_cleanup
    elif [ "$disk_usage" -gt "$WARNING_THRESHOLD" ] || [ "$force" = "standard" ]; then
        log "INFO" "Warning disk usage detected, performing standard cleanup"
        cleanup_old_logs 14
        cleanup_old_results 30
        cleanup_system false
    else
        log "INFO" "Disk usage is within acceptable limits"
        if [ "$force" = "light" ]; then
            log "INFO" "Performing light cleanup"
            cleanup_old_logs 30
            cleanup_system false
        else
            log "INFO" "No cleanup required"
        fi
    fi
    
    local disk_usage_after=$(get_disk_usage)
    log "INFO" "Disk usage after cleanup: $disk_usage_after%"
    
    local space_freed=$((disk_usage - disk_usage_after))
    if [ "$space_freed" -gt 0 ]; then
        log "INFO" "Freed up $space_freed% of disk space"
    elif [ "$disk_usage_after" -gt "$CRITICAL_THRESHOLD" ]; then
        log "ERROR" "Disk usage remains critical after cleanup"
        return 1
    fi
    
    return 0
}

case "$1" in
    status)
        disk_usage=$(get_disk_usage)
        disk_avail=$(get_available_space)
        log "INFO" "Disk usage: $disk_usage%, Available space: $disk_avail"
        
        results_size=$(get_directory_size "$RESULTS_DIR")
        log_size=$(get_directory_size "$LOG_DIR")
        log "INFO" "Results directory size: $results_size, Logs directory size: $log_size"
        ;;
    
    light)
        log "INFO" "Initiating light cleanup"
        manage_disk_space "light"
        ;;
    
    standard)
        log "INFO" "Initiating standard cleanup"
        manage_disk_space "standard"
        ;;
    
    critical)
        log "INFO" "Initiating critical cleanup"
        manage_disk_space "critical"
        ;;
    
    *)
        log "INFO" "Initiating automatic cleanup"
        manage_disk_space "auto"
        ;;
esac

log "INFO" "Disk management script completed"
exit 0