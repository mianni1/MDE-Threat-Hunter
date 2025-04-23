#!/bin/bash
# Disk management script

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
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message"
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
}

get_disk_usage() {
    df -h / | awk 'NR==2 {print $5}' | sed 's/%//'
}

get_available_space() {
    df -h / | awk 'NR==2 {print $4}'
}

get_directory_size() {
    local dir=$1
    if [ -d "$dir" ]; then
        du -sh "$dir" | awk '{print $1}'
    else
        echo "0B"
    fi
}

cleanup_old_results() {
    local retention_days=${1:-30}
    
    log "INFO" "Cleaning up results older than $retention_days days"
    
    if [ -d "$RESULTS_DIR/daily-monitoring" ]; then
        log "INFO" "Cleaning up daily monitoring results"
        find "$RESULTS_DIR/daily-monitoring" -type f -mtime +$((retention_days / 4)) -delete 2>/dev/null || true
    fi
    
    if [ -d "$RESULTS_DIR/weekly-monitoring" ]; then
        log "INFO" "Cleaning up weekly monitoring results"
        find "$RESULTS_DIR/weekly-monitoring" -type f -mtime +$retention_days -delete 2>/dev/null || true
    fi
    
    if [ -d "$RESULTS_DIR/critical-findings" ]; then
        log "INFO" "Cleaning up critical findings older than $((retention_days * 3)) days"
        find "$RESULTS_DIR/critical-findings" -type f -mtime +$((retention_days * 3)) -delete 2>/dev/null || true
    fi
}

cleanup_old_logs() {
    local retention_days=${1:-14}
    
    log "INFO" "Cleaning up log files older than $retention_days days"
    find "$LOG_DIR" -type f -name "*.log" -mtime +$retention_days -delete 2>/dev/null || true
}

cleanup_system() {
    local force=$1
    log "INFO" "Cleaning system temporary files"
    
    find /tmp -type f -mtime +1 -delete 2>/dev/null || true
    
    if [ "$force" = "true" ] || [ -n "$GITHUB_ACTIONS" ]; then
        if command -v apt-get &> /dev/null; then
            log "INFO" "Cleaning apt cache"
            apt-get clean || true
            apt-get autoremove -y || true
        fi
        
        if [ -d "/home/ubuntu/actions-runner/_work" ]; then
            log "INFO" "Cleaning up old GitHub Action runner work folders"
            find /home/ubuntu/actions-runner/_work -mindepth 2 -maxdepth 2 -type d -mtime +3 -exec rm -rf {} \; 2>/dev/null || true
        fi
    fi
}

emergency_cleanup() {
    log "WARNING" "Performing emergency disk cleanup"
    
    for dir in $(find "$RESULTS_DIR" -mindepth 1 -maxdepth 1 -type d); do
        if [ -d "$dir" ]; then
            file_count=$(find "$dir" -type f | wc -l)
            if [ "$file_count" -gt 5 ]; then
                log "WARNING" "Keeping only 5 most recent files in $dir"
                find "$dir" -type f -printf '%T@ %p\n' | sort -n | head -n -5 | awk '{print $2}' | xargs rm -f
            fi
        fi
    done
    
    log "WARNING" "Aggressively cleaning temporary files"
    find /tmp -type f -delete 2>/dev/null || true
    
    log "WARNING" "Cleaning workspace temporary files"
    find "$WORKSPACE_DIR" -name "*.tmp" -o -name "*.temp" -o -name "*.bak" -delete 2>/dev/null || true
    
    if [ -d "/home/ubuntu/actions-runner/_work/_temp" ]; then
        log "WARNING" "Cleaning Actions temporary files"
        rm -rf /home/ubuntu/actions-runner/_work/_temp/* 2>/dev/null || true
    fi
}

manage_disk_space() {
    local force=$1
    local disk_usage=$(get_disk_usage)
    local disk_avail=$(get_available_space)
    
    log "INFO" "Current disk usage: ${disk_usage}% (Available: ${disk_avail})"
    
    if [ "$disk_usage" -gt "$CRITICAL_THRESHOLD" ] || [ "$force" = "critical" ]; then
        log "WARNING" "Disk usage exceeds critical threshold. Taking aggressive measures."
        cleanup_old_logs 7
        cleanup_old_results 14
        cleanup_system true
        emergency_cleanup
    elif [ "$disk_usage" -gt "$WARNING_THRESHOLD" ] || [ "$force" = "standard" ]; then
        log "INFO" "Disk usage exceeds warning threshold. Taking standard measures."
        cleanup_old_logs 14
        cleanup_old_results 30
        cleanup_system false
    else
        log "INFO" "Disk usage is below thresholds."
        if [ "$force" = "light" ]; then
            log "INFO" "Performing light cleanup as requested"
            cleanup_old_logs 30
            cleanup_system false
        else
            log "INFO" "No cleanup needed at this time"
        fi
    fi
    
    local disk_usage_after=$(get_disk_usage)
    log "INFO" "Disk usage after cleanup: ${disk_usage_after}% (was: ${disk_usage}%)"
    
    local space_freed=$((disk_usage - disk_usage_after))
    if [ "$space_freed" -gt 0 ]; then
        log "INFO" "Successfully freed approximately ${space_freed}% disk space"
    elif [ "$disk_usage_after" -gt "$CRITICAL_THRESHOLD" ]; then
        log "ERROR" "Disk usage still critical after cleanup! Manual intervention required."
        return 1
    fi
    
    return 0
}

case "$1" in
    status)
        disk_usage=$(get_disk_usage)
        disk_avail=$(get_available_space)
        log "INFO" "Disk status: ${disk_usage}% used (Available: ${disk_avail})"
        
        results_size=$(get_directory_size "$RESULTS_DIR")
        log_size=$(get_directory_size "$LOG_DIR")
        log "INFO" "Directory sizes: Results=${results_size}, Logs=${log_size}"
        ;;
    
    light)
        log "INFO" "Performing light cleanup"
        manage_disk_space "light"
        ;;
    
    standard)
        log "INFO" "Performing standard cleanup"
        manage_disk_space "standard"
        ;;
    
    critical)
        log "INFO" "Performing critical cleanup"
        manage_disk_space "critical"
        ;;
    
    *)
        log "INFO" "Running automatic disk space management"
        manage_disk_space "auto"
        ;;
esac

log "INFO" "Disk management completed"
exit 0