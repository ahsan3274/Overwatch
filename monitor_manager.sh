#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# monitor_manager.sh - Manage FileMonitor and ProcessMonitor daemons
#
# Prevents orphaned processes and duplicate instances.
#
# Usage:
#   sudo bash monitor_manager.sh start    - Start all monitors
#   sudo bash monitor_manager.sh stop     - Stop all monitors
#   sudo bash monitor_manager.sh restart  - Restart all monitors
#   sudo bash monitor_manager.sh status   - Show running monitors
#   sudo bash monitor_manager.sh cleanup  - Kill orphaned processes
# ─────────────────────────────────────────────────────────────────────────────

set -e

QUEUE="$HOME/velociraptor-triage/event_queue.jsonl"
LOG_DIR="$HOME/velociraptor-triage"
FILEMONITOR_SCRIPT="$HOME/velociraptor-triage/run_filemonitor.sh"
PROCESSMONITOR_SCRIPT="$HOME/velociraptor-triage/run_processmonitor.sh"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

# Find all monitor-related processes
find_monitor_processes() {
    ps aux | grep -E "(FileMonitor|ProcessMonitor|run_filemonitor|run_processmonitor|python.*QUEUE)" | grep -v grep | grep -v monitor_manager
}

# Count running instances
count_filemonitor() {
    local count=$(ps aux | grep "[F]ileMonitor.app" 2>/dev/null | wc -l | tr -d ' ')
    echo "${count:-0}"
}

count_processmonitor() {
    local count=$(ps aux | grep "[P]rocessMonitor.app" 2>/dev/null | wc -l | tr -d ' ')
    echo "${count:-0}"
}

count_python_filters() {
    local count=$(ps aux | grep "python.*QUEUE" 2>/dev/null | wc -l | tr -d ' ')
    echo "${count:-0}"
}

# Kill all monitor processes
kill_all_monitors() {
    print_warning "Stopping all monitor processes..."
    
    # Kill bash wrapper scripts
    pkill -f "run_filemonitor.sh" 2>/dev/null || true
    pkill -f "run_processmonitor.sh" 2>/dev/null || true
    
    # Kill FileMonitor/ProcessMonitor apps
    pkill -9 "FileMonitor" 2>/dev/null || true
    pkill -9 "ProcessMonitor" 2>/dev/null || true
    
    # Kill python filter processes
    pkill -9 -f "python.*QUEUE" 2>/dev/null || true
    
    sleep 2
    print_status "All monitors stopped"
}

# Cleanup orphaned processes (more than 1 instance)
cleanup_orphans() {
    print_warning "Checking for orphaned processes..."
    
    local fm_count=$(count_filemonitor)
    local pm_count=$(count_processmonitor)
    local py_count=$(count_python_filters)
    
    if [ "$fm_count" -gt 1 ]; then
        print_warning "Found $fm_count FileMonitor instances (expected: 1)"
        print_warning "Killing extra FileMonitor processes..."
        ps aux | grep "[F]ileMonitor.app" | tail -n +2 | awk '{print $2}' | xargs kill -9 2>/dev/null || true
    fi
    
    if [ "$pm_count" -gt 1 ]; then
        print_warning "Found $pm_count ProcessMonitor instances (expected: 1)"
        print_warning "Killing extra ProcessMonitor processes..."
        ps aux | grep "[P]rocessMonitor.app" | tail -n +2 | awk '{print $2}' | xargs kill -9 2>/dev/null || true
    fi
    
    if [ "$py_count" -gt 2 ]; then
        print_warning "Found $py_count python filter processes (expected: 2)"
        print_warning "Killing extra python processes..."
        ps aux | grep "python.*QUEUE" | grep -v grep | tail -n +3 | awk '{print $2}' | xargs kill -9 2>/dev/null || true
    fi
    
    sleep 1
    print_status "Orphan cleanup complete"
}

# Start FileMonitor
start_filemonitor() {
    local fm_count=$(count_filemonitor)
    
    if [ "$fm_count" -gt 0 ]; then
        print_status "FileMonitor already running ($fm_count instance(s))"
        return 0
    fi
    
    print_status "Starting FileMonitor..."
    nohup sudo bash "$FILEMONITOR_SCRIPT" > "$LOG_DIR/filemonitor_stdout.log" 2> "$LOG_DIR/filemonitor_stderr.log" &
    sleep 2
    
    fm_count=$(count_filemonitor)
    if [ "$fm_count" -gt 0 ]; then
        print_status "FileMonitor started successfully"
    else
        print_error "Failed to start FileMonitor"
        return 1
    fi
}

# Start ProcessMonitor
start_processmonitor() {
    local pm_count=$(count_processmonitor)
    
    if [ "$pm_count" -gt 0 ]; then
        print_status "ProcessMonitor already running ($pm_count instance(s))"
        return 0
    fi
    
    print_status "Starting ProcessMonitor..."
    nohup sudo bash "$PROCESSMONITOR_SCRIPT" > "$LOG_DIR/processmonitor_stdout.log" 2> "$LOG_DIR/processmonitor_stderr.log" &
    sleep 2
    
    pm_count=$(count_processmonitor)
    if [ "$pm_count" -gt 0 ]; then
        print_status "ProcessMonitor started successfully"
    else
        print_error "Failed to start ProcessMonitor"
        return 1
    fi
}

# Show status
show_status() {
    echo "=== Overwatch Monitor Status ==="
    echo ""
    
    local fm_count=$(count_filemonitor)
    local pm_count=$(count_processmonitor)
    local py_count=$(count_python_filters)
    
    echo "FileMonitor:        $fm_count instance(s)"
    echo "ProcessMonitor:     $pm_count instance(s)"
    echo "Python Filters:     $py_count process(es)"
    echo ""
    
    local queue_size=0
    if [ -f "$QUEUE" ]; then
        queue_size=$(wc -l < "$QUEUE")
    fi
    echo "Event Queue:        $queue_size events"
    echo ""
    
    if [ "$fm_count" -eq 1 ] && [ "$pm_count" -eq 1 ] && [ "$py_count" -eq 2 ]; then
        print_status "All monitors running normally"
    elif [ "$fm_count" -gt 1 ] || [ "$pm_count" -gt 1 ] || [ "$py_count" -gt 2 ]; then
        print_warning "Multiple instances detected - run 'cleanup' to fix"
    else
        print_warning "Some monitors not running - run 'start' to fix"
    fi
    
    echo ""
    echo "=== Running Processes ==="
    find_monitor_processes | head -20
}

# Main command handler
case "${1:-status}" in
    start)
        cleanup_orphans
        start_filemonitor
        start_processmonitor
        echo ""
        show_status
        ;;
    stop)
        kill_all_monitors
        echo ""
        show_status
        ;;
    restart)
        kill_all_monitors
        sleep 2
        start_filemonitor
        start_processmonitor
        echo ""
        show_status
        ;;
    status)
        show_status
        ;;
    cleanup)
        cleanup_orphans
        show_status
        ;;
    *)
        echo "Usage: sudo bash $0 {start|stop|restart|status|cleanup}"
        echo ""
        echo "Commands:"
        echo "  start    - Start all monitors (with orphan cleanup)"
        echo "  stop     - Stop all monitors"
        echo "  restart  - Restart all monitors"
        echo "  status   - Show running monitors and queue size"
        echo "  cleanup  - Kill orphaned/duplicate processes"
        exit 1
        ;;
esac
