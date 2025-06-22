#!/bin/bash

# Network Intrusion Detection System - Multi-Interface Monitoring
# Ubuntu Router configuration with 4 network zones
# ens33=WAN, ens37=LAN, ens38=SERVER, ens39=DMZ

# Global configurations
PCAP_DIR="pcap_files"
CSV_DIR="$(pwd)/csv_files"
LOG_DIR="logs"
SIEM_SERVER="192.168.30.10"
SIEM_PORT="5514"

# Network interface mappings
declare -A INTERFACES=(
    ["ens33"]="WAN"
    ["ens37"]="LAN" 
    ["ens38"]="SERVER"
    ["ens39"]="DMZ"
)

# Packet capture settings
CAPTURE_COUNT=50  # Reduced for better real-time performance
CAPTURE_TIMEOUT=5 # seconds
MAX_PARALLEL_JOBS=4

# Initialize directories
mkdir -p "$PCAP_DIR" "$CSV_DIR" "$LOG_DIR"

# Function to log events
log_event() {
    local message="$1"
    local severity="${2:-info}"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $message" | tee -a "$LOG_DIR/automation.log"
    
    # Forward to SIEM
    send_automation_log_to_siem "$message" "$severity"
}

# Function to test SIEM connectivity
test_siem_connection() {
    log_event "Testing SIEM server connectivity..."
    if nc -z "$SIEM_SERVER" "$SIEM_PORT" 2>/dev/null; then
        log_event "SIEM server connection successful"
        return 0
    else
        log_event "WARNING: Cannot connect to SIEM server $SIEM_SERVER:$SIEM_PORT"
        return 1
    fi
}

# Function to forward automation logs to SIEM
send_automation_log_to_siem() {
    local message="$1"
    local severity="${2:-info}"
    
    # Create structured log entry for SIEM
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S.%f')
    local log_entry=$(cat <<EOF
{
    "timestamp": "$timestamp",
    "event_type": "nids_automation",
    "severity": "$severity",
    "message": "$message",
    "sensor_id": "nids-ubuntu-automation",
    "host": "ubuntu-router-192.168.111.133",
    "version": "2.1"
}
EOF
)
    
    # Send to SIEM via UDP syslog if connection is available
    if nc -z "$SIEM_SERVER" "$SIEM_PORT" 2>/dev/null; then
        local priority=14  # facility=1, severity=6 (info)
        if [ "$severity" = "error" ]; then
            priority=11  # facility=1, severity=3 (error)
        elif [ "$severity" = "warning" ]; then
            priority=12  # facility=1, severity=4 (warning)
        fi
        
        echo "<$priority>$log_entry" | nc -u -w1 "$SIEM_SERVER" "$SIEM_PORT" 2>/dev/null
    fi
}

# Function to monitor single interface
monitor_interface() {
    local interface=$1
    local zone=${INTERFACES[$interface]}
    
    log_event "Starting monitoring on interface $interface (Zone: $zone)"
    
    while true; do
        local timestamp=$(date +%Y%m%d_%H%M%S)
        local pcap_file="$PCAP_DIR/${zone}_${timestamp}.pcap"
        local csv_file="$CSV_DIR/${zone}_${timestamp}.csv"
        
        # Check if interface exists and is up
        if ! ip link show "$interface" >/dev/null 2>&1; then
            log_event "Interface $interface not found" "error"
            sleep 10
            continue
        fi
        
        # Capture packets with timeout
        timeout "$CAPTURE_TIMEOUT" sudo tcpdump -q -i "$interface" \
            -w "$pcap_file" -c "$CAPTURE_COUNT" 2>/dev/null
        
        # Check if we captured any packets
        if [[ -f "$pcap_file" && -s "$pcap_file" ]]; then
            # Convert PCAP to CSV
            if python3 Generating_dataset.py "$pcap_file" "$csv_file" >/dev/null 2>&1; then
                # Run ML analysis with zone information
                python3 program_siem.py "$csv_file" --zone "$zone" --interface "$interface"
            else
                log_event "Failed to convert PCAP to CSV for $interface" "error"
            fi
        fi
        
        # Clean up files
        rm -f "$pcap_file" "$csv_file"
        
        # Brief pause to prevent overwhelming
        sleep 1
    done
}

# Function to cleanup background processes
cleanup() {
    log_event "Shutting down NIDS monitoring..."
    # Kill all background tcpdump and monitoring processes
    sudo pkill -f "tcpdump.*ens3"
    jobs -p | xargs -r kill
    exit 0
}

# Setup signal handlers
trap cleanup SIGINT SIGTERM

# Main execution
log_event "Starting Network Intrusion Detection System"
log_event "Monitoring interfaces: ${!INTERFACES[@]}"

# Test SIEM connection (non-blocking)
test_siem_connection

# Check for required interfaces
available_interfaces=()
for interface in "${!INTERFACES[@]}"; do
    if ip link show "$interface" >/dev/null 2>&1; then
        available_interfaces+=("$interface")
        log_event "Interface $interface (${INTERFACES[$interface]}) available"
    else
        log_event "WARNING: Interface $interface not found" "warning"
    fi
done

if [[ ${#available_interfaces[@]} -eq 0 ]]; then
    log_event "No configured interfaces found. Exiting." "error"
    exit 1
fi

# Start monitoring each available interface in background
for interface in "${available_interfaces[@]}"; do
    monitor_interface "$interface" &
    # Stagger startup to avoid resource conflicts
    sleep 2
done

log_event "All interface monitors started. Press Ctrl+C to stop."

# Wait for all background processes
wait


