#!/bin/bash

# Real-time NIDS Automation Script with SIEM Integration
# Optimized for parallel processing and streaming

# Configuration
INTERFACE="eth0"  # Network interface to monitor
BATCH_SIZE=50     # Smaller batch size for real-time processing
CAPTURE_DURATION=5  # Seconds per capture cycle
OUTPUT_DIR="$(pwd)/realtime_output"
LOG_DIR="$(pwd)/logs"
MODELS_DIR="../Saved model"
CONCURRENT_JOBS=4  # Number of parallel processing jobs

# SIEM Integration
SIEM_ENABLED=true
LOGSTASH_HOST="localhost"
LOGSTASH_PORT=5514

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log_message() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "[${timestamp}] ${level}: ${message}"
    echo "[${timestamp}] ${level}: ${message}" >> "${LOG_DIR}/automation.log"
}

# Create directory structure
setup_directories() {
    log_message "${GREEN}INFO${NC}" "Setting up directory structure..."
    
    mkdir -p "${OUTPUT_DIR}"/{pcap,csv,processed}
    mkdir -p "${LOG_DIR}"
    
    # Create processing queues
    mkdir -p "${OUTPUT_DIR}/queue"/{pending,processing,completed}
    
    log_message "${GREEN}INFO${NC}" "Directory structure created"
}

# Check dependencies
check_dependencies() {
    log_message "${BLUE}INFO${NC}" "Checking dependencies..."
    
    local deps=("tshark" "python3" "csvtk")
    local missing_deps=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing_deps+=("$dep")
        fi
    done
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        log_message "${RED}ERROR${NC}" "Missing dependencies: ${missing_deps[*]}"
        log_message "${YELLOW}INFO${NC}" "Install with: sudo apt-get install tshark python3-pip csvtk"
        exit 1
    fi
    
    # Check Python packages
    if ! python3 -c "import pandas, numpy, sklearn, joblib, pickle" 2>/dev/null; then
        log_message "${RED}ERROR${NC}" "Missing Python packages"
        log_message "${YELLOW}INFO${NC}" "Install with: pip3 install pandas numpy scikit-learn joblib"
        exit 1
    fi
    
    log_message "${GREEN}INFO${NC}" "All dependencies satisfied"
}

# Test SIEM connection
test_siem_connection() {
    if [ "$SIEM_ENABLED" = true ]; then
        log_message "${BLUE}INFO${NC}" "Testing SIEM connection..."
        
        # Test Logstash TCP input
        timeout 5 bash -c "echo 'test' > /dev/tcp/${LOGSTASH_HOST}/${LOGSTASH_PORT}" 2>/dev/null
        if [ $? -eq 0 ]; then
            log_message "${GREEN}INFO${NC}" "SIEM connection successful"
        else
            log_message "${YELLOW}WARN${NC}" "SIEM connection failed, continuing without real-time forwarding"
            SIEM_ENABLED=false
        fi
    fi
}

# Enhanced packet capture with streaming
capture_packets() {
    local session_id=$1
    local pcap_file="${OUTPUT_DIR}/pcap/session_${session_id}.pcap"
    
    log_message "${BLUE}INFO${NC}" "Starting packet capture (Session: ${session_id})"
    
    # Use tshark for real-time capture with filtering
    timeout ${CAPTURE_DURATION} tshark \
        -i "${INTERFACE}" \
        -w "${pcap_file}" \
        -c ${BATCH_SIZE} \
        -f "not arp and not icmp6" \
        -q 2>/dev/null
    
    local capture_result=$?
    
    if [ -f "${pcap_file}" ] && [ -s "${pcap_file}" ]; then
        log_message "${GREEN}INFO${NC}" "Captured packets: ${pcap_file}"
        echo "${pcap_file}" >> "${OUTPUT_DIR}/queue/pending/batch_${session_id}.queue"
        return 0
    else
        log_message "${YELLOW}WARN${NC}" "No packets captured in session ${session_id}"
        return 1
    fi
}

# Optimized PCAP to CSV conversion
convert_pcap_to_csv() {
    local pcap_file=$1
    local session_id=$(basename "$pcap_file" .pcap | cut -d'_' -f2)
    local csv_file="${OUTPUT_DIR}/csv/session_${session_id}.csv"
    
    log_message "${BLUE}INFO${NC}" "Converting PCAP to CSV: ${session_id}"
    
    # Enhanced tshark command with optimized field extraction
    tshark -r "$pcap_file" -T fields \
        -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport \
        -e ip.proto -e frame.time_relative -e frame.len -e tcp.flags \
        -e ip.ttl -e tcp.window_size -e tcp.ack -e tcp.seq \
        -E header=y -E separator=, -E quote=d -E occurrence=f \
        > "$csv_file" 2>/dev/null
    
    if [ -s "$csv_file" ]; then
        # Post-process CSV for ML features
        python3 -c "
import pandas as pd
import numpy as np
import sys

try:
    df = pd.read_csv('$csv_file')
    if len(df) == 0:
        sys.exit(1)
    
    # Basic feature engineering
    df['src_port'] = df['tcp.srcport'].fillna(df['udp.srcport']).fillna(0)
    df['dst_port'] = df['tcp.dstport'].fillna(df['udp.dstport']).fillna(0)
    
    # Rename columns to match model expectations
    df = df.rename(columns={
        'ip.src': 'Src IP',
        'ip.dst': 'Dst IP', 
        'src_port': 'Src Port',
        'dst_port': 'Dst Port',
        'ip.proto': 'Protocol',
        'frame.time_relative': 'Flow Duration',
        'frame.len': 'Packet Length'
    })
    
    # Add derived features
    df['Tot Fwd Pkts'] = 1
    df['Tot Bwd Pkts'] = 0  
    df['TotLen Fwd Pkts'] = df['Packet Length']
    df['TotLen Bwd Pkts'] = 0
    df['Flow Byts/s'] = df['Packet Length'] / (df['Flow Duration'] + 0.001)
    df['Flow Pkts/s'] = 1 / (df['Flow Duration'] + 0.001)
    
    # Fill missing values
    df = df.fillna(0)
    
    # Select and reorder columns for model
    required_cols = ['Src IP', 'Dst IP', 'Src Port', 'Dst Port', 'Protocol', 
                    'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts', 
                    'TotLen Fwd Pkts', 'TotLen Bwd Pkts', 'Flow Byts/s', 'Flow Pkts/s']
    
    # Ensure all required columns exist
    for col in required_cols:
        if col not in df.columns:
            df[col] = 0
    
    df[required_cols].to_csv('$csv_file', index=False)
    print(f'Processed {len(df)} flows')
    
except Exception as e:
    print(f'Error: {e}', file=sys.stderr)
    sys.exit(1)
"
        
        if [ $? -eq 0 ]; then
            log_message "${GREEN}INFO${NC}" "CSV conversion completed: ${csv_file}"
            return 0
        else
            log_message "${RED}ERROR${NC}" "Failed to process CSV: ${csv_file}"
            return 1
        fi
    else
        log_message "${YELLOW}WARN${NC}" "Empty CSV file: ${csv_file}"
        return 1
    fi
}

# Real-time ML prediction with SIEM integration
predict_and_log() {
    local csv_file=$1
    local session_id=$(basename "$csv_file" .csv | cut -d'_' -f2)
    
    log_message "${BLUE}INFO${NC}" "Running ML prediction: ${session_id}"
    
    # Run prediction with enhanced logging
    python3 program_siem.py \
        --data "$csv_file" \
        --models "$MODELS_DIR" \
        --output "${OUTPUT_DIR}/processed/results_${session_id}.csv" 2>/dev/null
    
    local prediction_result=$?
    
    if [ $prediction_result -eq 0 ]; then
        log_message "${GREEN}INFO${NC}" "Prediction completed: ${session_id}"
        
        # Forward to SIEM if enabled
        if [ "$SIEM_ENABLED" = true ]; then
            forward_to_siem "${session_id}"
        fi
        
        return 0
    else
        log_message "${RED}ERROR${NC}" "Prediction failed: ${session_id}"
        return 1
    fi
}

# Forward detection results to SIEM
forward_to_siem() {
    local session_id=$1
    local log_file="${LOG_DIR}/nids_detections.log"
    
    if [ -f "$log_file" ]; then
        # Send recent log entries to Logstash
        tail -n 20 "$log_file" | while read -r log_line; do
            if [[ "$log_line" =~ ^\{.*\}$ ]]; then  # JSON format check
                echo "$log_line" | nc -w 1 "$LOGSTASH_HOST" "$LOGSTASH_PORT" 2>/dev/null || true
            fi
        done
        
        log_message "${GREEN}INFO${NC}" "Forwarded to SIEM: ${session_id}"
    fi
}

# Background processor for queued items
process_queue() {
    while true; do
        local queue_file=$(find "${OUTPUT_DIR}/queue/pending" -name "*.queue" -type f | head -1)
        
        if [ -n "$queue_file" ]; then
            local batch_id=$(basename "$queue_file" .queue)
            
            # Move to processing
            mv "$queue_file" "${OUTPUT_DIR}/queue/processing/"
            
            # Process each file in the batch
            while read -r pcap_file; do
                if [ -f "$pcap_file" ]; then
                    local csv_file="${pcap_file/pcap/csv}"
                    csv_file="${csv_file/.pcap/.csv}"
                    
                    # Convert and predict
                    if convert_pcap_to_csv "$pcap_file"; then
                        predict_and_log "$csv_file"
                    fi
                    
                    # Cleanup old files
                    rm -f "$pcap_file"
                fi
            done < "${OUTPUT_DIR}/queue/processing/${batch_id}.queue"
            
            # Move to completed
            mv "${OUTPUT_DIR}/queue/processing/${batch_id}.queue" "${OUTPUT_DIR}/queue/completed/"
        else
            sleep 1
        fi
    done
}

# Statistics and monitoring
monitor_system() {
    local stats_file="${LOG_DIR}/system_stats.log"
    
    while true; do
        local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
        local pending_count=$(find "${OUTPUT_DIR}/queue/pending" -name "*.queue" | wc -l)
        local processing_count=$(find "${OUTPUT_DIR}/queue/processing" -name "*.queue" | wc -l)
        local memory_usage=$(free -m | awk 'NR==2{printf "%.1f%%", $3*100/$2}')
        local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | awk -F'%' '{print $1}')
        
        echo "${timestamp},${pending_count},${processing_count},${memory_usage},${cpu_usage}%" >> "$stats_file"
        
        log_message "${BLUE}INFO${NC}" "Queue: Pending=${pending_count}, Processing=${processing_count}, CPU=${cpu_usage}%, MEM=${memory_usage}"
        
        sleep 30
    done
}

# Cleanup function
cleanup() {
    log_message "${YELLOW}INFO${NC}" "Shutting down NIDS automation..."
    
    # Kill background processes
    jobs -p | xargs -r kill 2>/dev/null
    
    # Archive logs
    if [ -d "$LOG_DIR" ]; then
        tar -czf "${LOG_DIR}/archive_$(date +%Y%m%d_%H%M%S).tar.gz" "${LOG_DIR}"/*.log 2>/dev/null || true
    fi
    
    log_message "${GREEN}INFO${NC}" "Cleanup completed"
    exit 0
}

# Signal handlers
trap cleanup SIGINT SIGTERM EXIT

# Main execution
main() {
    log_message "${GREEN}INFO${NC}" "Starting Real-time NIDS with SIEM Integration"
    log_message "${BLUE}INFO${NC}" "Interface: ${INTERFACE}, Batch Size: ${BATCH_SIZE}, Concurrent Jobs: ${CONCURRENT_JOBS}"
    
    # Setup
    setup_directories
    check_dependencies
    test_siem_connection
    
    # Start background processors
    for i in $(seq 1 $CONCURRENT_JOBS); do
        process_queue &
        log_message "${GREEN}INFO${NC}" "Started processor ${i} (PID: $!)"
    done
    
    # Start system monitor
    monitor_system &
    local monitor_pid=$!
    log_message "${GREEN}INFO${NC}" "Started system monitor (PID: ${monitor_pid})"
    
    # Main capture loop
    local session_counter=1
    
    while true; do
        if capture_packets "$session_counter"; then
            ((session_counter++))
        fi
        
        sleep 1  # Small delay between captures
        
        # Cleanup old files every 100 sessions
        if [ $((session_counter % 100)) -eq 0 ]; then
            find "${OUTPUT_DIR}/processed" -name "*.csv" -mtime +1 -delete 2>/dev/null || true
            find "${OUTPUT_DIR}/queue/completed" -name "*.queue" -mtime +1 -delete 2>/dev/null || true
            log_message "${BLUE}INFO${NC}" "Cleaned up old files"
        fi
    done
}

# Start main function
main "$@"
