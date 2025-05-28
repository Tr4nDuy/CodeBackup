#!/bin/bash

# NIDS-SIEM Integration Test Script
# Tests the complete pipeline from packet capture to SIEM integration

echo "=== NIDS-SIEM Integration Test ==="
echo "Testing Ubuntu Router (192.168.111.133) -> Windows Server (192.168.30.10)"
echo

# Configuration
SIEM_SERVER="192.168.30.10"
SIEM_PORT="5514"
TEST_DIR="test_data"
LOG_DIR="logs"

# Create test directories
mkdir -p "$TEST_DIR" "$LOG_DIR"

echo "1. Testing SIEM connectivity..."
if nc -z "$SIEM_SERVER" "$SIEM_PORT" 2>/dev/null; then
    echo "✓ SIEM server connection successful"
else
    echo "✗ Cannot connect to SIEM server $SIEM_SERVER:$SIEM_PORT"
    echo "  Make sure ELK Stack is running on Windows Server"
fi

echo
echo "2. Testing network interfaces..."
declare -A INTERFACES=(
    ["ens33"]="WAN"
    ["ens37"]="LAN" 
    ["ens38"]="SERVER"
    ["ens39"]="DMZ"
)

available_interfaces=()
for interface in "${!INTERFACES[@]}"; do
    if ip link show "$interface" >/dev/null 2>&1; then
        available_interfaces+=("$interface")
        echo "✓ Interface $interface (${INTERFACES[$interface]}) available"
    else
        echo "✗ Interface $interface not found"
    fi
done

if [[ ${#available_interfaces[@]} -eq 0 ]]; then
    echo "✗ No configured interfaces found"
    exit 1
fi

echo
echo "3. Testing ML models..."
model_dir="../Saved model"
models=(
    "kinn_model.pkl"
    "scaler.pkl"
    "label_encoder.pkl"
)

for model in "${models[@]}"; do
    if [[ -f "$model_dir/$model" ]]; then
        echo "✓ Model found: $model"
    else
        echo "✗ Missing model: $model"
    fi
done

echo
echo "4. Testing dependencies..."
dependencies=(
    "tcpdump"
    "python3"
    "nc"
)

for dep in "${dependencies[@]}"; do
    if command -v "$dep" >/dev/null 2>&1; then
        echo "✓ $dep available"
    else
        echo "✗ $dep not found"
    fi
done

echo
echo "5. Testing Python dependencies..."
python_deps=(
    "pandas"
    "numpy"
    "sklearn"
    "joblib"
)

for dep in "${python_deps[@]}"; do
    if python3 -c "import $dep" 2>/dev/null; then
        echo "✓ Python module $dep available"
    else
        echo "✗ Python module $dep not found"
    fi
done

echo
echo "6. Testing packet capture (10 second test)..."
test_interface="${available_interfaces[0]}"
if [[ -n "$test_interface" ]]; then
    test_pcap="$TEST_DIR/test_capture.pcap"
    
    echo "Capturing packets on $test_interface for 10 seconds..."
    timeout 10 sudo tcpdump -q -i "$test_interface" -w "$test_pcap" -c 50 2>/dev/null
    
    if [[ -f "$test_pcap" && -s "$test_pcap" ]]; then
        packet_count=$(tcpdump -r "$test_pcap" 2>/dev/null | wc -l)
        echo "✓ Captured $packet_count packets"
        
        # Test CSV conversion
        test_csv="$TEST_DIR/test_features.csv"
        if python3 Generating_dataset.py "$test_pcap" "$test_csv" >/dev/null 2>&1; then
            if [[ -f "$test_csv" && -s "$test_csv" ]]; then
                echo "✓ Successfully converted PCAP to CSV"
                
                # Test ML prediction
                echo "Testing ML prediction..."
                if python3 program_siem.py "$test_csv" --zone "TEST" --interface "$test_interface" --debug; then
                    echo "✓ ML prediction successful"
                else
                    echo "✗ ML prediction failed"
                fi
            else
                echo "✗ CSV conversion produced empty file"
            fi
        else
            echo "✗ Failed to convert PCAP to CSV"
        fi
        
        # Cleanup test files
        rm -f "$test_pcap" "$test_csv"
    else
        echo "✗ No packets captured (interface may be down or no traffic)"
    fi
fi

echo
echo "7. Testing SIEM log format..."
test_log_entry='{
    "timestamp": "'$(date '+%Y-%m-%d %H:%M:%S.%f')'",
    "event_type": "test_event",
    "severity": "info",
    "message": "NIDS integration test",
    "sensor_id": "nids-test",
    "host": "ubuntu-router-192.168.111.133"
}'

if nc -z "$SIEM_SERVER" "$SIEM_PORT" 2>/dev/null; then
    echo "Sending test log entry to SIEM..."
    echo "<14>$test_log_entry" | nc -u -w1 "$SIEM_SERVER" "$SIEM_PORT" 2>/dev/null
    echo "✓ Test log sent to SIEM"
else
    echo "✗ Cannot send test log to SIEM (server not reachable)"
fi

echo
echo "8. Checking log files..."
if [[ -d "$LOG_DIR" ]]; then
    echo "✓ Log directory exists"
    if [[ -f "$LOG_DIR/nids_detections.log" ]]; then
        echo "✓ NIDS detection log exists"
    else
        echo "ℹ NIDS detection log will be created on first detection"
    fi
else
    echo "ℹ Log directory will be created automatically"
fi

echo
echo "=== Test Summary ==="
echo "✓ = Working correctly"
echo "✗ = Needs attention" 
echo "ℹ = Information/Will be created automatically"
echo
echo "If all critical components show ✓, the system is ready for deployment."
echo "To start monitoring: sudo ./automation.sh"
echo
