#!/bin/bash
# filepath: /home/duy/CodeBackup/Code/start_nids.sh

# Real-Time NIDS Starter Script
# Launch the real-time NIDS system

# Current directory
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
LOG_DIR="${SCRIPT_DIR}/logs"

# Create log directory if it doesn't exist
mkdir -p "$LOG_DIR"

# Default network interface
DEFAULT_INTERFACE="ens33"

# Help message
show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo "Start the Real-Time Network Intrusion Detection System."
    echo ""
    echo "Options:"
    echo "  -i, --interface INTERFACE   Network interface to monitor (default: $DEFAULT_INTERFACE)"
    echo "  -v, --verbose               Enable verbose logging"
    echo "  -h, --help                  Display this help message and exit"
}

# Process command line arguments
INTERFACE="$DEFAULT_INTERFACE"
VERBOSE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -i|--interface)
            INTERFACE="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE="--verbose"
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo "Error: Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Check if running as root (required for packet capture)
if [ "$(id -u)" != "0" ]; then
    echo "Error: This script must be run as root to capture network traffic."
    echo "Please use: sudo $0 $*"
    exit 1
fi

# Check if Python is installed
if ! command -v python3 &>/dev/null; then
    echo "Error: Python 3 is not installed."
    exit 1
fi

echo "Starting Real-Time NIDS..."
echo "Monitoring interface: $INTERFACE"

# Run the Python script
python3 "$SCRIPT_DIR/nids_analyzer.py" --interface "$INTERFACE" $VERBOSE

# Check exit status
if [ $? -ne 0 ]; then
    echo "Error: NIDS failed to start."
    exit 1
fi

exit 0
