#!/bin/bash

# NIDS-SIEM Quick Deployment Script
# For Ubuntu Router (192.168.111.133)

set -e

echo "=============================================="
echo "NIDS-SIEM Quick Deployment Script"
echo "Ubuntu Router Configuration"
echo "=============================================="
echo

# Configuration
SIEM_SERVER="192.168.30.10"
SIEM_PORT="5514"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="$SCRIPT_DIR/deployment.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        log_error "This script should not be run as root. Please run as regular user."
        log_error "The script will prompt for sudo when needed."
        exit 1
    fi
}

# Function to install dependencies
install_dependencies() {
    log "Installing system dependencies..."
    
    sudo apt update
    
    # Install required packages
    local packages=(
        "tcpdump"
        "python3"
        "python3-pip" 
        "netcat-openbsd"
        "curl"
        "git"
    )
    
    for package in "${packages[@]}"; do
        if ! dpkg -l | grep -q "^ii  $package "; then
            log "Installing $package..."
            sudo apt install -y "$package"
        else
            log_info "$package already installed"
        fi
    done
    
    # Install Python packages
    log "Installing Python dependencies..."
    pip3 install --user pandas numpy scikit-learn joblib tqdm
    
    # Verify installations
    log "Verifying installations..."
    for cmd in tcpdump python3 nc; do
        if command_exists "$cmd"; then
            log_info "✓ $cmd available"
        else
            log_error "✗ $cmd not found"
            exit 1
        fi
    done
}

# Function to setup network interfaces
setup_network() {
    log "Checking network interfaces..."
    
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
            log_info "✓ Interface $interface (${INTERFACES[$interface]}) available"
        else
            log_warning "✗ Interface $interface not found"
        fi
    done
    
    if [[ ${#available_interfaces[@]} -eq 0 ]]; then
        log_error "No configured interfaces found. Please check network configuration."
        exit 1
    fi
    
    # Test network connectivity to SIEM
    log "Testing SIEM connectivity..."
    if nc -z "$SIEM_SERVER" "$SIEM_PORT" 2>/dev/null; then
        log_info "✓ SIEM server connection successful"
    else
        log_warning "✗ Cannot connect to SIEM server $SIEM_SERVER:$SIEM_PORT"
        log_warning "Make sure ELK Stack is running on Windows Server"
    fi
}

# Function to setup NIDS files
setup_nids_files() {
    log "Setting up NIDS files and permissions..."
    
    # Create necessary directories
    mkdir -p logs csv_files pcap_files output
    
    # Set executable permissions
    chmod +x automation.sh
    chmod +x test_nids_integration.sh
    
    # Verify model files
    log "Checking ML model files..."
    model_dir="../Saved model"
    models=(
        "kinn_model.pkl"
        "scaler.pkl" 
        "label_encoder.pkl"
    )
    
    for model in "${models[@]}"; do
        if [[ -f "$model_dir/$model" ]]; then
            log_info "✓ Model found: $model"
        else
            log_error "✗ Missing model: $model"
            exit 1
        fi
    done
}

# Function to test the system
test_system() {
    log "Running system integration test..."
    
    if [[ -f "test_nids_integration.sh" ]]; then
        chmod +x test_nids_integration.sh
        ./test_nids_integration.sh | tee -a "$LOG_FILE"
    else
        log_warning "Integration test script not found"
    fi
}

# Function to configure system optimization
optimize_system() {
    log "Applying system optimizations..."
    
    # Network buffer optimizations
    log_info "Configuring network buffers..."
    sudo sysctl -w net.core.rmem_max=134217728 2>/dev/null || true
    sudo sysctl -w net.core.netdev_max_backlog=5000 2>/dev/null || true
    
    # Add to sysctl.conf for persistence
    if ! grep -q "net.core.netdev_max_backlog" /etc/sysctl.conf 2>/dev/null; then
        echo 'net.core.netdev_max_backlog = 5000' | sudo tee -a /etc/sysctl.conf >/dev/null
        echo 'net.core.rmem_max = 134217728' | sudo tee -a /etc/sysctl.conf >/dev/null
        log_info "Network optimizations added to sysctl.conf"
    fi
    
    # Create systemd service for NIDS (optional)
    if [[ "$1" == "--create-service" ]]; then
        create_systemd_service
    fi
}

# Function to create systemd service
create_systemd_service() {
    log "Creating systemd service for NIDS..."
    
    local service_file="/etc/systemd/system/nids-monitor.service"
    local service_content="[Unit]
Description=NIDS Network Monitoring Service
After=network.target

[Service]
Type=simple
User=$(whoami)
WorkingDirectory=$SCRIPT_DIR
ExecStart=$SCRIPT_DIR/automation.sh
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target"

    echo "$service_content" | sudo tee "$service_file" >/dev/null
    sudo systemctl daemon-reload
    
    log_info "NIDS service created. Use: sudo systemctl start nids-monitor"
}

# Function to create startup script
create_startup_script() {
    log "Creating startup script..."
    
    cat > start_nids.sh << 'EOF'
#!/bin/bash

# NIDS Startup Script
cd "$(dirname "$0")"

echo "Starting NIDS Network Monitoring..."
echo "Press Ctrl+C to stop monitoring"
echo

# Start monitoring with proper logging
sudo ./automation.sh 2>&1 | tee logs/startup.log
EOF
    
    chmod +x start_nids.sh
    log_info "Startup script created: start_nids.sh"
}

# Main deployment function
main() {
    log "Starting NIDS deployment..."
    
    # Check prerequisites
    check_root
    
    # Change to script directory
    cd "$SCRIPT_DIR"
    
    # Run deployment steps
    install_dependencies
    setup_network
    setup_nids_files
    optimize_system "$@"
    create_startup_script
    
    # Run tests
    test_system
    
    log "=============================================="
    log "NIDS Deployment Completed Successfully!"
    log "=============================================="
    echo
    log_info "Next steps:"
    log_info "1. Ensure ELK Stack is running on Windows Server (192.168.30.10)"
    log_info "2. Start NIDS monitoring: sudo ./automation.sh"
    log_info "3. Or use startup script: ./start_nids.sh"
    log_info "4. Monitor logs: tail -f logs/nids_detections.log"
    log_info "5. Access Kibana dashboard: http://192.168.30.10:5601"
    echo
    log_info "Log file: $LOG_FILE"
    
    if [[ "$1" == "--create-service" ]]; then
        echo
        log_info "Systemd service created. To enable auto-start:"
        log_info "  sudo systemctl enable nids-monitor"
        log_info "  sudo systemctl start nids-monitor"
    fi
}

# Handle command line options
if [[ "$1" == "--help" || "$1" == "-h" ]]; then
    echo "NIDS-SIEM Quick Deployment Script"
    echo
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "OPTIONS:"
    echo "  --create-service    Create systemd service for auto-start"
    echo "  --help, -h         Show this help message"
    echo
    echo "This script will:"
    echo "  • Install required dependencies"
    echo "  • Configure network interfaces"
    echo "  • Setup NIDS files and permissions"
    echo "  • Optimize system settings"
    echo "  • Run integration tests"
    echo "  • Create startup scripts"
    echo
    exit 0
fi

# Run main deployment
main "$@"
