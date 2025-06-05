#!/bin/bash
# filepath: /home/duy/CodeBackup/Code/multi_interface_automation.sh

# NIDS Automation Script - Multi-Interface Version
# Theo dõi nhiều interface mạng cùng lúc, bắt gói tin và phân tích với mô hình ML

# Cấu hình
INTERFACES=("ens33" "ens37" "ens38" "ens39")  # Danh sách các interface cần giám sát
PACKET_COUNT=100           # Số lượng gói tin bắt trong mỗi chu kỳ mỗi interface
RETAIN_FILES=false         # Có giữ lại các file PCAP và CSV hay không
MAX_RETAIN_COUNT=50        # Số lượng file tối đa giữ lại nếu RETAIN_FILES=true
BUFFER_SIZE="256MB"        # Buffer size cho tcpdump
ANALYSIS_INTERVAL=60       # Thời gian chờ giữa các lần phân tích (giây)

# Đường dẫn
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
PCAP_DIR="${SCRIPT_DIR}/pcap_files"
CSV_DIR="${SCRIPT_DIR}/csv_files"
LOG_DIR="${SCRIPT_DIR}/logs"

# Tạo thư mục nếu chưa tồn tại
mkdir -p "$PCAP_DIR" "$CSV_DIR" "$LOG_DIR" "${SCRIPT_DIR}/split_temp" "${SCRIPT_DIR}/output"

# Đảm bảo quyền đọc/ghi cho thư mục split_temp và output
chmod 777 "${SCRIPT_DIR}/split_temp" "${SCRIPT_DIR}/output"

# File log
LOG_FILE="${LOG_DIR}/multi_interface_$(date +%Y%m%d).log"

# Các process ID của tcpdump cho từng interface
declare -A TCPDUMP_PIDS

# Hàm ghi log
log() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $message" | tee -a "$LOG_FILE"
}

# Hàm clean up khi nhận tín hiệu thoát
cleanup() {
    log "Đang dừng quá trình bắt gói tin..."
    for interface in "${!TCPDUMP_PIDS[@]}"; do
        pid=${TCPDUMP_PIDS[$interface]}
        if [ -n "$pid" ] && ps -p $pid > /dev/null; then
            log "Dừng tcpdump trên interface $interface (PID: $pid)"
            kill -TERM $pid 2>/dev/null
        fi
    done
    log "NIDS Multi-Interface Automation đã dừng lại"
    exit 0
}

# Bắt tín hiệu thoát
trap cleanup SIGINT SIGTERM

# Hiển thị thông tin
log "=== NIDS Multi-Interface Automation Script - Phiên bản 1.0 ==="
log "Interfaces: ${INTERFACES[*]}"
log "Gói tin mỗi chu kỳ mỗi interface: $PACKET_COUNT"
log "Giữ file: $RETAIN_FILES"
log "Thư mục PCAP: $PCAP_DIR"
log "Thư mục CSV: $CSV_DIR"
log "=== Bắt đầu bắt gói tin liên tục trên nhiều interface ==="

# Kiểm tra quyền root
if [ "$(id -u)" != "0" ]; then
   log "Lỗi: Script cần được chạy với quyền root (sudo)!"
   exit 1
fi

# Kiểm tra tất cả interfaces
for interface in "${INTERFACES[@]}"; do
    if ! ip link show "$interface" >/dev/null 2>&1; then
        log "Cảnh báo: Interface '$interface' không tồn tại! Sẽ bỏ qua interface này."
        # Loại bỏ interface không tồn tại
        INTERFACES=( "${INTERFACES[@]/$interface}" )
    fi
done

if [ ${#INTERFACES[@]} -eq 0 ]; then
    log "Lỗi: Không có interface nào khả dụng!"
    log "Các interface có sẵn:"
    ip -o link show | awk -F': ' '{print $2}'
    exit 1
fi

log "Các interface hoạt động: ${INTERFACES[*]}"

# Hàm bắt đầu tcpdump trên một interface
start_tcpdump() {
    local interface=$1
    local pcap_file=$2
    
    log "Bắt đầu tcpdump trên interface $interface, lưu vào: $pcap_file"
    sudo tcpdump -q -i "$interface" -B "$BUFFER_SIZE" -w "$pcap_file" -c "$PACKET_COUNT" &
    TCPDUMP_PIDS[$interface]=$!
}

# Hàm chờ tcpdump hoàn thành trên một interface
wait_for_tcpdump() {
    local interface=$1
    local pid=${TCPDUMP_PIDS[$interface]}
    
    if [ -n "$pid" ]; then
        wait $pid
        TCPDUMP_PIDS[$interface]=""
        return 0
    fi
    return 1
}

# Hàm phân tích file pcap
analyze_pcap() {
    local pcap_file=$1
    local csv_file=$2
    local interface=$3
    
    log "Chuyển đổi PCAP thành CSV cho interface $interface: $csv_file"
    # Đảm bảo thư mục split_temp và output có đủ quyền
    chmod 777 "${SCRIPT_DIR}/split_temp" "${SCRIPT_DIR}/output"
    
    if python3 "${SCRIPT_DIR}/Generating_dataset.py" "$pcap_file" "$csv_file"; then
        if [ -f "$csv_file" ] && [ -s "$csv_file" ]; then
            log "Đã chuyển đổi thành công, phân tích với mô hình ML"
            
            # Chạy mô hình ML trên CSV
            python3 "${SCRIPT_DIR}/nids_analyzer.py" "$csv_file"
            ML_EXIT_CODE=$?
            
            if [ $ML_EXIT_CODE -ne 0 ]; then
                log "Cảnh báo: Phân tích ML thất bại với exit code $ML_EXIT_CODE"
            fi
        else
            log "Lỗi: File CSV không được tạo hoặc trống"
        fi
    else
        log "Lỗi: Không thể chuyển đổi PCAP thành CSV"
    fi
    
    # Xóa file nếu không giữ lại
    if [ "$RETAIN_FILES" = false ]; then
        rm -f "$pcap_file" "$csv_file"
    fi
}

# Hàm quản lý số lượng file lưu trữ
manage_file_count() {
    local dir=$1
    local file_pattern=$2
    
    if [ "$RETAIN_FILES" = true ]; then
        # Đếm số file
        file_count=$(find "$dir" -name "$file_pattern" | wc -l)
        
        if [ "$file_count" -gt "$MAX_RETAIN_COUNT" ]; then
            log "Số lượng file vượt quá giới hạn, xóa bớt file cũ..."
            find "$dir" -name "$file_pattern" -printf "%T@ %p\n" | sort -n | head -n $(( $file_count - $MAX_RETAIN_COUNT )) | cut -d' ' -f2- | xargs rm -f
        fi
    fi
}

# Vòng lặp chính
CYCLE_COUNT=0
while true; do
    CYCLE_COUNT=$((CYCLE_COUNT+1))
    log "Chu kỳ #$CYCLE_COUNT: Bắt đầu thu thập gói tin trên ${#INTERFACES[@]} interfaces"
    
    # Bắt đầu tcpdump trên tất cả interfaces
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    for interface in "${INTERFACES[@]}"; do
        PCAP_FILE="$PCAP_DIR/capture_${interface}_${TIMESTAMP}.pcap"
        start_tcpdump "$interface" "$PCAP_FILE"
    done
    
    # Chờ tất cả tcpdump hoàn thành
    for interface in "${INTERFACES[@]}"; do
        wait_for_tcpdump "$interface"
    done
    
    # Phân tích tất cả file pcap
    for interface in "${INTERFACES[@]}"; do
        PCAP_FILE="$PCAP_DIR/capture_${interface}_${TIMESTAMP}.pcap"
        CSV_FILE="$CSV_DIR/capture_${interface}_${TIMESTAMP}.csv"
        
        if [ -f "$PCAP_FILE" ] && [ -s "$PCAP_FILE" ]; then
            log "Đã thu thập xong gói tin trên interface $interface, kích thước file: $(du -h "$PCAP_FILE" | cut -f1)"
            analyze_pcap "$PCAP_FILE" "$CSV_FILE" "$interface" &
        else
            log "Cảnh báo: File PCAP trống hoặc không tồn tại cho interface $interface"
        fi
    done
    
    # Chờ tất cả phân tích hoàn thành
    wait
    
    # Quản lý số lượng file
    if [ "$RETAIN_FILES" = true ]; then
        manage_file_count "$PCAP_DIR" "*.pcap"
        manage_file_count "$CSV_DIR" "*.csv"
    fi
    
    log "Chu kỳ #$CYCLE_COUNT hoàn thành. Chờ $ANALYSIS_INTERVAL giây trước khi bắt đầu chu kỳ mới..."
    sleep "$ANALYSIS_INTERVAL"
done
