#!/bin/bash

# NIDS Automation Script - Single Interface Version
# Theo dõi một interface mạng, bắt gói tin và phân tích với mô hình ML

# Cấu hình
INTERFACE="ens33"          # Interface mạng cần giám sát (WAN interface)
PACKET_COUNT=100           # Số lượng gói tin bắt trong mỗi chu kỳ
RETAIN_FILES=false         # Có giữ lại các file PCAP và CSV hay không
MAX_RETAIN_COUNT=50        # Số lượng file tối đa giữ lại nếu RETAIN_FILES=true
BUFFER_SIZE="256MB"        # Buffer size cho tcpdump

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
LOG_FILE="${LOG_DIR}/automation_$(date +%Y%m%d).log"

# Hàm ghi log
log() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $message" | tee -a "$LOG_FILE"
}

# Hàm clean up khi nhận tín hiệu thoát
cleanup() {
    log "Đang dừng quá trình bắt gói tin..."
    if [ -n "$TCPDUMP_PID" ] && ps -p $TCPDUMP_PID > /dev/null; then
        kill -TERM $TCPDUMP_PID 2>/dev/null
    fi
    log "NIDS Automation đã dừng lại"
    exit 0
}

# Bắt tín hiệu thoát
trap cleanup SIGINT SIGTERM

# Hiển thị thông tin
log "=== NIDS Automation Script - Phiên bản 1.0 ==="
log "Interface: $INTERFACE"
log "Gói tin mỗi chu kỳ: $PACKET_COUNT"
log "Giữ file: $RETAIN_FILES"
log "Thư mục PCAP: $PCAP_DIR"
log "Thư mục CSV: $CSV_DIR"
log "=== Bắt đầu bắt gói tin liên tục ==="

# Kiểm tra quyền root
if [ "$(id -u)" != "0" ]; then
   log "Lỗi: Script cần được chạy với quyền root (sudo)!"
   exit 1
fi

# Kiểm tra interface tồn tại
if ! ip link show "$INTERFACE" >/dev/null 2>&1; then
    log "Lỗi: Interface '$INTERFACE' không tồn tại!"
    log "Các interface có sẵn:"
    ip -o link show | awk -F': ' '{print $2}'
    exit 1
fi

# Vòng lặp chính
CYCLE_COUNT=0
while true; do
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    PCAP_FILE="$PCAP_DIR/capture_${INTERFACE}_${TIMESTAMP}.pcap"
    CSV_FILE="$CSV_DIR/capture_${INTERFACE}_${TIMESTAMP}.csv"
    
    CYCLE_COUNT=$((CYCLE_COUNT+1))
    log "Chu kỳ #$CYCLE_COUNT: Bắt đầu thu thập gói tin trên interface $INTERFACE"
    
    # Thu thập gói tin và lưu vào file .pcap
    log "Thu thập gói tin và lưu vào: $PCAP_FILE"
    sudo tcpdump -q -i "$INTERFACE" -B "$BUFFER_SIZE" -w "$PCAP_FILE" -c "$PACKET_COUNT" &
    TCPDUMP_PID=$!
    wait $TCPDUMP_PID
    
    if [ -f "$PCAP_FILE" ] && [ -s "$PCAP_FILE" ]; then
        log "Đã thu thập xong, kích thước file: $(du -h "$PCAP_FILE" | cut -f1)"
        
        # Chuyển đổi PCAP thành CSV
        log "Chuyển đổi PCAP thành CSV: $CSV_FILE"
        # Đảm bảo thư mục split_temp và output có đủ quyền
        chmod 777 "${SCRIPT_DIR}/split_temp" "${SCRIPT_DIR}/output"
        python3 Generating_dataset.py "$PCAP_FILE" "$CSV_FILE"
        
        if [ -f "$CSV_FILE" ] && [ -s "$CSV_FILE" ]; then
            log "Đã chuyển đổi thành công, phân tích với mô hình ML"
            
            # Chạy mô hình ML trên CSV
            python3 nids_analyzer.py "$CSV_FILE"
            ML_EXIT_CODE=$?
            
            if [ $ML_EXIT_CODE -eq 0 ]; then
                log "Phân tích hoàn tất thành công"
            else
                log "Cảnh báo: Phân tích ML gặp lỗi (code: $ML_EXIT_CODE)"
            fi
        else
            log "Lỗi: Không thể chuyển đổi PCAP thành CSV hoặc file CSV rỗng"
        fi
    else
        log "Lỗi: Không thể thu thập gói tin hoặc file PCAP rỗng"
    fi
    
    # Xử lý file sau khi phân tích
    if [ "$RETAIN_FILES" = false ]; then
        rm -f "$PCAP_FILE" "$CSV_FILE"
        log "Đã xóa các file tạm: $(basename "$PCAP_FILE"), $(basename "$CSV_FILE")"
    else
        # Nếu giữ lại file, kiểm tra số lượng và xóa file cũ nếu vượt quá hạn mức
        pcap_count=$(ls -1 "$PCAP_DIR" | wc -l)
        csv_count=$(ls -1 "$CSV_DIR" | wc -l)
        
        if [ "$pcap_count" -gt "$MAX_RETAIN_COUNT" ]; then
            oldest_pcap=$(ls -t "$PCAP_DIR" | tail -1)
            rm -f "$PCAP_DIR/$oldest_pcap"
            log "Đã xóa file PCAP cũ nhất: $oldest_pcap"
        fi
        
        if [ "$csv_count" -gt "$MAX_RETAIN_COUNT" ]; then
            oldest_csv=$(ls -t "$CSV_DIR" | tail -1)
            rm -f "$CSV_DIR/$oldest_csv"
            log "Đã xóa file CSV cũ nhất: $oldest_csv"
        fi
    fi
    
    log "Chu kỳ #$CYCLE_COUNT hoàn tất"
    log "------------------------------------"
    
    # Thêm độ trễ giữa các chu kỳ để giảm tải cho CPU
    sleep 2
done


