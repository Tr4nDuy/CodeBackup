#!/bin/bash

# NIDS STARTER SCRIPT
# Dùng để khởi động và quản lý dịch vụ NIDS

# Đường dẫn tới thư mục chứa script
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
AUTOMATION_SCRIPT="${SCRIPT_DIR}/automation.sh"
LOG_DIR="${SCRIPT_DIR}/logs"
PID_FILE="${SCRIPT_DIR}/nids.pid"

# Tạo thư mục log nếu chưa tồn tại
mkdir -p "$LOG_DIR"

# File log
LOG_FILE="${LOG_DIR}/nids_service_$(date +%Y%m%d).log"

# Hàm ghi log
log() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $message" | tee -a "$LOG_FILE"
}

# Kiểm tra quyền root
if [ "$(id -u)" != "0" ]; then
   log "Lỗi: Script cần được chạy với quyền root (sudo)!"
   exit 1
fi

# Kiểm tra automation script có tồn tại không
if [ ! -f "$AUTOMATION_SCRIPT" ]; then
    log "Lỗi: Không tìm thấy automation script tại '$AUTOMATION_SCRIPT'"
    exit 1
fi

# Kiểm tra automation script có quyền thực thi không
if [ ! -x "$AUTOMATION_SCRIPT" ]; then
    log "Thiết lập quyền thực thi cho automation script"
    chmod +x "$AUTOMATION_SCRIPT"
fi

# Hàm kiểm tra NIDS có đang chạy không
is_nids_running() {
    if [ -f "$PID_FILE" ]; then
        local pid=$(cat "$PID_FILE")
        if ps -p "$pid" > /dev/null; then
            return 0  # Đang chạy
        fi
    fi
    return 1  # Không chạy
}

# Hàm khởi động NIDS
start_nids() {
    if is_nids_running; then
        log "NIDS đã đang chạy với PID $(cat "$PID_FILE")"
        return 0
    fi
    
    log "Khởi động NIDS Automation..."
    nohup "$AUTOMATION_SCRIPT" >> "${LOG_DIR}/automation_output.log" 2>&1 &
    
    local pid=$!
    echo $pid > "$PID_FILE"
    
    sleep 2
    if ps -p "$pid" > /dev/null; then
        log "NIDS đã khởi động thành công với PID $pid"
        return 0
    else
        log "Lỗi: Không thể khởi động NIDS"
        rm -f "$PID_FILE"
        return 1
    fi
}

# Hàm dừng NIDS
stop_nids() {
    if ! is_nids_running; then
        log "NIDS không chạy"
        return 0
    fi
    
    local pid=$(cat "$PID_FILE")
    log "Dừng NIDS với PID $pid..."
    
    # Gửi tín hiệu SIGTERM để thoát an toàn
    kill -TERM $pid
    
    # Đợi quá trình tắt
    local count=0
    while ps -p "$pid" > /dev/null && [ $count -lt 10 ]; do
        sleep 1
        count=$((count + 1))
    done
    
    # Kiểm tra xem quá trình đã dừng chưa
    if ps -p "$pid" > /dev/null; then
        log "NIDS không phản hồi, buộc dừng..."
        kill -9 $pid
    fi
    
    rm -f "$PID_FILE"
    log "NIDS đã dừng thành công"
    return 0
}

# Hàm kiểm tra trạng thái NIDS
status_nids() {
    if is_nids_running; then
        local pid=$(cat "$PID_FILE")
        log "NIDS đang chạy với PID $pid"
        
        # Hiển thị một số thông tin hữu ích
        log "Thời gian chạy:"
        ps -o etime= -p $pid
        
        log "Sử dụng tài nguyên:"
        ps -o %cpu,%mem -p $pid
        
        log "Các file PCAP gần đây nhất:"
        ls -lt "${SCRIPT_DIR}/pcap_files" | head -5
        
        log "Log gần đây nhất:"
        tail -5 "${LOG_DIR}/automation_$(date +%Y%m%d).log"
        
        return 0
    else
        log "NIDS không chạy"
        return 1
    fi
}

# Xử lý tham số dòng lệnh
case "$1" in
    start)
        start_nids
        ;;
    stop)
        stop_nids
        ;;
    restart)
        stop_nids
        sleep 2
        start_nids
        ;;
    status)
        status_nids
        ;;
    *)
        echo "Sử dụng: $0 {start|stop|restart|status}"
        exit 1
        ;;
esac

exit 0
