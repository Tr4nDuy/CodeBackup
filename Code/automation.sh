#!/bin/bash

PCAP_DIR="pcap_files"
CSV_DIR="$(pwd)/csv_files"
mkdir -p "$PCAP_DIR" "$CSV_DIR"

echo ">>> Bắt đầu bắt gói tin liên tục..."

# Chạy tcpdump và thu thập từng gói tin
while true; do
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    PCAP_FILE="$PCAP_DIR/capture_${TIMESTAMP}.pcap"
    CSV_FILE="$CSV_DIR/capture_${TIMESTAMP}.csv"

    # Thu thập 1 gói tin và lưu vào file .pcap
    sudo tcpdump -q -i eth0 -w "$PCAP_FILE" -c 100

    # Chuyển đổi PCAP thành CSV
    python3 Generating_dataset.py "$PCAP_FILE" "$CSV_FILE"

    # Chạy mô hình ML trên CSV
    python3 program.py "$CSV_FILE"

    # Xóa file sau khi xử lý xong
    rm -f "$PCAP_FILE" "$CSV_FILE"

done


