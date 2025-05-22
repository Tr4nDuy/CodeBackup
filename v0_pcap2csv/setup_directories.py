# Tạo thư mục cần thiết cho PCAP2CSV
# Script này sẽ tạo cấu trúc thư mục cần thiết cho công cụ phân tích PCAP2CSV

import os
import sys

def create_directories():
    """Tạo các thư mục cần thiết cho việc phân tích PCAP"""
    required_dirs = [
        "pcap_files",
        "split_temp",
        "output",
        "csv_files"
    ]
    
    print("Tạo thư mục cần thiết cho PCAP2CSV...")
    
    for directory in required_dirs:
        if not os.path.exists(directory):
            try:
                os.makedirs(directory)
                print(f"  ✓ Đã tạo thư mục: {directory}")
            except Exception as e:
                print(f"  ✗ Lỗi khi tạo thư mục {directory}: {e}")
        else:
            print(f"  ✓ Thư mục đã tồn tại: {directory}")
    
    print("\nCấu trúc thư mục đã sẵn sàng!")
    print("Đặt các tệp PCAP vào thư mục 'pcap_files/' và chạy script 'Generating_dataset.py'")

if __name__ == "__main__":
    create_directories()
