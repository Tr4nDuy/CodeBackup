# Cấu trúc thư mục PCAP2CSV

Để công cụ phân tích hoạt động chính xác, cần có cấu trúc thư mục sau:

```
v0_pcap2csv/
├── Communication_features.py    # Xử lý các đặc trưng giao tiếp
├── Connectivity_features.py     # Xử lý các đặc trưng kết nối
├── Dynamic_features.py          # Xử lý các đặc trưng động
├── Feature_extraction.py        # Module chính trích xuất đặc trưng
├── Generating_dataset.py        # Script chính để xử lý các file PCAP
├── IMPROVEMENTS.md              # Mô tả các cải tiến đã thực hiện
├── Layered_features.py          # Xử lý các đặc trưng theo lớp mạng
├── README.md                    # Tài liệu hướng dẫn chính
├── Supporting_functions.py      # Các hàm hỗ trợ
│
├── csv_files/                   # Thư mục chứa kết quả cuối cùng (CSV)
│   └── <tên_file.csv>           # Mỗi file PCAP sẽ tạo một file CSV tương ứng
│
├── output/                      # Thư mục chứa kết quả tạm thời
│   └── <temp_files.csv>         # Các file tạm sẽ được xóa sau khi xử lý xong
│
├── pcap_files/                  # Thư mục chứa các file PCAP đầu vào
│   └── <tên_file.pcap>          # Các file PCAP cần phân tích
│
└── split_temp/                  # Thư mục chứa các file PCAP đã chia nhỏ
    └── <split_temp...>          # Các file PCAP tạm thời
```

## Tạo cấu trúc thư mục

Bạn có thể tạo cấu trúc thư mục cần thiết bằng lệnh sau:

### Trên Linux/Mac

```bash
mkdir -p csv_files output pcap_files split_temp
```

### Trên Windows

```powershell
mkdir csv_files, output, pcap_files, split_temp -Force
```

## Cách sử dụng

1. Đặt các file PCAP cần phân tích vào thư mục `pcap_files/`
2. Chạy script `Generating_dataset.py`
3. Kết quả sẽ được lưu trong thư mục `csv_files/`

Xem thêm chi tiết trong file [GENERATING_DATASET_GUIDE.md](GENERATING_DATASET_GUIDE.md).
