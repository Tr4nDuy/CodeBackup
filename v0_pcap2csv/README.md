# Tài liệu hướng dẫn - PCAP2CSV

## Giới thiệu

Thư viện PCAP2CSV là một công cụ phân tích gói tin mạng chuyên dụng, dùng để trích xuất các đặc trưng từ các tệp PCAP và lưu chúng vào các tệp CSV để phân tích sau này.

## Cấu trúc thư viện

### 1. Feature_extraction.py

File chính để trích xuất đặc trưng từ tệp PCAP. Lớp `Feature_extraction` chứa các phương thức để phân tích gói tin và trích xuất các đặc trưng.

Các phương thức chính:

- `initialize_data_structures()`: Khởi tạo các cấu trúc dữ liệu cần thiết
- `process_tcp_packet()`: Xử lý gói tin TCP
- `process_udp_packet()`: Xử lý gói tin UDP
- `process_ip_flow()`: Xử lý luồng IP
- `prepare_row_data()`: Chuẩn bị dữ liệu cho một hàng CSV
- `pcap_evaluation()`: Hàm chính để đánh giá tệp PCAP và trích xuất đặc trưng

### 2. Connectivity_features.py

Chứa các lớp để trích xuất đặc trưng liên quan đến kết nối:

- `Connectivity_features_basic`: Trích xuất thông tin cơ bản (IP, Port)
- `Connectivity_features_time`: Trích xuất thông tin liên quan đến thời gian
- `Connectivity_features_flags_bytes`: Trích xuất thông tin cờ và byte

Lưu ý: Phương thức `ttl()` trả về giá trị TTL (Time-to-Live), không phải thời gian kéo dài của gói tin.

### 3. Dynamic_features.py

Chứa các phương thức để tính toán các đặc trưng động:

- `dynamic_calculation()`: Tính các thống kê cơ bản (tổng, min, max, trung bình, độ lệch chuẩn)
- `dynamic_two_streams()`: Tính các đặc trưng dựa trên hai luồng gói tin (vào/ra)

### 4. Layered_features.py

Chứa các lớp để trích xuất đặc trưng theo các lớp mạng:

- `L1`: Đặc trưng lớp vật lý
- `L2`: Đặc trưng lớp liên kết dữ liệu (DHCP)
- `L3`: Đặc trưng lớp mạng (TCP, UDP)
- `L4`: Đặc trưng lớp giao vận (HTTP, HTTPS, DNS, SMTP, SSH, ...)

### 5. Supporting_functions.py

Chứa các hàm hỗ trợ:

- `get_protocol_name()`: Lấy tên giao thức từ giá trị số
- `get_flow_info()`: Tính thông tin của flow
- `get_flag_values()`: Lấy giá trị của các cờ TCP
- `compare_flow_flags()`: So sánh các cờ TCP trong flow

## Cách sử dụng

```python
from Feature_extraction import Feature_extraction

# Khởi tạo đối tượng
fe = Feature_extraction()

# Phân tích tệp PCAP và tạo tệp CSV
fe.pcap_evaluation("input.pcap", "output")
```

## Xử lý ngoại lệ

Thư viện xử lý nhiều loại ngoại lệ để đảm bảo không bị crash khi gặp gói tin không hợp lệ:

- Xử lý gói tin không phải Ethernet
- Xử lý lỗi khi trích xuất địa chỉ MAC
- Xử lý trường hợp tính toán phức tạp gặp lỗi
- Kiểm tra đầu vào trước khi tính toán để tránh chia cho 0

## Hiệu suất

- Xử lý từng batch gói tin để tối ưu bộ nhớ
- Giải phóng bộ nhớ sau mỗi batch để tránh tràn bộ nhớ
- Ghi log tiến trình sau mỗi 10,000 gói tin
