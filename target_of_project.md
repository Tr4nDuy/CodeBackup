# Dự án: Hệ thống phát hiện xâm nhập mạng (NIDS) tích hợp SIEM

## Mục tiêu chính
Xây dựng một hệ thống NIDS (Network Intrusion Detection System) để phát hiện các cuộc tấn công mạng, đặc biệt là tấn công scanning/portscan. Hệ thống cần hoạt động theo thời gian thực (real-time) và tích hợp với SIEM (ELK Stack) để hiển thị kết quả phát hiện trên dashboard.

## Kiến trúc hệ thống
- **NIDS Sensor**: Triển khai trên router Ubuntu (192.168.111.133)
- **SIEM Platform**: Triển khai trên Windows Server (192.168.30.10)
- **Vùng mạng giám sát**: WAN (ens33), LAN (ens37), SERVER (ens38), DMZ (ens39)

## Phương pháp tiếp cận
1. **Thu thập dữ liệu**: Capture packet từ nhiều interface sử dụng tcpdump
2. **Trích xuất đặc trưng**: Phân tích packet để tạo feature vectors
3. **Phát hiện bất thường**: Sử dụng mô hình kINN để phát hiện tấn công
4. **Tích hợp SIEM**: Gửi kết quả phát hiện đến ELK Stack để hiển thị

## Yêu cầu kỹ thuật
1. **Packet Capture**
   - Thu thập packet từ nhiều network interface (WAN, LAN, SERVER, DMZ)
   - Hỗ trợ nhiều loại protocol (TCP, UDP, ICMP, ARP)
   - Hoạt động liên tục và hiệu quả

2. **Feature Extraction**
   - Trích xuất đặc trưng mạng từ packet header và payload
   - Phân tích flow và connection patterns
   - Tạo feature vectors cho mô hình ML

3. **ML Detection**
   - Phát hiện tấn công scanning/portscan theo thời gian thực
   - Phân loại traffic thành các nhóm (normal, suspicious, attack)
   - Đánh giá mức độ nguy hiểm dựa trên zone

4. **SIEM Integration**
   - Gửi kết quả phân tích đến ELK Stack
   - Hiển thị visualizations trên Kibana dashboard
   - Hỗ trợ tìm kiếm và phân tích theo thời gian

## Môi trường triển khai

### 1. NIDS Sensor (Ubuntu Router)
- **OS**: Ubuntu Server 22.04 (Kernel 5.15.0-130)
- **Hardware**: VM (2 CPUs, 4GB RAM)
- **Network Interfaces**:
  - `ens33`: 192.168.111.133/24 (WAN Zone)
  - `ens37`: 192.168.20.1/24 (LAN Zone)
  - `ens38`: 192.168.30.1/24 (SERVER Zone)
  - `ens39`: 192.168.40.1/24 (DMZ Zone)
- **Software Stack**:
  - Python 3.10.12
  - tcpdump (packet capture)
  - scikit-learn, pandas (ML processing)

### 2. SIEM Server (Windows)
- **OS**: Windows Server 2019 Standard (Build 17763)
- **Hardware**: VM (2 CPUs, 4GB RAM)
- **Network**: 192.168.30.10 (SERVER Zone)
- **Software Stack**:
  - Elasticsearch 8.11.0 (Port 9200)
  - Logstash 8.11.0 (Port 5514)
  - Kibana 8.11.0 (Port 5601)


## Network Topology
```
┌─────────────────────────────────────────────────┐
│               Internet                          │
└──────────────────────┬──────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────┐
│                 WAN Interface                   │
│                 (192.168.111.133)               │
│                                                 │
│  ┌─────────────────────────────────────────┐    │
│  │            NIDS Router                  │    │
│  │                                         │    │
│  │  ┌─────────────┐  ┌─────────────────┐   │    │
│  │  │  LAN Zone   │  │   SERVER Zone   │   │    │
│  │  │ 192.168.20.1│  │  192.168.30.1   │   │    │
│  │  └──────┬──────┘  └────────┬────────┘   │    │
│  │         │                  │            │    │
│  │         │         ┌────────▼────────┐   │    │
│  │         │         │    ELK Server   │   │    │
│  │         │         │  192.168.30.10  │   │    │
│  │         │         └─────────────────┘   │    │
│  │         │                               │    │
│  │  ┌──────▼──────┐  ┌─────────────────┐   │    │
│  │  │ Client PCs  │  │    DMZ Zone     │   │    │
│  │  │192.168.20.x │  │  192.168.40.1   │   │    │
│  │  └─────────────┘  └─────────────────┘   │    │
│  │                                         │    │
│  └─────────────────────────────────────────┘    │
│                                                 │
└─────────────────────────────────────────────────┘
```

## Kế hoạch triển khai

### Phase 1: Thiết lập môi trường (đã thực hiện)
1. Cài đặt Ubuntu Server và cấu hình network interfaces 
2. Cài đặt Windows Server và triển khai ELK stack 
3. Cấu hình firewall và kết nối mạng giữa các zone 

### Phase 2: Triển khai NIDS
1. Cài đặt dependencies và Python packages 
2. Cấu hình packet capture trên multiple interfaces 
3. Triển khai feature extraction từ packet data 
4. Huấn luyện và tối ưu mô hình ML kINN 

### Phase 3: Tích hợp SIEM
1. Cấu hình Logstash pipeline cho log ingestion
2. Thiết lập Elasticsearch indices và mappings
3. Phát triển Kibana dashboards và visualizations
4. Kiểm thử end-to-end integration

### Phase 4: Kiểm tra và Đánh giá
1. Thực hiện các kịch bản tấn công controlled
2. Đánh giá accuracy, false positive/negative rates
3. Tối ưu performance và resource usage
4. Triển khai monitoring cho overall system health

## Phương pháp làm việc
- Tiếp cận step-by-step, từng bước xác nhận kết quả trước khi tiến hành bước tiếp theo
- Sửa lỗi khi phát hiện và kiểm thử lại trước khi tiếp tục
<!-- - Triển khai đầy đủ tài liệu và logging để thuận tiện cho việc troubleshooting -->