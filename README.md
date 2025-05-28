# NIDS-SIEM Integration System

## Hệ thống phát hiện xâm nhập mạng tích hợp SIEM

### Mô tả tổng quan
Hệ thống NIDS (Network Intrusion Detection System) với khả năng phát hiện tấn công scanning/portscan theo thời gian thực, tích hợp với SIEM (Security Information and Event Management) để giám sát và phân tích bảo mật toàn diện.

### Kiến trúc hệ thống

```
┌─────────────────────────────────────────────────────────────┐
│                    Ubuntu Router                            │
│                  (192.168.111.133)                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │   ens33     │  │   ens37     │  │     ens38/ens39     │  │
│  │    WAN      │  │    LAN      │  │   SERVER/DMZ        │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
│           │              │                    │             │
│           └──────────────┴────────────────────┘             │
│                          │                                  │
│        ┌─────────────────▼─────────────────┐                │
│        │        NIDS Sensor                │                │
│        │  • Packet Capture (tcpdump)       │                │
│        │  • Feature Extraction             │                │
│        │  • ML Detection (kINN)            │                │
│        │  • JSON Logging                   │                │
│        └─────────────────┬─────────────────┘                │
└──────────────────────────┼──────────────────────────────────┘
                           │ TCP:5514 (Syslog)
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                 Windows Server                              │
│                  (192.168.30.10)                            │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │Elasticsearch│  │  Logstash   │  │      Kibana         │  │
│  │   :9200     │  │   :5514     │  │       :5601         │  │
│  │             │  │             │  │                     │  │
│  │ • Indexing  │  │ • Log Parse │  │ • Dashboard         │  │
│  │ • Storage   │  │ • Transform │  │ • Visualization     │  │
│  │ • Search    │  │ • Enrichment│  │ • Alerting          │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Thành phần hệ thống

#### 1. Ubuntu Router (NIDS Sensor)
- **Chức năng**: Capture packet, phân tích ML, gửi log đến SIEM
- **Interfaces**: 
  - `ens33` → WAN Zone
  - `ens37` → LAN Zone  
  - `ens38` → SERVER Zone
  - `ens39` → DMZ Zone
- **Components**:
  - `automation.sh`: Multi-interface monitoring script
  - `program_siem.py`: Enhanced ML detection với JSON logging
  - `Generating_dataset.py`: PCAP to CSV conversion
  - Models: kINN classifier, scaler, label encoder

#### 2. Windows Server (SIEM)
- **Chức năng**: Thu thập, phân tích, hiển thị security events
- **Components**:
  - **Elasticsearch** (Port 9200): Storage và indexing
  - **Logstash** (Port 5514): Log parsing và transformation
  - **Kibana** (Port 5601): Dashboard và visualization

### Cài đặt và triển khai

#### Bước 1: Chuẩn bị Ubuntu Router

```bash
# 1. Clone repository
cd /home/user
git clone <repository-url>
cd CodeBackup/Code

# 2. Cài đặt dependencies
sudo apt update
sudo apt install tcpdump python3 python3-pip netcat-openbsd

# 3. Cài đặt Python packages
pip3 install pandas numpy scikit-learn joblib tqdm

# 4. Set permissions
chmod +x automation.sh
chmod +x test_nids_integration.sh

# 5. Test hệ thống
./test_nids_integration.sh
```

#### Bước 2: Cài đặt SIEM trên Windows Server

```powershell
# Mở PowerShell với quyền Administrator
cd C:\Users\ADMIN\Desktop\CodeBackup\siem_setup

# 1. Cài đặt ELK Stack
.\start_siem.ps1 -Install

# 2. Khởi động services
.\start_siem.ps1 -Start -ConfigureKibana

# 3. Kiểm tra status
.\start_siem.ps1 -Status
```

#### Bước 3: Kiểm tra kết nối

```bash
# Trên Ubuntu Router - Test SIEM connectivity
nc -z 192.168.30.10 5514
# Nếu thành công sẽ không có output, return code = 0

# Test gửi log thử nghiệm
echo '<14>{"test": "connection", "timestamp": "'$(date)'"}' | nc -u 192.168.30.10 5514
```

#### Bước 4: Khởi động NIDS Monitoring

```bash
# Trên Ubuntu Router
cd /home/user/CodeBackup/Code
sudo ./automation.sh
```

### Sử dụng hệ thống

#### NIDS Monitoring
```bash
# Khởi động monitoring tất cả interfaces
sudo ./automation.sh

# Log files được tạo tại:
# - logs/automation.log: System logs
# - logs/nids_detections.log: JSON detection logs  
# - logs/nids_debug.log: Debug information
```

#### SIEM Management
```powershell
# Khởi động SIEM
.\start_siem.ps1 -Start

# Dừng SIEM  
.\start_siem.ps1 -Stop

# Kiểm tra status
.\start_siem.ps1 -Status

# Cấu hình Kibana
.\start_siem.ps1 -ConfigureKibana
```

#### Truy cập Dashboard
- **Kibana Dashboard**: http://192.168.30.10:5601
- **Elasticsearch API**: http://192.168.30.10:9200
- **Index Pattern**: `nids-logs-*`

### Cấu hình nâng cao

#### 1. Tuning Detection Sensitivity
Chỉnh sửa file `program_siem.py`:
```python
# Tại class kINN
self.k = 3              # Số neighbors (tăng để giảm false positive)
self.kernel = "poly"    # Kernel type: poly, rbf, linear
```

#### 2. Custom Alert Rules
Chỉnh sửa file `siem_setup/nids-pipeline.conf`:
```ruby
# Thêm custom filters
if [severity] == "high" and [network_zone] == "SERVER" {
    mutate { add_tag => ["critical_alert"] }
}
```

#### 3. Network Interface Configuration
Chỉnh sửa file `automation.sh`:
```bash
# Cập nhật interface mapping
declare -A INTERFACES=(
    ["eth0"]="WAN"
    ["eth1"]="LAN"
    ["eth2"]="SERVER" 
    ["eth3"]="DMZ"
)
```

### Attack Detection Capabilities

#### Loại tấn công được phát hiện:
1. **TCP Port Scanning** - Risk Level: 8
2. **UDP Port Scanning** - Risk Level: 7  
3. **ICMP Sweeping** - Risk Level: 6
4. **ARP Scanning** - Risk Level: 5

#### Zone-based Risk Assessment:
- **SERVER Zone**: +30% risk multiplier
- **WAN Zone**: +20% risk multiplier  
- **DMZ Zone**: +10% risk multiplier
- **LAN Zone**: Base risk level

### Log Format và SIEM Integration

#### JSON Log Format:
```json
{
  "timestamp": "2025-05-28 10:30:45.123456",
  "event_type": "network_detection",
  "prediction": "TCP",
  "confidence": 0.8745,
  "is_attack": true,
  "severity": "high",
  "risk_level": 8,
  "network_zone": "SERVER",
  "interface": "ens38",
  "attack_type": "TCP Port Scan",
  "category": "reconnaissance",
  "source_ip": "10.0.0.50",
  "destination_ip": "192.168.100.10",
  "source_port": 54321,
  "destination_port": 22,
  "sensor_id": "nids-ubuntu-ens38",
  "host": "ubuntu-router-192.168.111.133"
}
```

### Troubleshooting

#### Common Issues:

1. **SIEM Connection Failed**
```bash
# Check network connectivity
ping 192.168.30.10
nc -z 192.168.30.10 5514

# Check Windows Firewall
# Trên Windows Server, mở PowerShell Administrator:
New-NetFirewallRule -DisplayName "SIEM-Logstash" -Direction Inbound -Protocol UDP -LocalPort 5514 -Action Allow
```

2. **No Packets Captured**
```bash
# Check interface status
ip link show
sudo tcpdump -i ens33 -c 10  # Test capture

# Check permissions
sudo chmod +x automation.sh
sudo usermod -a -G netdev $USER
```

3. **ML Model Errors**
```bash
# Verify model files
ls -la "../Saved model/"
python3 -c "import pickle; print('Models OK')"

# Check Python dependencies
pip3 install -r requirements.txt
```

4. **ELK Stack Issues**
```powershell
# Check Windows services
Get-Process -Name "java" | Format-Table
Get-Process -Name "node" | Format-Table

# Reset ELK Stack
.\start_siem.ps1 -Stop
Start-Sleep 10
.\start_siem.ps1 -Start
```

### Performance Tuning

#### Ubuntu Router:
```bash
# Tăng buffer size cho tcpdump
sudo sysctl -w net.core.rmem_max=134217728
sudo sysctl -w net.core.netdev_max_backlog=5000

# Optimize cho real-time processing
echo 'net.core.netdev_max_backlog = 5000' | sudo tee -a /etc/sysctl.conf
```

#### Windows Server:
```powershell
# Tăng memory cho Elasticsearch (trong elasticsearch.yml)
# -Xms2g
# -Xmx2g

# Optimize cho real-time indexing
# index.refresh_interval: 1s
```

### Security Considerations

1. **Network Segmentation**: Đảm bảo SIEM server được bảo vệ trong DMZ hoặc management network
2. **Authentication**: Cấu hình Kibana authentication cho production
3. **Encryption**: Sử dụng TLS cho communication giữa NIDS và SIEM
4. **Log Retention**: Cấu hình retention policy phù hợp với yêu cầu compliance

### Monitoring và Maintenance

#### Daily Checks:
```bash
# Ubuntu Router
./test_nids_integration.sh
tail -f logs/nids_detections.log

# Windows Server  
.\start_siem.ps1 -Status
```

#### Weekly Maintenance:
```bash
# Cleanup old logs
find logs/ -name "*.log" -mtime +7 -delete

# Update ML models if needed
# Retrain với dataset mới
```

### Support và Documentation

- **Log Locations**: 
  - Ubuntu: `/home/user/CodeBackup/Code/logs/`
  - Windows: `C:\ELK\alerts\`
- **Configuration Files**: `siem_setup/`
- **ML Models**: `Saved model/`
- **Test Scripts**: `test_nids_integration.sh`, `test_system.ps1`

---

**Version**: 2.1  
**Last Updated**: May 2025  
**Compatible**: Ubuntu 20.04+, Windows Server 2019+
