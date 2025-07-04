### Mô tả chi tiết quá trình tạo dataset và kịch bản tấn công


#### Internal Portscan

- **Giai đoạn 1: Lưu lượng bình thường (benign)**
  - Thời gian: 2024-05-24 18:09:41.630593 đến 2024-05-24 18:12:53.383733
  - Chỉ sinh lưu lượng bình thường (normal traffic) bằng script tự động (truy cập web, gửi nhận email, truyền file qua FTP, truy cập các dịch vụ nội bộ và DMZ) kết hợp thao tác thủ công như duyệt web, tải file, xem video, nghe nhạc... nhằm mô phỏng hành vi người dùng thực tế.

- **Giai đoạn 2: Quét TCP (in-tcp-1 đến in-tcp-7)**
  - Thời gian: 2024-05-24 18:13:02.930867 đến 2024-05-24 21:37:31.690047
  - Tiến hành tấn công quét cổng từ máy trong mạng LAN (attacker IP: 192.168.20.102) tới toàn bộ các subnet nội bộ (192.168.20.0/24, 192.168.30.0/24, 192.168.40.0/24) với các lệnh Nmap sau, đồng thời vẫn duy trì sinh traffic bình thường:
    - 4 loại TCP scan đầu (in-tcp-1 đến in-tcp-4):
      - `nmap -sS 192.168.20.0/24 192.168.30.0/24 192.168.40.0/24 -T2`  (TCP SYN scan)
      - `nmap -sT 192.168.20.0/24 192.168.30.0/24 192.168.40.0/24 -T2`  (TCP Connect scan)
      - `nmap -sF 192.168.20.0/24 192.168.30.0/24 192.168.40.0/24 -T2`  (TCP FIN scan)
      - `nmap -sX 192.168.20.0/24 192.168.30.0/24 192.168.40.0/24 -T2`  (TCP Xmas scan)
    - 4 loại TCP scan tiếp theo (in-tcp-5 đến in-tcp-7):
      - `nmap -sN 192.168.20.0/24 192.168.30.0/24 192.168.40.0/24 -T2`  (TCP Null scan)
      - `nmap -sA 192.168.20.0/24 192.168.30.0/24 192.168.40.0/24 -T2`  (TCP ACK scan)
      - `nmap -sW 192.168.20.0/24 192.168.30.0/24 192.168.40.0/24 -T2`  (TCP Window scan)
      - `nmap -sM 192.168.20.0/24 192.168.30.0/24 192.168.40.0/24 -T2`  (TCP Maimon scan)

- **Giai đoạn 3: Quét UDP (in-udp-1 đến in-udp-4)**
  - Thời gian: 2024-05-24 21:37:45.314895 đến 2024-05-24 23:59:06.612963
  - Thực hiện các lần quét UDP:
    - `nmap -sU 192.168.20.0/24 192.168.30.0/24 192.168.40.0/24` (quét trên các subnet nội bộ)

- **Lưu ý về ARP/ICMP:**
  - Trong quá trình quét TCP/UDP, các gói ARP và ICMP cũng được sinh ra nhưng số lượng ít. Nếu cần tăng cường dữ liệu, có thể thực hiện thêm quét ARP/ICMP riêng biệt với lệnh:
    - `nmap -sn 192.168.20.0/24 192.168.30.0/24 192.168.40.0/24 -T2`

**Lưu ý:** Trong toàn bộ quá trình, lưu lượng bình thường luôn được duy trì song song với lưu lượng tấn công để đảm bảo tính thực tế cho dataset. Việc gán nhãn cho từng flow được thực hiện dựa trên thời điểm thực hiện các lệnh scan, log script và hành động thực tế, không chỉ dựa vào IP/MAC/protocol.


#### External Portscan

- **Giai đoạn 1: Lưu lượng bình thường (out-benign)**
  - Thời gian: 2024-05-25 15:24:44.020856 đến 2024-05-25 15:29:12.078891
  - Chỉ sinh lưu lượng bình thường (normal traffic) từ phía ngoài (user IP: 10.45.10.202) truy cập dịch vụ web tại DMZ.

- **Giai đoạn 2: Quét TCP/UDP (out-tcp-1, out-tcp-2, out-udp-1, out-udp-2)**
  - Thời gian: 2024-05-25 15:29:19.425602 đến 2024-05-25 16:02:52.251410
  - Tiến hành quét cổng từ ngoài vào (attacker IP: 10.45.71.76) nhắm vào WAN interface của router (10.45.172.150, cổng 80 được forward về web server tại DMZ), sử dụng các lệnh Nmap sau, đồng thời vẫn duy trì traffic bình thường:
    - 8 loại TCP scan:
      - `nmap -sS 10.45.172.150 -T2`  (TCP SYN scan)
      - `nmap -sT 10.45.172.150 -T2`  (TCP Connect scan)
      - `nmap -sF 10.45.172.150 -T2`  (TCP FIN scan)
      - `nmap -sX 10.45.172.150 -T2`  (TCP Xmas scan)
      - `nmap -sN 10.45.172.150 -T2`  (TCP Null scan)
      - `nmap -sA 10.45.172.150 -T2`  (TCP ACK scan)
      - `nmap -sM 10.45.172.150 -T2`  (TCP Maimon scan)
      - `nmap -sW 10.45.172.150 -T2`  (TCP Window scan)
    - 2 lần UDP scan:
      - `nmap -sU 10.45.172.150`
    - ARP/ICMP scan:
      - `nmap -sn 10.45.172.150 -T2`