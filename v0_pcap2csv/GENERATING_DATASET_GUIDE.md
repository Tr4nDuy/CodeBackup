# Hướng dẫn sử dụng Generating_dataset.py

## Tổng quan

File `Generating_dataset.py` là công cụ chính để xử lý các tệp PCAP và tạo bộ dữ liệu CSV phân tích. Công cụ này thực hiện nhiều thao tác tự động:

1. Tự động quét thư mục `pcap_files/` để tìm các tệp PCAP đầu vào
2. Chia tệp PCAP lớn thành các tệp nhỏ hơn (10MB mặc định) sử dụng tcpdump
3. Xử lý song song các tệp nhỏ bằng đa luồng (8 luồng mặc định)
4. Trích xuất đặc trưng từ mỗi tệp nhỏ và tạo các tệp CSV riêng biệt
5. Gộp các tệp CSV nhỏ thành một tệp CSV lớn với tên tương ứng với tệp PCAP đầu vào
6. Tự động xóa các tệp tạm để tiết kiệm không gian đĩa

## Cấu trúc thư mục

Để sử dụng `Generating_dataset.py`, bạn cần đảm bảo có các thư mục sau:

- `pcap_files/`: Thư mục chứa các tệp PCAP đầu vào
- `split_temp/`: Thư mục tạm để lưu các tệp PCAP đã chia nhỏ
- `output/`: Thư mục tạm chứa các tệp CSV trích xuất đặc trưng từ các tệp PCAP nhỏ
- `csv_files/`: Thư mục chứa các tệp CSV đã gộp, mỗi tệp tương ứng với một tệp PCAP đầu vào

## Các bước thực hiện

1. **Tạo các thư mục cần thiết** (nếu chưa tồn tại):

   ```bash
   mkdir -p pcap_files split_temp output csv_files
   ```

2. **Đặt các tệp PCAP vào thư mục `pcap_files/`**:
   - Đảm bảo các tệp có định dạng `.pcap`
   - Tool sẽ tự động xử lý tất cả các tệp trong thư mục này

3. **Chạy script Generating_dataset.py**:

   ```bash
   python Generating_dataset.py
   ```

4. **Quá trình xử lý** sẽ tự động diễn ra:
   - Chia tệp PCAP thành các phần nhỏ hơn (10MB mỗi phần)
   - Xử lý từng phần nhỏ sử dụng 8 luồng xử lý song song
   - Gộp kết quả thành một tệp CSV duy nhất cho mỗi tệp PCAP đầu vào

5. **Kết quả đầu ra**:
   - Các tệp CSV kết quả sẽ được lưu trong thư mục `csv_files/`
   - Tên tệp CSV sẽ là tên tệp PCAP gốc (không bao gồm phần mở rộng `.pcap`)
   - Ví dụ: `traffic.pcap` sẽ tạo ra `traffic.csv`

## Các tham số có thể tùy chỉnh

Trong file `Generating_dataset.py`, bạn có thể điều chỉnh các tham số sau:

```python
subfiles_size = 10  # Kích thước của mỗi tệp PCAP nhỏ (MB)
n_threads = 8       # Số luồng song song để xử lý
```

## Yêu cầu hệ thống

- Python 3.6+
- tcpdump (để chia tệp PCAP)
- Thư viện Python: pandas, numpy, tqdm, dpkt, scapy (tùy chọn)
- Đủ RAM để xử lý các tệp PCAP lớn (tối thiểu 4GB khuyến nghị)

## Xử lý sự cố

1. **Lỗi "tcpdump command not found"**:
   - Đảm bảo đã cài đặt tcpdump: `apt-get install tcpdump` (Linux) hoặc `brew install tcpdump` (macOS)

2. **Lỗi bộ nhớ**:
   - Giảm giá trị `subfiles_size` xuống (ví dụ: 5MB thay vì 10MB)
   - Giảm giá trị `n_threads` (ví dụ: 4 thay vì 8)

3. **Lỗi "Permission denied"**:
   - Đảm bảo bạn có quyền ghi vào các thư mục đầu ra
   - Chạy với quyền admin hoặc sudo nếu cần

4. **Thời gian xử lý quá lâu**:
   - Quá trình xử lý có thể mất nhiều thời gian với các tệp PCAP lớn
   - Đây là hành vi bình thường, công cụ hiển thị thanh tiến trình để theo dõi
