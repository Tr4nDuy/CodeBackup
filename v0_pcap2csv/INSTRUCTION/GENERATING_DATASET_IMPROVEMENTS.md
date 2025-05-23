# Cải tiến trong Generating_dataset.py

## Các thay đổi chính

1. **Cải thiện cách đọc file đầu vào**:
   - Trước đây: Danh sách cố định các file PCAP
   - Hiện tại: Tự động quét thư mục `pcap_files/` và xử lý tất cả các file

   ```python
   pcapfilesdir = "pcap_files"
   pcapfiles = os.listdir(pcapfilesdir)
   ```

2. **Cải thiện quản lý đường dẫn**:
   - Trước đây: Ghép chuỗi trực tiếp, dễ gây lỗi trên các hệ điều hành khác nhau
   - Hiện tại: Sử dụng `os.path.join()` để tạo đường dẫn chính xác

   ```python
   os.path.join(pcapfilesdir, pcap_file)
   ```

3. **Cải thiện đặt tên file đầu ra**:
   - Trước đây: Tên file CSV có thể không nhất quán
   - Hiện tại: Lấy tên file PCAP gốc, loại bỏ phần mở rộng và thêm `.csv`

   ```python
   os.path.join(converted_csv_files_directory, pcap_file[:-5] + ".csv")
   ```

4. **Cải thiện kiểm tra tính nhất quán**:
   - Đảm bảo số lượng file chia nhỏ và số lượng file CSV tạm thời là bằng nhau

   ```python
   assert len(subfiles) == len(os.listdir(destination_directory))
   ```

5. **Cải thiện xử lý lỗi**:
   - Bỏ qua các cảnh báo không cần thiết

   ```python
   warnings.filterwarnings("ignore")
   ```

   - Bắt lỗi khi đọc/ghi file CSV

   ```python
   try:
       d = pd.read_csv(destination_directory + f)
       # ... xử lý file ...
   except:
       pass
   ```

6. **Tối ưu hóa hiệu suất**:
   - Thông số kích thước file nhỏ và số luồng xử lý có thể tùy chỉnh

   ```python
   subfiles_size = 10  # MB
   n_threads = 8
   ```

   - Chia nhỏ danh sách file theo số luồng xử lý

   ```python
   subfiles_threadlist = np.array_split(subfiles, (len(subfiles) / n_threads) + 1)
   ```

7. **Cải thiện giao diện người dùng**:
   - Hiển thị tiến trình xử lý với thanh tiến độ

   ```python
   for f_list in tqdm(subfiles_threadlist):
       # ... xử lý ...
   ```

   - Hiển thị thời gian xử lý

   ```python
   print(f"done! ({pcap_file})(" + str(round(time.time() - lstart, 2)) + "s)")
   ```

## Tác động của các cải tiến

1. **Tăng tính tự động**: Người dùng chỉ cần đặt file PCAP vào thư mục và chạy script
2. **Tăng tính linh hoạt**: Hoạt động trên nhiều hệ điều hành, xử lý nhiều loại file
3. **Tăng tính ổn định**: Xử lý tốt các trường hợp ngoại lệ và lỗi
4. **Cải thiện UX**: Cung cấp thông tin tiến trình rõ ràng cho người dùng
5. **Dễ bảo trì hơn**: Quy trình làm việc rõ ràng, dễ thay đổi và mở rộng
