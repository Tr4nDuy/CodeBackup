## câu hỏi



###### **Về mặt dataset**

###### **1. Mô tả kịch bản tấn công kiểu trong 5p đầu, 5 phút tiếp theo thì e làm những gì**
###### **2. Có dựa trên phương pháp nào của các dataset không**

tham khảo các tạo dataset cicids2017, botiot

trong cicids2017 dữ liệu nền được tạo bằng cách sử dụng B-profiles, một cách mô hình hóa dữ liệu để gen ra dữ liệu mới...

yêu cầu: **---bảng so sánh với dataset khác---**

###### **3. Làm rõ trong lúc e tấn công vẫn có lưu lượng bình thường và cách gán nhãn phải cho thấy trường hợp dữ liệu gán nhãn gắn với kịch bản đó. Hiện tại đang gán bằng IP, MAC, protocol thì k dc tin cậy cho lắm --> Nhãn phải phụ thuộc vào đặc điểm của kịch bản đó.**
###### **4. Làm sao làm rõ kịch bản quét nmap này tương ứng với các kịch bản tấn công nào? (Quét nền tảng nào, tốc độ ntn, quét với option ntn, quét với chế độ nào)?**
###### **5. Hiện tại mô tả phần dataset bị chung chung (thực tế pentester hay attacker không đơn giản là chạy nmap cơ bản --> phải có tùy chỉnh,..)**
###### **6. Khi test hiệu suất mô hình với CIDDS và bot-IoT thì kịch bản có giống nhau với dataset custom hay không --> Nếu giống thì dataset tự tạo k có ý nghĩa**
###### **7. Dataset nó có đủ tổng quát hay không hay chỉ nó chỉ có những trường hợp quét đơn giản. Thêm option thứ 1 xong capture , thêm option thứ 2 xong capture --> Thêm nhãn mới không có quá nhiều ý nghĩa**
###### **8. Khi test trên tập data đơn giản như vậy thì đề xuất mô hình cũng không có nhiều ý nghĩa.**
###### **9. Làm rõ Threat model trong báo cáo kltn ở chương 3,...**



**Đảm bảo các yêu cầu về chi tiết và thực tế:**

- Kịch bản tấn công được xây dựng đa dạng, sử dụng nhiều loại scan, nhiều option, tốc độ khác nhau, mô phỏng hành vi pentester thực tế.
- Trong suốt quá trình, lưu lượng bình thường luôn được sinh song song với lưu lượng tấn công.
- Việc gán nhãn không chỉ dựa vào IP/MAC mà dựa vào thời điểm, log script, hành động thực tế, đảm bảo nhãn phản ánh đúng kịch bản.
- Các lệnh scan và traffic đều được ghi lại chi tiết, có thể truy vết lại từng flow.
- Dataset đảm bảo tổng quát, không chỉ là các trường hợp đơn giản, mà bao gồm nhiều loại scan, nhiều subnet, nhiều chế độ.
- Khi so sánh với các dataset công khai (CICIDS2017, Bot-IoT, CIDDS-001), kịch bản test và môi trường khác biệt, bổ sung các trường hợp thực tế chưa có trong các bộ dữ liệu công khai.
- Mô hình được kiểm thử trên cả data đơn giản và phức tạp để đánh giá toàn diện.
















