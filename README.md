## DDoS Detection and Mitigation System
## Mô tả dự án
Dự án này phát triển một hệ thống phát hiện và ngăn chặn tấn công DDoS (Distributed Denial of Service) sử dụng các mô hình học máy. Hệ thống sẽ giám sát mạng trong thời gian thực, phát hiện các tấn công DDoS và tự động thực thi các biện pháp bảo vệ như chặn IP của các nguồn tấn công.

Các module chính
Module Giám Sát (Monitoring Module):

Thu thập gói tin mạng và trích xuất các đặc trưng từ các gói tin này.
Gửi các đặc trưng đến mô hình học máy để phân loại liệu có tấn công DDoS hay không.
Module Phát Hiện (Detection Module):

Sử dụng mô hình học máy đã huấn luyện để phát hiện tấn công DDoS.
Trả về kết quả phân loại (DDoS hay bình thường).
Module Ngăn Chặn (Mitigation Module):

Khi phát hiện tấn công DDoS, thực thi các biện pháp ngăn chặn, ví dụ: chặn IP của nguồn tấn công bằng cách sử dụng iptables.
Các bước cài đặt và sử dụng
1. Cài đặt các thư viện phụ thuộc
Trước khi bắt đầu, bạn cần cài đặt các thư viện cần thiết:

pip install -r requirements.txt
scikit-learn
numpy
pandas
scapy
keras
tensorflow
2. Chuẩn bị dữ liệu
You can download the dataset from the following link:

[Download Dataset](https://drive.google.com/file/d/1amqNCTs9boU6g9y57p8O2q7GeTIK35P9/view?usp=drive_link)


3. Huấn luyện mô hình
Để huấn luyện mô hình học máy, bạn có thể sử dụng mã trong file train_model.py. Sau khi huấn luyện, mô hình sẽ được lưu dưới dạng file model.pkl.
python RF.py
4. Cấu hình hệ thống giám sát
Sau khi huấn luyện mô hình, bạn có thể bắt đầu giám sát mạng bằng cách chạy module giám sát:
python monitoring_module.py
Module giám sát sẽ thu thập gói tin từ mạng, trích xuất các đặc trưng và gửi chúng vào mô hình học máy để phân loại. Nếu mô hình phát hiện tấn công DDoS, nó sẽ kích hoạt module ngăn chặn.

5. Cấu hình hệ thống ngăn chặn
Khi module phát hiện tấn công DDoS, hệ thống sẽ tự động thực thi các biện pháp ngăn chặn. Điều này được thực hiện trong module ngăn chặn (mitigation_module.py). Mặc định, hệ thống sử dụng iptables để chặn IP của các nguồn tấn công.

Để thay đổi các biện pháp ngăn chặn, bạn có thể chỉnh sửa hàm block_ip() trong mitigation_module.py.

Cấu trúc dự án

### DDoS-Detection-Mitigation/
 ## monitoring_module.py       # Module giám sát mạng
 ## detection_module.py        # Module phát hiện tấn công DDoS
 ## mitigation_module.py       # Module ngăn chặn tấn công DDoS
 ## RF.py             # Huấn luyện mô hình học máy
 ## model.pkl                  # Mô hình đã huấn luyện
 ## README.md                  # Tài liệu hướng dẫn sử dụng
Chạy thử hệ thống
Huấn luyện mô hình:

python RF.py
Sau khi huấn luyện xong, chạy module giám sát:

python monitoring_module.py
Nếu tấn công DDoS được phát hiện, hệ thống sẽ tự động thực hiện biện pháp ngăn chặn (chặn IP).

Ghi chú
Đảm bảo rằng bạn có quyền truy cập root hoặc quyền quản trị để thực thi các lệnh ngăn chặn (ví dụ: iptables).
Hệ thống giám sát sẽ chạy liên tục và tự động phát hiện các tấn công DDoS trong thời gian thực.
Để tối ưu hiệu suất, bạn có thể điều chỉnh các tham số trong mô hình học máy và cấu hình module giám sát sao cho phù hợp với hệ thống của bạn.
Tạo mô hình học máy
Mô hình học máy trong dự án sử dụng các đặc trưng của gói tin mạng từ bộ dữ liệu như sau:

Destination Port
Flow Duration
Total Fwd Packets
Total Backward Packets
... (Danh sách đầy đủ các đặc trưng có trong bộ dữ liệu)
Các đặc trưng này sẽ được sử dụng để huấn luyện mô hình phân loại, giúp phân biệt tấn công DDoS với các lưu lượng mạng bình thường.

