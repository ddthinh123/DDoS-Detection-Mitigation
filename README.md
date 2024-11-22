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
scikit-learn
numpy
pandas
scapy
keras
tensorflow
2. Chuẩn bị dữ liệu
You can download the dataset from the following link:

[Download Dataset](https://drive.google.com/file/d/1amqNCTs9boU6g9y57p8O2q7GeTIK35P9/view?usp=drive_link)


Tạo mô hình học máy
Mô hình học máy trong dự án sử dụng các đặc trưng của gói tin mạng từ bộ dữ liệu, bao gồm:

Destination Port
Flow Duration
Total Fwd Packets
Total Backward Packets
Total Length of Fwd Packets
Total Length of Bwd Packets
Fwd Packet Length Max
Fwd Packet Length Min
Fwd Packet Length Mean
Fwd Packet Length Std
Bwd Packet Length Max
Bwd Packet Length Min
Bwd Packet Length Mean
Bwd Packet Length Std
Flow Bytes/s
Flow Packets/s
Flow IAT Mean
Flow IAT Std
Flow IAT Max
Flow IAT Min
Fwd IAT Total
Fwd IAT Mean
Fwd IAT Std
Fwd IAT Max
Fwd IAT Min
Bwd IAT Total
Bwd IAT Mean
Bwd IAT Std
Bwd IAT Max
Bwd IAT Min
Fwd PSH Flags
Bwd PSH Flags
Fwd URG Flags
Bwd URG Flags
Fwd Header Length
Bwd Header Length
Fwd Packets/s
Bwd Packets/s
Min Packet Length
Max Packet Length
Packet Length Mean
Packet Length Std
Packet Length Variance
FIN Flag Count
SYN Flag Count
RST Flag Count
PSH Flag Count
ACK Flag Count
URG Flag Count
CWE Flag Count
ECE Flag Count
Down/Up Ratio
Average Packet Size
Avg Fwd Segment Size
Avg Bwd Segment Size
Fwd Avg Bytes/Bulk
Fwd Avg Packets/Bulk
Bwd Avg Bytes/Bulk
Bwd Avg Packets/Bulk
Subflow Fwd Packets
Subflow Fwd Bytes
Subflow Bwd Packets
Subflow Bwd Bytes
Init_Win_bytes_forward
Init_Win_bytes_backward
act_data_pkt_fwd
min_seg_size_forward
Active Mean
Active Std
Active Max
Active Min
Idle Mean
Idle Std
Idle Max
Idle Min
Các đặc trưng này sẽ được sử dụng để huấn luyện mô hình phân loại, giúp phân biệt tấn công DDoS với các lưu lượng mạng bình thường.



