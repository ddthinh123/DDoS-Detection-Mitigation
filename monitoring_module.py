import time
import socket
from detection_module import DDoSDetector  # import module phát hiện

class MonitoringModule:
    def __init__(self, model):
        self.model = model
        self.detector = DDoSDetector(self.model)  # Tạo đối tượng detector từ model đã huấn luyện
        
    def monitor_network(self):
        while True:
            # Giả sử chúng ta nhận gói tin từ scapy hoặc tcpdump
            packet = self.capture_packet()  # Hàm này phải được implement để thu thập gói tin
            
            if packet:
                features = self.extract_features(packet)  # Trích xuất đặc trưng từ gói tin
                is_ddos = self.detector.detect(features)  # Phát hiện tấn công

                if is_ddos:
                    print("DDoS Attack Detected!")
                    self.block_attack(packet.src_ip)  # Chặn tấn công (gọi module ngăn chặn)
            
            time.sleep(1)  # Giám sát liên tục

    def capture_packet(self):
        # Hàm thu thập gói tin (có thể dùng Scapy hoặc TCPDump)
        pass

    def extract_features(self, packet):
        # Trích xuất đặc trưng của gói tin để đưa vào mô hình
        pass

    def block_attack(self, ip_address):
        # Gọi module ngăn chặn để chặn IP của kẻ tấn công
        pass
