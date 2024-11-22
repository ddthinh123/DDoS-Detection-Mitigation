import os

class DDoSMitigation:
    def __init__(self):
        pass

    def block_ip(self, ip_address):
        # Cách đơn giản là sử dụng iptables để chặn IP
        os.system(f"sudo iptables -A INPUT -s {ip_address} -j DROP")
        print(f"Blocked IP: {ip_address}")
