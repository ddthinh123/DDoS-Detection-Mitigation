from ryu.app.simple_switch_13 import SimpleSwitch13  # Kế thừa từ ứng dụng SimpleSwitch13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from datetime import datetime
import os

class CollectTrainingStatsApp(SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super(CollectTrainingStatsApp, self).__init__(*args, **kwargs)
        self.datapaths = {}  # Từ điển lưu các datapaths
        self.monitor_thread = hub.spawn(self.monitor)  # Tạo một luồng giám sát
        self.file_path = "FlowStatsfile.csv"  # Đường dẫn tệp CSV
        self._initialize_csv_file()  # Khởi tạo tệp CSV với tiêu đề

    def _initialize_csv_file(self):
        """Khởi tạo tệp CSV nếu chưa tồn tại."""
        if not os.path.exists(self.file_path):
            with open(self.file_path, "w") as file:
                file.write('timestamp,datapath_id,flow_id,ip_src,tp_src,ip_dst,tp_dst,ip_proto,icmp_code,icmp_type,'
                           'flow_duration_sec,flow_duration_nsec,idle_timeout,hard_timeout,flags,packet_count,'
                           'byte_count,packet_count_per_second,packet_count_per_nsecond,byte_count_per_second,'
                           'byte_count_per_nsecond,label\n')

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        """Xử lý sự kiện thay đổi trạng thái của datapath."""
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.info(f"Registering datapath: {datapath.id}")
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.info(f"Unregistering datapath: {datapath.id}")
                del self.datapaths[datapath.id]

    def monitor(self):
        """Giám sát và gửi yêu cầu thống kê flow đến các datapaths."""
        while True:
            for dp in self.datapaths.values():
                self.request_stats(dp)
            hub.sleep(10)

    def request_stats(self, datapath):
        """Gửi yêu cầu thống kê flow đến datapath."""
        self.logger.debug(f"Sending stats request to datapath: {datapath.id}")
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        """Xử lý phản hồi thống kê flow và ghi vào tệp CSV."""
        timestamp = datetime.now().timestamp()

        # Mở file CSV ở chế độ append
        with open(self.file_path, "a+") as file:
            body = ev.msg.body
            for stat in body:
                # Lấy thông tin từ flow match, sử dụng giá trị mặc định nếu không tồn tại
                ip_src = stat.match.get('ipv4_src', 'N/A')
                ip_dst = stat.match.get('ipv4_dst', 'N/A')
                ip_proto = stat.match.get('ip_proto', 0)
                tp_src = stat.match.get('tcp_src', 0) if ip_proto == 6 else stat.match.get('udp_src', 0)
                tp_dst = stat.match.get('tcp_dst', 0) if ip_proto == 6 else stat.match.get('udp_dst', 0)
                icmp_code = stat.match.get('icmpv4_code', -1)
                icmp_type = stat.match.get('icmpv4_type', -1)

                # Tạo flow ID hợp lệ
                flow_id = f"{ip_src}-{tp_src}-{ip_dst}-{tp_dst}-{ip_proto}"

                # Tính toán các thông số lưu lượng
                packet_count_per_second = stat.packet_count / stat.duration_sec if stat.duration_sec > 0 else 0
                byte_count_per_second = stat.byte_count / stat.duration_sec if stat.duration_sec > 0 else 0
                packet_count_per_nsecond = stat.packet_count / stat.duration_nsec if stat.duration_nsec > 0 else 0
                byte_count_per_nsecond = stat.byte_count / stat.duration_nsec if stat.duration_nsec > 0 else 0

                # Ghi dữ liệu vào file CSV
                file.write(
                    f"{timestamp},{ev.msg.datapath.id},{flow_id},{ip_src},{tp_src},{ip_dst},{tp_dst},{ip_proto},"
                    f"{icmp_code},{icmp_type},{stat.duration_sec},{stat.duration_nsec},{stat.idle_timeout},"
                    f"{stat.hard_timeout},{stat.flags},{stat.packet_count},{stat.byte_count},"
                    f"{packet_count_per_second},{packet_count_per_nsecond},{byte_count_per_second},"
                    f"{byte_count_per_nsecond},0\n"
                )

        self.logger.info(f"Flow stats processed and written to {self.file_path}")

