from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub

import mitigation_module  # Import the mitigation module or no mitigation from the controller folder
from datetime import datetime

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import confusion_matrix
from sklearn.metrics import accuracy_score
from sklearn.model_selection import cross_val_score


class SimpleMonitor13(mitigation_module.SimpleSwitch13):

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.datapaths = {}

        self.monitor_thread = hub.spawn(self._monitor)

        start = datetime.now()
        self.flow_training()
        end = datetime.now()

        # Corrected logging: Using f-string for proper formatting
        self.logger.info(f"Training time: {end - start}")

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(10)
            self.flow_predict()

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        timestamp = datetime.now().timestamp()
        # Open file in append mode, not overwrite
        with open("PredictFlowStatsfile.csv", "a") as file0:
            if file0.tell() == 0:  # if file is empty, write headers
                file0.write('timestamp,datapath_id,flow_id,ip_src,tp_src,ip_dst,tp_dst,ip_proto,icmp_code,icmp_type,flow_duration_sec,flow_duration_nsec,idle_timeout,hard_timeout,flags,packet_count,byte_count,packet_count_per_second,packet_count_per_nsecond,byte_count_per_second,byte_count_per_nsecond\n')

            body = ev.msg.body
            icmp_code = -1
            icmp_type = -1
            tp_src = 0
            tp_dst = 0

            for stat in sorted([flow for flow in body if flow.priority == 1], key=lambda flow:
                (flow.match.get('eth_type', ''), flow.match.get('ipv4_src', ''), flow.match.get('ipv4_dst', ''), flow.match.get('ip_proto', ''))):

                ip_src = stat.match.get('ipv4_src', '')
                ip_dst = stat.match.get('ipv4_dst', '')
                ip_proto = stat.match.get('ip_proto', '')

                # Handle missing eth_type or ip_proto
                if not ip_src or not ip_dst or not ip_proto:
                    continue

                if ip_proto == 1:
                    icmp_code = stat.match.get('icmpv4_code', -1)
                    icmp_type = stat.match.get('icmpv4_type', -1)
                elif ip_proto == 6:
                    tp_src = stat.match.get('tcp_src', 0)
                    tp_dst = stat.match.get('tcp_dst', 0)
                elif ip_proto == 17:
                    tp_src = stat.match.get('udp_src', 0)
                    tp_dst = stat.match.get('udp_dst', 0)

                flow_id = str(ip_src) + str(tp_src) + str(ip_dst) + str(tp_dst) + str(ip_proto)

                # Handling zero division or missing packet/byte counts
                packet_count_per_second = stat.packet_count / stat.duration_sec if stat.duration_sec else 0
                packet_count_per_nsecond = stat.packet_count / stat.duration_nsec if stat.duration_nsec else 0
                byte_count_per_second = stat.byte_count / stat.duration_sec if stat.duration_sec else 0
                byte_count_per_nsecond = stat.byte_count / stat.duration_nsec if stat.duration_nsec else 0

                file0.write("{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n"
                            .format(timestamp, ev.msg.datapath.id, flow_id, ip_src, tp_src, ip_dst, tp_dst,
                                    ip_proto, icmp_code, icmp_type,
                                    stat.duration_sec, stat.duration_nsec,
                                    stat.idle_timeout, stat.hard_timeout,
                                    stat.flags, stat.packet_count, stat.byte_count,
                                    packet_count_per_second, packet_count_per_nsecond,
                                    byte_count_per_second, byte_count_per_nsecond))

    def flow_training(self):
        self.logger.info("Flow Training ...")
        flow_dataset = pd.read_csv('../machinelearning/FlowStatsfile.csv')

        # Ensuring the columns are treated as strings for replace
        flow_dataset.iloc[:, 2] = flow_dataset.iloc[:, 2].astype(str).str.replace('.', '')
        flow_dataset.iloc[:, 3] = flow_dataset.iloc[:, 3].astype(str).str.replace('.', '')
        flow_dataset.iloc[:, 5] = flow_dataset.iloc[:, 5].astype(str).str.replace('.', '')

        X_flow = flow_dataset.iloc[:, :-1].values
        X_flow = X_flow.astype('float64')
        y_flow = flow_dataset.iloc[:, -1].values

        X_flow_train, X_flow_test, y_flow_train, y_flow_test = train_test_split(X_flow, y_flow, test_size=0.25, random_state=0)

        classifier = DecisionTreeClassifier(criterion='entropy', random_state=0)
        self.flow_model = classifier.fit(X_flow_train, y_flow_train)

        y_flow_pred = self.flow_model.predict(X_flow_test)

        self.logger.info("------------------------------------------------------------------------------")
        self.logger.info("Confusion Matrix:")
        cm = confusion_matrix(y_flow_test, y_flow_pred)
        self.logger.info(cm)

        acc = accuracy_score(y_flow_test, y_flow_pred)
        self.logger.info(f"Success accuracy = {acc*100:.2f} %")
        fail = 1.0 - acc
        self.logger.info(f"Fail accuracy = {fail*100:.2f} %")
        self.logger.info("------------------------------------------------------------------------------")

    def flow_predict(self):
        try:
            predict_flow_dataset = pd.read_csv('PredictFlowStatsfile.csv')

            # Ensuring the columns are treated as strings for replace
            predict_flow_dataset.iloc[:, 2] = predict_flow_dataset.iloc[:, 2].astype(str).str.replace('.', '')
            predict_flow_dataset.iloc[:, 3] = predict_flow_dataset.iloc[:, 3].astype(str).str.replace('.', '')
            predict_flow_dataset.iloc[:, 5] = predict_flow_dataset.iloc[:, 5].astype(str).str.replace('.', '')

            X_predict_flow = predict_flow_dataset.iloc[:, :].values
            X_predict_flow = X_predict_flow.astype('float64')

            y_flow_pred = self.flow_model.predict(X_predict_flow)

            legitimate_traffic = 0
            ddos_traffic = 0

            for i in y_flow_pred:
                if i == 0:
                    legitimate_traffic += 1
                else:
                    ddos_traffic += 1
                    victim = int(predict_flow_dataset.iloc[i, 5]) % 20

            self.logger.info("------------------------------------------------------------------------------")
            if (legitimate_traffic / len(y_flow_pred) * 100) > 80:
                self.logger.info("Normal Traffic")
            else:
                self.logger.info(f"DDOS Attack at host h{victim} with IP address 10.0.0.{victim}")
                self.mitigation = 1  # Placeholder for mitigation logic

            self.logger.info("------------------------------------------------------------------------------")
            # Open file in write mode only when overwriting (not appending)
            with open("PredictFlowStatsfile.csv", "w") as file0:
                file0.write('timestamp,datapath_id,flow_id,ip_src,tp_src,ip_dst,tp_dst,ip_proto,icmp_code,icmp_type,flow_duration_sec,flow_duration_nsec,idle_timeout,hard_timeout,flags,packet_count,byte_count,packet_count_per_second,packet_count_per_nsecond,byte_count_per_second,byte_count_per_nsecond\n')

        except Exception as e:
            self.logger.error(f"Prediction failed: {str(e)}")
            return

