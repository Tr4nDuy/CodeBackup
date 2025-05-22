from scapy.all import *
import pandas as pd
import dpkt
import logging
import time

from Communication_features import Communication_wifi, Communication_zigbee
from Connectivity_features import Connectivity_features_basic, Connectivity_features_time, \
    Connectivity_features_flags_bytes
from Dynamic_features import Dynamic_features
from Layered_features import L3, L4, L2, L1
from Supporting_functions import get_protocol_name, get_flow_info, get_flag_values, compare_flow_flags, \
    get_src_dst_packets, calculate_incoming_connections, \
    calculate_packets_counts_per_ips_proto, calculate_packets_count_per_ports_proto

# Thiết lập logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class Feature_extraction():
    """
    Lớp chính để trích xuất các đặc trưng từ tệp PCAP.
    Chức năng:
    - Phân tích gói tin mạng
    - Trích xuất các đặc trưng từ các gói tin
    - Lưu kết quả vào tệp CSV
    """
    
    def __init__(self):
        """
        Khởi tạo các cột và cấu trúc dữ liệu cần thiết
        """
        self.columns = [
            "ts", "flow_duration", "flow_byte",
            "src_mac", "dst_mac", "src_ip", "dst_ip", "src_port", "dst_port",
            "Protocol_Type", "ttl_value",
            "Rate", "Srate", "Drate",
            "fin_flag_number", "syn_flag_number", "rst_flag_number",
            "psh_flag_number", "ack_flag_number", "urg_flag_number", "ece_flag_number", "cwr_flag_number",
            "ack_count", "syn_count", "fin_count", "urg_count", "rst_count",
            "max_duration", "min_duration", "sum_duration", "average_duration", "std_duration",
            "CoAP", "HTTP", "HTTPS", "DNS", "Telnet", "SMTP", "SSH", "IRC", "TCP", "UDP", "DHCP", "ARP", "ICMP", "IGMP", "IPv", "LLC",
            "Tot_sum", "Min", "Max", "AVG", "Std", "Tot_size", "IAT", "Number", "MAC", "Magnitude", "Radius", "Covariance", "Variance", "Weight",
            "DS_status", "Fragments", 
            "Sequence_number", "Protocol_Version",
            "flow_idle_time", "flow_active_time"
        ]
        
        # Đặt tên biến chính xác hơn
        self.base_row = {c:[] for c in self.columns}
        self.batch_size = 20  # Số lượng gói tin trong mỗi batch

    def initialize_data_structures(self):
        """
        Khởi tạo các cấu trúc dữ liệu cần thiết cho việc phân tích
        """
        # Các dict để theo dõi luồng IP
        self.ip_flow = {}
        self.ethsize = []
        
        # Các dict để lưu trữ thông tin về port
        self.src_ports = {}  # Lưu số lượng port nguồn được sử dụng
        self.dst_ports = {}  # Lưu số lượng port đích được sử dụng
        
        # Các dict để lưu trữ thông tin về flow
        self.tcpflows = {}  # Lưu tất cả TCPflows
        self.udpflows = {}  # Lưu tất cả UDPflows
        
        # Các dict để lưu trữ thông tin về gói tin
        self.src_packet_count = {}  # Lưu số lượng gói tin trên mỗi IP nguồn
        self.dst_packet_count = {}  # Lưu số lượng gói tin trên mỗi IP đích
        self.dst_port_packet_count = {}  # Lưu số lượng gói tin trên mỗi port đích
        
        # Các dict để lưu trữ thông tin về byte
        self.src_ip_byte = {}
        self.dst_ip_byte = {}
        
        # Các dict để lưu trữ thông tin về cờ TCP
        self.tcp_flow_flags = {}  # Lưu số lượng cờ cho mỗi flow
        
        # Các dict để lưu trữ thông tin về protocol
        self.packets_per_protocol = {}  # Lưu số lượng gói tin theo protocol
        
        # Các dict để lưu trữ thông tin thống kê
        self.average_per_proto_src = {}  # Lưu số lượng gói tin theo protocol và src_ip
        self.average_per_proto_dst = {}  # Lưu số lượng gói tin theo protocol và dst_ip
        self.average_per_proto_src_port = {}
        self.average_per_proto_dst_port = {}
        
        # Biến tính toán
        self.ips = set()  # Lưu IP duy nhất
        self.incoming_pack = []
        self.outgoing_pack = []
        
        # Biến thống kê thời gian
        self.first_pac_time = 0
        self.last_pac_time = 0
        self.total_du = 0
        
        return self

    def process_mac_addresses(self, eth):
        """
        Xử lý địa chỉ MAC từ gói tin Ethernet
        """
        try:
            src_mac = ':'.join('%02x' % b for b in eth.src)
            dst_mac = ':'.join('%02x' % b for b in eth.dst)
            return src_mac, dst_mac
        except Exception as e:
            logger.error(f"Error processing MAC addresses: {e}")
            return "", ""

    def process_dynamic_features(self, ethernet_frame_size, ts):
        """
        Tính toán các đặc trưng động dựa trên kích thước frame và timestamp
        """
        dy = Dynamic_features()
        self.ethsize.append(ethernet_frame_size)
        
        # Tính toán các đặc trưng động
        sum_packets, min_packets, max_packets, mean_packets, std_packets = dy.dynamic_calculation(self.ethsize)
        
        # Tính IAT (Inter Arrival Time)
        self.last_pac_time = ts
        iat = self.last_pac_time - self.first_pac_time
        self.first_pac_time = self.last_pac_time
        
        return sum_packets, min_packets, max_packets, mean_packets, std_packets, iat

    def process_ip_flow(self, src_ip, dst_ip, ethernet_frame_size):
        """
        Xử lý luồng IP, phân loại gói tin vào/ra
        """
        if dst_ip in self.ip_flow and self.ip_flow[dst_ip] == src_ip:
            self.outgoing_pack.append(ethernet_frame_size)
        else:
            self.incoming_pack.append(ethernet_frame_size)
            self.ip_flow[src_ip] = dst_ip
            
        # Tính các đặc trưng dựa trên 2 luồng
        dy = Dynamic_features()
        magnitude, radius, correlation, covariance, var_ratio, weight = dy.dynamic_two_streams(
            self.incoming_pack, self.outgoing_pack
        )
        
        return magnitude, radius, correlation, covariance, var_ratio, weight

    def process_tcp_packet(self, eth, ip, src_ip, dst_ip, src_port, dst_port, ts):
        """
        Xử lý gói tin TCP
        """
        flag_values = get_flag_values(ip.data)
        ack_count, syn_count, fin_count, urg_count, rst_count = 0, 0, 0, 0, 0
        
        # L4 features based on TCP
        l_four = L4(src_port, dst_port)
        http = l_four.http()
        https = l_four.https()
        ssh = l_four.ssh()
        irc = l_four.IRC()
        smtp = l_four.smtp()
        mqtt = l_four.mqtt()
        telnet = l_four.telnet()
        
        # Kiểm tra trạng thái kết nối HTTP nếu có
        connection_status = 0
        try:
            http_info = dpkt.http.Response(ip.data)
            connection_status = http_info.status
        except Exception:
            pass
            
        # Xử lý flow TCP
        flow = sorted([(src_ip, src_port), (dst_ip, dst_port)])
        flow = (flow[0], flow[1])
        flow_data = {
            'byte_count': len(eth),
            'ts': ts
        }
        
        if self.tcpflows.get(flow):
            self.tcpflows[flow].append(flow_data)
            # So sánh trạng thái Flow dựa trên các cờ
            ack_count, syn_count, fin_count, urg_count, rst_count = self.tcp_flow_flags[flow]
            ack_count, syn_count, fin_count, urg_count, rst_count = compare_flow_flags(
                flag_values, ack_count, syn_count, fin_count, urg_count, rst_count
            )
            self.tcp_flow_flags[flow] = [ack_count, syn_count, fin_count, urg_count, rst_count]
        else:
            self.tcpflows[flow] = [flow_data]
            ack_count, syn_count, fin_count, urg_count, rst_count = compare_flow_flags(
                flag_values, ack_count, syn_count, fin_count, urg_count, rst_count
            )
            self.tcp_flow_flags[flow] = [ack_count, syn_count, fin_count, urg_count, rst_count]
            
        # Tính các thông tin của flow
        packets = self.tcpflows[flow]
        number_of_packets = len(packets)
        flow_byte, flow_duration, max_duration, min_duration, sum_duration, avg_duration, std_duration, idle_time, active_time = get_flow_info(self.tcpflows, flow)
        src_to_dst_pkt, dst_to_src_pkt, src_to_dst_byte, dst_to_src_byte = get_src_dst_packets(self.tcpflows, flow)
        
        # Tính tốc độ nếu flow_duration khác 0
        rate, srate, drate = 0, 0, 0
        if flow_duration != 0:
            rate = number_of_packets / flow_duration
            srate = src_to_dst_pkt / flow_duration
            drate = dst_to_src_pkt / flow_duration
            
        # Cập nhật các thông số
        self.update_port_count(dst_port)
        
        return {
            'flag_values': flag_values,
            'flow_byte': flow_byte,
            'flow_duration': flow_duration,
            'ack_count': ack_count,
            'syn_count': syn_count,
            'fin_count': fin_count,
            'urg_count': urg_count,
            'rst_count': rst_count,
            'max_duration': max_duration,
            'min_duration': min_duration,
            'sum_duration': sum_duration,
            'avg_duration': avg_duration,
            'std_duration': std_duration,
            'idle_time': idle_time,
            'active_time': active_time,
            'rate': rate,
            'srate': srate,
            'drate': drate,
            'http': http,
            'https': https,
            'ssh': ssh,
            'irc': irc,
            'smtp': smtp,
            'mqtt': mqtt,
            'telnet': telnet,
            'connection_status': connection_status
        }

    def process_udp_packet(self, eth, src_ip, dst_ip, src_port, dst_port, ts):
        """
        Xử lý gói tin UDP
        """
        # L4 features
        l_four = L4(src_port, dst_port)
        l_two = L2(src_port, dst_port)
        dhcp = l_two.dhcp()
        dns = l_four.dns()
        
        # Cập nhật thông tin port
        if dst_port in self.dst_port_packet_count:
            self.dst_port_packet_count[dst_port] = self.dst_port_packet_count[dst_port] + 1
        else:
            self.dst_port_packet_count[dst_port] = 1
            
        # Xử lý flow UDP
        flow = sorted([(src_ip, src_port), (dst_ip, dst_port)])
        flow = (flow[0], flow[1])
        flow_data = {
            'byte_count': len(eth),
            'ts': ts
        }
        
        if self.udpflows.get(flow):
            self.udpflows[flow].append(flow_data)
        else:
            self.udpflows[flow] = [flow_data]
            
        # Tính các thông tin của flow
        packets = self.udpflows[flow]
        number_of_packets = len(packets)
        flow_byte, flow_duration, max_duration, min_duration, sum_duration, avg_duration, std_duration, idle_time, active_time = get_flow_info(self.udpflows, flow)
        src_to_dst_pkt, dst_to_src_pkt, src_to_dst_byte, dst_to_src_byte = get_src_dst_packets(self.udpflows, flow)
        
        # Tính tốc độ nếu flow_duration khác 0
        rate, srate, drate = 0, 0, 0
        if flow_duration != 0:
            rate = number_of_packets / flow_duration
            srate = src_to_dst_pkt / flow_duration
            drate = dst_to_src_pkt / flow_duration
            
        return {
            'flow_byte': flow_byte,
            'flow_duration': flow_duration,
            'max_duration': max_duration,
            'min_duration': min_duration,
            'sum_duration': sum_duration,
            'avg_duration': avg_duration,
            'std_duration': std_duration,
            'idle_time': idle_time,
            'active_time': active_time,
            'rate': rate,
            'srate': srate,
            'drate': drate,
            'dhcp': dhcp,
            'dns': dns
        }

    def update_port_count(self, dst_port):
        """
        Cập nhật số lượng gói tin trên mỗi port đích
        """
        if dst_port in self.dst_port_packet_count:
            self.dst_port_packet_count[dst_port] = self.dst_port_packet_count[dst_port] + 1
        else:
            self.dst_port_packet_count[dst_port] = 1

    def prepare_row_data(self, packet_data, **kwargs):
        """
        Chuẩn bị dữ liệu cho một hàng mới
        """
        # Lấy giá trị mặc định nếu không được cung cấp
        ts = kwargs.get('ts', 0)
        src_mac = kwargs.get('src_mac', '')
        dst_mac = kwargs.get('dst_mac', '')
        src_ip = kwargs.get('src_ip', 0)
        dst_ip = kwargs.get('dst_ip', 0)
        src_port = kwargs.get('src_port', 0)
        dst_port = kwargs.get('dst_port', 0)
        ttl_value = kwargs.get('ttl_value', 0)
        proto_type = kwargs.get('proto_type', 0)
        ethernet_frame_size = kwargs.get('ethernet_frame_size', 0)
        
        # Lấy các đặc trưng động
        sum_packets = kwargs.get('sum_packets', 0)
        min_packets = kwargs.get('min_packets', 0)
        max_packets = kwargs.get('max_packets', 0)
        mean_packets = kwargs.get('mean_packets', 0)
        std_packets = kwargs.get('std_packets', 0)
        iat = kwargs.get('iat', 0)
        
        # Lấy các đặc trưng magnitude
        magnitude = kwargs.get('magnitude', 0)
        radius = kwargs.get('radius', 0)
        correlation = kwargs.get('correlation', 0)
        covariance = kwargs.get('covariance', 0)
        var_ratio = kwargs.get('var_ratio', 0)
        weight = kwargs.get('weight', 0)
        
        # Khởi tạo giá trị mặc định cho các trường không có trong packet_data
        for key in ['flow_byte', 'flow_duration', 'ack_count', 'syn_count', 'fin_count', 'urg_count', 'rst_count',
                   'max_duration', 'min_duration', 'sum_duration', 'avg_duration', 'std_duration', 
                   'idle_time', 'active_time', 'rate', 'srate', 'drate']:
            if key not in packet_data:
                packet_data[key] = 0
                
        # Cờ TCP mặc định nếu không có
        if 'flag_values' not in packet_data:
            packet_data['flag_values'] = [0] * 8
                
        # Khởi tạo các trường giao thức với giá trị mặc định là 0
        protocols = ['http', 'https', 'ssh', 'irc', 'smtp', 'mqtt', 'telnet', 'dhcp', 'dns', 'udp', 'tcp', 'arp', 'icmp', 'igmp', 'ipv', 'llc']
        for proto in protocols:
            if proto not in packet_data:
                packet_data[proto] = 0
                
        # Lấy giá trị wifi nếu có
        ds_status = kwargs.get('ds_status', 0)
        fragments = kwargs.get('fragments', 0)
        sequence = kwargs.get('sequence', 0)
        pack_id = kwargs.get('pack_id', 0)
        
        # Các biến khác
        mac = kwargs.get('mac', 0)
        rarp = kwargs.get('rarp', 0)
        src_byte_count = kwargs.get('src_byte_count', 0)
        dst_byte_count = kwargs.get('dst_byte_count', 0)
        
        # Tạo dòng dữ liệu mới
        new_row = {
            "ts": ts,
            "src_mac": src_mac,
            "dst_mac": dst_mac,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "ttl_value": ttl_value,
            'Protocol_Type': proto_type,
            "flow_duration": packet_data['flow_duration'],
            "flow_byte": packet_data['flow_byte'],
            "fin_flag_number": packet_data['flag_values'][0] if 'flag_values' in packet_data else 0,
            "syn_flag_number": packet_data['flag_values'][1] if 'flag_values' in packet_data else 0,
            "rst_flag_number": packet_data['flag_values'][2] if 'flag_values' in packet_data else 0,
            "psh_flag_number": packet_data['flag_values'][3] if 'flag_values' in packet_data else 0,
            "ack_flag_number": packet_data['flag_values'][4] if 'flag_values' in packet_data else 0,
            "urg_flag_number": packet_data['flag_values'][5] if 'flag_values' in packet_data else 0,
            "ece_flag_number": packet_data['flag_values'][6] if 'flag_values' in packet_data else 0,
            "cwr_flag_number": packet_data['flag_values'][7] if 'flag_values' in packet_data else 0,
            "src_ip_bytes": src_byte_count,
            "dst_ip_bytes": dst_byte_count,
            "Rate": packet_data['rate'],
            "Srate": packet_data['srate'],
            "Drate": packet_data['drate'],
            "ack_count": packet_data['ack_count'],
            "syn_count": packet_data['syn_count'],
            "fin_count": packet_data['fin_count'],
            "urg_count": packet_data['urg_count'],
            "rst_count": packet_data['rst_count'],
            "max_duration": packet_data['max_duration'],
            "min_duration": packet_data['min_duration'],
            "sum_duration": packet_data['sum_duration'],
            "average_duration": packet_data['avg_duration'],
            "std_duration": packet_data['std_duration'],
            "CoAP": packet_data.get('coap', 0),
            "HTTP": packet_data.get('http', 0),
            "HTTPS": packet_data.get('https', 0),
            "DNS": packet_data.get('dns', 0),
            "Telnet": packet_data.get('telnet', 0),
            "SMTP": packet_data.get('smtp', 0),
            "SSH": packet_data.get('ssh', 0),
            "IRC": packet_data.get('irc', 0),
            "TCP": packet_data.get('tcp', 0),
            "UDP": packet_data.get('udp', 0),
            "DHCP": packet_data.get('dhcp', 0),
            "ARP": packet_data.get('arp', 0),
            "ICMP": packet_data.get('icmp', 0),
            "IGMP": packet_data.get('igmp', 0),
            "IPv": packet_data.get('ipv', 0),
            "LLC": packet_data.get('llc', 0),
            "Tot_sum": sum_packets,
            "Min": min_packets,
            "Max": max_packets,
            "AVG": mean_packets,
            "Std": std_packets,
            "Tot_size": ethernet_frame_size,
            "IAT": iat,
            "Number": len(self.ethsize),
            "MAC": mac,
            "Magnitude": magnitude,
            "Radius": radius,
            "Covariance": covariance,
            "Variance": var_ratio,
            "Weight": weight,
            "Correlation": correlation,
            "RARP": rarp,
            "DS_status": ds_status,
            "Fragments": fragments,
            "Sequence_number": sequence,
            "Protocol_Version": pack_id,
            "flow_idle_time": packet_data['idle_time'],
            "flow_active_time": packet_data['active_time']
        }
        
        return new_row

    def save_to_csv(self, csv_file_name):
        """
        Lưu dữ liệu đã xử lý vào file CSV
        """
        try:
            processed_df = pd.DataFrame(self.base_row)
            processed_df.to_csv(csv_file_name + ".csv", index=False)
            logger.info(f"Successfully saved data to {csv_file_name}.csv")
            return True
        except Exception as e:
            logger.error(f"Error saving data to CSV: {e}")
            return False

    def pcap_evaluation(self, pcap_file, csv_file_name):
        """
        Hàm chính để đánh giá tệp PCAP và trích xuất các đặc trưng
        """
        start_time = time.time()
        logger.info(f"Starting to process PCAP file: {pcap_file}")
        
        # Khởi tạo các cấu trúc dữ liệu
        self.initialize_data_structures()
        
        try:
            # Mở file PCAP để đọc
            f = open(pcap_file, 'rb')
            pcap = dpkt.pcap.Reader(f)
            
            count = 0  # Đếm số lượng gói tin
            count_rows = 0  # Đếm số lượng hàng đã xử lý
            
            # Duyệt qua từng gói tin trong file PCAP
            for ts, buf in pcap:
                count += 1
                
                try:
                    # Giải mã gói tin Ethernet
                    eth = dpkt.ethernet.Ethernet(buf)
                except Exception as e:
                    logger.warning(f"Packet {count} cannot be parsed as Ethernet: {e}")
                    continue
                
                # Lấy địa chỉ MAC
                src_mac, dst_mac = self.process_mac_addresses(eth)
                
                # Cập nhật tổng thời gian
                ethernet_frame_size = len(eth)
                ethernet_frame_type = eth.type
                self.total_du += ts
                
                # Khởi tạo các biến cho gói tin hiện tại
                src_port, src_ip, dst_port, dst_ip = 0, 0, 0, 0
                ttl_value, proto_type, protocol_name = 0, 0, ""
                src_byte_count, dst_byte_count = 0, 0
                mac, rarp = 0, 0
                ds_status, fragments, sequence, pack_id = 0, 0, 0, 0
                
                # Xử lý loại gói tin
                if eth.type == dpkt.ethernet.ETH_TYPE_IP or eth.type == dpkt.ethernet.ETH_TYPE_ARP:
                    # Reset các cấu trúc dữ liệu sau mỗi batch
                    if len(self.ethsize) % self.batch_size == 0:
                        self.ethsize = []
                        self.ip_flow = {}
                        self.incoming_pack = []
                        self.outgoing_pack = []
                    
                    # Tính toán các đặc trưng động
                    sum_packets, min_packets, max_packets, mean_packets, std_packets, iat = self.process_dynamic_features(ethernet_frame_size, ts)
                    
                    # Lấy thông tin cơ bản về kết nối
                    con_basic = Connectivity_features_basic(eth.data)
                    src_ip = con_basic.get_source_ip()
                    dst_ip = con_basic.get_destination_ip()
                    
                    # Xử lý luồng IP
                    magnitude, radius, correlation, covariance, var_ratio, weight = self.process_ip_flow(src_ip, dst_ip, ethernet_frame_size)
                    
                    # Biến lưu trữ dữ liệu gói tin
                    packet_data = {}
                    
                    if eth.type == dpkt.ethernet.ETH_TYPE_IP:  # Gói tin IP
                        ip = eth.data
                        ipv = 1
                        
                        # Lấy thông tin cơ bản về kết nối
                        con_basic = Connectivity_features_basic(ip)
                        src_port = con_basic.get_source_port()
                        dst_port = con_basic.get_destination_port()
                        proto_type = con_basic.get_protocol_type()
                        
                        # Lấy thông tin thời gian kết nối
                        con_time = Connectivity_features_time(ip)
                        ttl_value = con_time.ttl()
                        potential_packet = ip.data
                        
                        # Lấy thông tin cờ và byte
                        conn_flags_bytes = Connectivity_features_flags_bytes(ip)
                        src_byte_count, dst_byte_count = conn_flags_bytes.count(self.src_ip_byte, self.dst_ip_byte)
                        
                        # Lấy thông tin lớp 3
                        l_three = L3(potential_packet)
                        udp = l_three.udp()
                        tcp = l_three.tcp()
                        
                        # Xác định tên protocol
                        protocol_name = get_protocol_name(proto_type)
                        icmp = 1 if protocol_name == "ICMP" else 0
                        igmp = 1 if protocol_name == "IGMP" else 0
                        
                        # Lấy thông tin lớp 1
                        l_one = L1(potential_packet)
                        llc = l_one.LLC()
                        mac = l_one.MAC()
                        
                        # Lấy thông tin lớp 4 cho cả UDP và TCP
                        l_four_both = L4(src_port, dst_port)
                        coap = l_four_both.coap()
                        smtp = l_four_both.smtp()
                        
                        # Xử lý gói tin UDP
                        if type(potential_packet) == dpkt.udp.UDP:
                            packet_data = self.process_udp_packet(eth, src_ip, dst_ip, src_port, dst_port, ts)
                            packet_data['udp'] = udp
                            packet_data['tcp'] = tcp
                            packet_data['coap'] = coap
                            packet_data['smtp'] = smtp
                            packet_data['flag_values'] = [0] * 8
                            
                        # Xử lý gói tin TCP
                        elif type(potential_packet) == dpkt.tcp.TCP:
                            packet_data = self.process_tcp_packet(eth, ip, src_ip, dst_ip, src_port, dst_port, ts)
                            packet_data['udp'] = udp
                            packet_data['tcp'] = tcp
                            packet_data['coap'] = coap
                            packet_data['smtp'] = smtp
                    
                    elif eth.type == dpkt.ethernet.ETH_TYPE_ARP:  # Gói tin ARP
                        arp = 1
                        packet_data = {'arp': arp, 'flag_values': [0] * 8}
                        
                    elif eth.type == dpkt.ieee80211:  # Gói tin WiFi
                        wifi_info = Communication_wifi(eth.data)
                        type_info, sub_type_info, ds_status, wifi_src_mac, wifi_dst_mac, sequence, pack_id, fragments, wifi_dur = wifi_info.calculating()
                        packet_data = {'flag_values': [0] * 8}
                        
                    elif eth.type == dpkt.ethernet.ETH_TYPE_REVARP:  # Gói tin RARP
                        rarp = 1
                        packet_data = {'rarp': rarp, 'flag_values': [0] * 8}
                    
                    # Chuẩn bị dữ liệu hàng
                    if not packet_data:
                        packet_data = {'flag_values': [0] * 8}
                        
                    new_row = self.prepare_row_data(
                        packet_data,
                        ts=ts,
                        src_mac=src_mac,
                        dst_mac=dst_mac,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=src_port,
                        dst_port=dst_port,
                        ttl_value=ttl_value,
                        proto_type=proto_type,
                        ethernet_frame_size=ethernet_frame_size,
                        sum_packets=sum_packets,
                        min_packets=min_packets,
                        max_packets=max_packets,
                        mean_packets=mean_packets,
                        std_packets=std_packets,
                        iat=iat,
                        magnitude=magnitude,
                        radius=radius,
                        correlation=correlation,
                        covariance=covariance,
                        var_ratio=var_ratio,
                        weight=weight,
                        mac=mac,
                        rarp=rarp,
                        src_byte_count=src_byte_count,
                        dst_byte_count=dst_byte_count,
                        ds_status=ds_status,
                        fragments=fragments,
                        sequence=sequence,
                        pack_id=pack_id
                    )
                    
                    # Thêm hàng vào base_row
                    for c in self.base_row.keys():
                        if c in new_row:
                            self.base_row[c].append(new_row[c])
                        else:
                            self.base_row[c].append(0)
                    
                    count_rows += 1
                
                # In tiến trình mỗi 10000 gói tin
                if count % 10000 == 0:
                    logger.info(f"Processed {count} packets, {count_rows} rows")
            
            # Đóng file
            f.close()
            
            # Lưu dữ liệu vào CSV
            self.save_to_csv(csv_file_name)
            
            end_time = time.time()
            logger.info(f"Finished processing {count} packets in {end_time - start_time:.2f} seconds")
            
            return True
            
        except Exception as e:
            logger.error(f"Error in pcap_evaluation: {e}")
            return False
