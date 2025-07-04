import dpkt
import pandas as pd
import json
from scapy.all import *
from Communication_features import Communication_wifi, Communication_zigbee
from Connectivity_features import Connectivity_features_basic, Connectivity_features_time, \
    Connectivity_features_flags_bytes
from Dynamic_features import Dynamic_features
from Layered_features import L3, L4, L2, L1
from Supporting_functions import get_protocol_name, get_flow_info, get_flag_values, compare_flow_flags, \
    get_src_dst_packets, calculate_incoming_connections, \
    calculate_packets_counts_per_ips_proto, calculate_packets_count_per_ports_proto
    
from tqdm import tqdm
import time

class Feature_extraction():
    # columns = ["ts","flow_duration","Header_Length",
    #           "Source IP","Destination IP","Source Port","Destination Port","Protocol Type","Protocol_name",
    #           "Duration","src_ip_bytes","dst_ip_bytes","src_pkts","dst_pkts", "Rate", "Srate", "Drate"
    #            ,"TNP_per_proto_tcp","TNP_per_proto_udp","fin_flag_number","syn_flag_number","rst_flag_number"
    #            ,"psh_flag_number","ack_flag_number","urg_flag_number","ece_flag_number","cwr_flag_number",
    #            "ack_count", "syn_count", "fin_count", "urg_count", "rst_count", 
              
    #            "max_duration","min_duration","sum_duration","average_duration","std_duration",
    #            "MQTT", "CoAP", "HTTP", "HTTPS", "DNS", "Telnet","SMTP", "SSH", "IRC", "TCP", "UDP", "DHCP","ARP", "ICMP", "IGMP", "IPv", "LLC",
    # "Tot sum", "Min", "Max", "AVG", "Std","Tot size", "IAT", "Number", "MAC", "Magnitue", "Radius", "Covariance", "Variance", "Weight",
    #            "Wifi_Type", "Wifi_Subtype", "DS status", "Fragments", "wifi_src", "wifi_dst", "Sequence number", "Protocol Version",
    #            "flow_idle_time", "flow_active_time"

    # ]
    
    
    def pcap_evaluation(self,pcap_file,csv_file_name):
        global ethsize, src_ports, dst_ports, src_ips, dst_ips, ips , tcpflows, udpflows, src_packet_count, dst_packet_count, src_ip_byte, dst_ip_byte
        global protcols_count, tcp_flow_flgs, incoming_packets_src, incoming_packets_dst, packets_per_protocol, average_per_proto_src
        global average_per_proto_dst, average_per_proto_src_port, average_per_proto_dst_port
        
        columns = [
            "ts","flow_duration","flow_byte",

            "src_mac", "dst_mac", "src_ip", "dst_ip", "src_port", "dst_port",

            "Protocol Type",
            "Duration",

            "Rate", "Srate", "Drate"
            ,"fin_flag_number","syn_flag_number","rst_flag_number"
            ,"psh_flag_number","ack_flag_number","urg_flag_number","ece_flag_number","cwr_flag_number",
            "ack_count", "syn_count", "fin_count", "urg_count", "rst_count",

            "max_duration","min_duration","sum_duration","average_duration","std_duration",

            "CoAP", "HTTP", "HTTPS", "DNS", "Telnet","SMTP", "SSH", "IRC", "TCP", "UDP", "DHCP","ARP", "ICMP", "IGMP", "IPv", "LLC",
            "Tot sum", "Min", "Max", "AVG", "Std","Tot size", "IAT", "Number", "MAC", "Magnitue", "Radius", "Covariance", "Variance", "Weight",

            "DS status", "Fragments",

            "Sequence number", "Protocol Version",
            "flow_idle_time", "flow_active_time"
        ]

        base_row = {c:[] for c in columns}
        ip_flow = {}
        ethsize = []
        src_ports = {}  # saving the number of source port used
        dst_ports = {}  # saving the number of destination port used
        tcpflows = {}  # saving the whole tcpflows
        udpflows = {}  # saving the whole udpflows
        src_packet_count = {}  # saving the number of packets per source IP
        dst_packet_count = {}  # saving the number of packets per destination IP
        dst_port_packet_count = {}  # saving the number of packets per destination port
        src_ip_byte, dst_ip_byte = {}, {}
        tcp_flow_flags = {}  # saving the number of flags for each flow
        packets_per_protocol = {}   # saving the number of packets per protocol
        average_per_proto_src = {}  # saving the number of packets per protocol and src_ip
        average_per_proto_dst = {}  # saving the number of packets per protocol and dst_ip
        average_per_proto_src_port, average_per_proto_dst_port = {}, {}    # saving the number of packets per protocol and src_port and dst_port
        ips = set()  # saving unique IPs
        number_of_packets_per_trabsaction = 0  # saving the number of packets per transaction
        rate, srate, drate = 0, 0, 0
        max_duration, min_duration, sum_duration, average_duration, std_duration = 0, 0, 0, 0, 0   # duration-related features of aggerated records
        total_du = 0
        first_pac_time = 0
        last_pac_time = 0
        incoming_pack = []
        outgoing_pack = []
        
        f = open(pcap_file, 'rb')
        pcap = dpkt.pcap.Reader(f)
        ## Using SCAPY for Zigbee and blutooth ##
        # scapy_pak = rdpcap(pcap_file)
        
        count = 0  # counting the packets
        count_rows = 0
        
        for ts, buf in (pcap):
            # if type(scapy_pak[count]) == scapy.layers.bluetooth:
            #     pass
            # elif type(scapy_pak[count]) == scapy.layers.zigbee.ZigbeeNWKCommandPayload:
            #     zigbee = Communication_zigbee(scapy_pak[count])
            
            count = count + 1
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except:
                continue  # If packet format is not readable by dpkt, discard the packet
            
            # Get MAC address
            src_mac = ':'.join('%02x' % b for b in eth.src)
            dst_mac = ':'.join('%02x' % b for b in eth.dst)

            ethernet_frame_size = len(eth)
            ethernet_frame_type = eth.type
            total_du = total_du + ts
            # initilization #
            src_port, src_ip, dst_port, dst_ip = 0, 0, 0, 0
            duration, proto_type, protocol_name = 0, 0, ""
            flow_duration, flow_byte = 0, 0
            src_byte_count, dst_byte_count = 0, 0
            src_pkts, dst_pkts = 0, 0
            connection_status = 0
            number = 0
            IAT = 0
            src_to_dst_pkt, dst_to_src_pkt = 0, 0  # count of packets from src to des and vice-versa
            src_to_dst_byte, dst_to_src_byte = 0, 0  # Total bytes of packets from src to dst and vice-versa
            # flags
            flag_valus = []  # numerical values of packet(TCP) flags
            ack_count, syn_count, fin_count, urg_count, rst_count = 0, 0, 0, 0, 0
            # Layered flags
            udp, tcp, http, https, arp, smtp, irc, ssh, dns, ipv, icmp, igmp, mqtt, coap = 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            telnet, dhcp, llc, mac, rarp = 0, 0, 0, 0, 0
            sum_packets, min_packets, max_packets, mean_packets, std_packets = 0, 0, 0, 0, 0
            magnite, radius, correlation, covaraince, var_ratio, weight = 0, 0, 0, 0, 0, 0
            idle_time, active_time = 0, 0
            type_info, sub_type_info, ds_status, sequence, pack_id, fragments, wifi_dur = 0, 0, 0, 0, 0, 0, 0
            
            if eth.type == dpkt.ethernet.ETH_TYPE_IP or eth.type == dpkt.ethernet.ETH_TYPE_ARP:
                if len(ethsize) % 20 == 0:
                    ethsize = []
                    ip_flow = {}
                    incoming_pack = []
                    outgoing_pack = []

                dy = Dynamic_features()
                ethsize.append(ethernet_frame_size)
                
                sum_packets, min_packets, max_packets, mean_packets, std_packets = dy.dynamic_calculation(ethsize)
                
                last_pac_time = ts
                IAT = last_pac_time - first_pac_time
                first_pac_time = last_pac_time

                con_basic = Connectivity_features_basic(eth.data)
                src_ip = con_basic.get_source_ip()
                dst_ip = con_basic.get_destination_ip()

                if dst_ip in ip_flow and ip_flow[dst_ip] == src_ip:
                    outgoing_pack.append(ethernet_frame_size)
                else:
                    incoming_pack.append(ethernet_frame_size)
                    ip_flow[src_ip] = dst_ip

                magnite, radius, correlation, covaraince, var_ratio, weight = dy.dynamic_two_streams(incoming_pack, outgoing_pack)                
                
                if eth.type == dpkt.ethernet.ETH_TYPE_IP:     # IP packets
                    # print("IP packet")
                    ipv = 1
                    ip = eth.data
                    con_basic = Connectivity_features_basic(ip)

                    #Dynamic_packets
                    # dy = Dynamic_features()
                    # number = dy.dynamic_count(protcols_count)  # need to ask information about it


                    # Connectivity_basic_features
                    src_port = con_basic.get_source_port()
                    dst_port = con_basic.get_destination_port()

                    proto_type = con_basic.get_protocol_type()

                    # ips.add(dst_ip)
                    # ips.add(src_ip)

                    # Connectivity_time_features
                    con_time = Connectivity_features_time(ip)
                    duration = con_time.duration()
                    potential_packet = ip.data

                    # Connectivity_features_flags_bytes
                    conn_flags_bytes = Connectivity_features_flags_bytes(ip)
                    src_byte_count, dst_byte_count = conn_flags_bytes.count(src_ip_byte, dst_ip_byte)

                    # L_three_layered_features
                    l_three = L3(potential_packet)
                    udp = l_three.udp()
                    tcp = l_three.tcp()

                    protocol_name = get_protocol_name(proto_type)
                    if protocol_name == "ICMP":
                        icmp = 1
                    elif protocol_name == "IGMP":
                        igmp = 1
                    # L1_features
                    l_one = L1(potential_packet)
                    llc = l_one.LLC()
                    mac = l_one.MAC()


                    # Extra features of Bot-IoT and Ton-IoT

                    # Average rate features
                    # calculate_packets_counts_per_ips_proto(average_per_proto_src, protocol_name, src_ip, average_per_proto_dst, dst_ip)
                    # calculate_packets_count_per_ports_proto(average_per_proto_src_port, average_per_proto_dst_port, protocol_name, src_port, dst_port)
                    #----end of Average rate features ---#

                    # if packets_per_protocol.get(protocol_name):
                    #     packets_per_protocol[protocol_name] = packets_per_protocol[protocol_name] + 1
                    # else:
                    #     packets_per_protocol[protocol_name] = 1

                    # if protocol_name in protcols_count.keys():
                    #     protcols_count[protocol_name] = protcols_count[protocol_name] + 1
                    # else:
                    #     protcols_count[protocol_name] = 1



                    # if src_ip not in src_packet_count.keys():
                    #     src_packet_count[src_ip] = 1
                    # else:
                    #     src_packet_count[src_ip] = src_packet_count[src_ip] + 1


                    # if dst_ip not in dst_packet_count.keys():
                    #     dst_packet_count[dst_ip] = 1
                    # else:
                    #     dst_packet_count[dst_ip] = dst_packet_count[dst_ip] + 1

                    # src_pkts, dst_pkts = src_packet_count[src_ip], dst_packet_count[dst_ip]
                    l_four_both = L4(src_port, dst_port)
                    coap = l_four_both.coap()
                    smtp = l_four_both.smtp()


                    # Features related to UDP
                    if type(potential_packet) == dpkt.udp.UDP:
                        # L4 features
                        l_four = L4(src_port, dst_port)
                        l_two = L2(src_port, dst_port)
                        dhcp = l_two.dhcp()
                        dns = l_four.dns()
                        if dst_port in dst_port_packet_count.keys():
                            dst_packet_count[dst_port] = dst_port_packet_count[dst_port] + 1
                        else:
                            dst_packet_count[dst_port] = 1

                        flow = sorted([(src_ip, src_port), (dst_ip, dst_port)])
                        flow = (flow[0], flow[1])
                        flow_data = {
                            'byte_count': len(eth),
                            'ts': ts
                        }
                        if udpflows.get(flow):
                            udpflows[flow].append(flow_data)
                        else:
                            udpflows[flow] = [flow_data]
                        packets = udpflows[flow]
                        number_of_packets_per_trabsaction = len(packets)
                        flow_byte, flow_duration, max_duration, min_duration, sum_duration, average_duration, std_duration, idle_time,active_time = get_flow_info(udpflows,flow)
                        src_to_dst_pkt, dst_to_src_pkt, src_to_dst_byte, dst_to_src_byte = get_src_dst_packets(udpflows, flow)
                    
                    
                    
                    # Features related to TCP
                    elif type(potential_packet) == dpkt.tcp.TCP:
                        # if dst_port in dst_port_packet_count.keys():
                        #     dst_packet_count[dst_port] = dst_port_packet_count[dst_port] + 1
                        # else:
                        #     dst_packet_count[dst_port] = 1

                        flag_valus = get_flag_values(ip.data)
                        # L4 features based on TCP
                        l_four = L4(src_port,dst_port)
                        http = l_four.http()
                        https = l_four.https()
                        ssh = l_four.ssh()
                        irc = l_four.IRC()
                        smtp = l_four.smtp()
                        mqtt = l_four.mqtt()
                        telnet = l_four.telnet()

                        try:
                            http_info = dpkt.http.Response(ip.data)
                            connection_status = http_info.status
                        except:
                            # print("No status")
                            connection_status = 0


                        flow = sorted([(src_ip, src_port), (dst_ip, dst_port)])
                        flow = (flow[0], flow[1])
                        flow_data = {
                            'byte_count': len(eth),
                            'ts': ts
                        }
                        if tcpflows.get(flow):
                            tcpflows[flow].append(flow_data)
                            # comparing Flow state based on its flags
                            ack_count, syn_count, fin_count, urg_count, rst_count = tcp_flow_flags[flow]
                            ack_count,syn_count,fin_count,urg_count,rst_count = compare_flow_flags(flag_valus,ack_count,syn_count,fin_count,urg_count,rst_count)
                            tcp_flow_flags[flow] = [ack_count, syn_count, fin_count, urg_count, rst_count]
                        else:
                            tcpflows[flow] = [flow_data]
                            ack_count,syn_count,fin_count,urg_count,rst_count = compare_flow_flags(flag_valus, ack_count, syn_count, fin_count, urg_count, rst_count)
                            tcp_flow_flags[flow] = [ack_count,syn_count,fin_count,urg_count,rst_count]

                        packets = tcpflows[flow]
                        number_of_packets_per_trabsaction = len(packets)
                        flow_byte, flow_duration,max_duration,min_duration,sum_duration,average_duration,std_duration,idle_time,active_time = get_flow_info(tcpflows,flow)
                        src_to_dst_pkt, dst_to_src_pkt, src_to_dst_byte, dst_to_src_byte = get_src_dst_packets(tcpflows, flow)

                    # calculate_incoming_connections(incoming_packets_src, incoming_packets_dst, src_port, dst_port, src_ip, dst_ip)
                    if flow_duration != 0:
                        rate = number_of_packets_per_trabsaction / flow_duration
                        srate = src_to_dst_pkt / flow_duration
                        drate = dst_to_src_pkt / flow_duration

                    if dst_port_packet_count.get(dst_port):
                        dst_port_packet_count[dst_port] = dst_port_packet_count[dst_port] + 1
                    else:
                        dst_port_packet_count[dst_port] = 1

                elif eth.type == dpkt.ethernet.ETH_TYPE_ARP:   # ARP packets
                    # print("ARP packet")
                    # protocol_name = "ARP"
                    arp = 1
                    # if packets_per_protocol.get(protocol_name):
                    #     packets_per_protocol[protocol_name] = packets_per_protocol[protocol_name] + 1
                    # else:
                    #     packets_per_protocol[protocol_name] = 1


                    # calculate_packets_counts_per_ips_proto(average_per_proto_src, protocol_name, src_ip, average_per_proto_dst,
                    #                           dst_ip)

                elif eth.type == dpkt.ieee80211:   # Wifi packets
                    wifi_info = Communication_wifi(eth.data)
                    type_info, sub_type_info, ds_status, src_mac, dst_mac, sequence, pack_id, fragments,wifi_dur = wifi_info.calculating()
                    # print("Wifi related")
                elif eth.type == dpkt.ethernet.ETH_TYPE_REVARP:  # RARP packets
                    rarp = 1   # Reverce of ARP

                # Average rate features
                # for key in average_per_proto_src:
                #     AR_P_Proto_P_SrcIP[key] = average_per_proto_src[key] / total_du

                # for key in average_per_proto_dst:
                #     AR_P_Proto_P_Dst_IP[key] = average_per_proto_dst[key] / total_du

                # for key in average_per_proto_src_port:
                #     ar_p_proto_p_src_sport[key] = average_per_proto_src_port[key] / total_du

                # for key in average_per_proto_dst_port:
                #     ar_p_proto_p_dst_dport[key] = average_per_proto_dst_port[key] / total_du

                # end of average rate features
                if len(flag_valus) == 0:
                    for i in range(0,8):
                        flag_valus.append(0)

                
                new_row = {"ts": ts,
                            "src_mac": src_mac,
                            "dst_mac": dst_mac,
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "src_port": src_port,
                            "dst_port": dst_port,
                            "Duration": duration,
                            'Protocol Type': proto_type,
                            "flow_duration": flow_duration,
                            "flow_byte": flow_byte,
                            "src_ip_bytes": src_byte_count,
                            "fin_flag_number": flag_valus[0],
                            "syn_flag_number":flag_valus[1],
                            "rst_flag_number":flag_valus[2],
                            "psh_flag_number": flag_valus[3],
                            "ack_flag_number": flag_valus[4],
                            "urg_flag_number": flag_valus[5],
                            "ece_flag_number":flag_valus[6],
                            "cwr_flag_number":flag_valus[7],
                            "dst_ip_bytes": dst_byte_count,
                            "Rate": rate,
                            "Srate": srate,
                            "Drate": drate,
                            "ack_count":ack_count,
                            "syn_count":syn_count,
                            "fin_count": fin_count,
                            "urg_count": urg_count,
                            "rst_count": rst_count,
                            "max_duration": max_duration,
                            "min_duration": min_duration,
                            "sum_duration": sum_duration,
                            "average_duration": average_duration,
                            "std_duration": std_duration,
                            "CoAP": coap,
                            "HTTP": http,
                            "HTTPS": https,
                            "DNS": dns,
                            "Telnet":telnet,
                            "SMTP": smtp,
                            "SSH": ssh,
                            "IRC": irc,
                            "TCP": tcp,
                            "UDP": udp,
                            "DHCP": dhcp,
                            "ARP": arp,
                            "ICMP": icmp,
                            "IGMP": igmp,
                            "IPv": ipv,
                            "LLC": llc,
                            "Tot sum":sum_packets,
                            "Min": min_packets,
                            "Max": max_packets,
                            "AVG": mean_packets,
                            "Std": std_packets,
                            "Tot size": ethernet_frame_size,
                            "IAT": IAT,
                            "Number": len(ethsize),
                            "MAC": mac,
                            "Magnitue": magnite,
                            "Radius":radius,
                            "Covariance":covaraince,
                            "Variance":var_ratio,
                            "Weight": weight,
                            "Correlation": correlation,
                            "RARP": rarp,
                            "DS status":ds_status,
                            "Fragments":fragments,
                            "Sequence number":sequence,
                            "Protocol Version": pack_id,
                            "flow_idle_time":idle_time,
                            "flow_active_time":active_time}
                for c in base_row.keys():
                    base_row[c].append(new_row[c])

                count_rows+=1



        processed_df = pd.DataFrame(base_row)
        processed_df.to_csv(csv_file_name+".csv", index=False)

        return True
    
    def pcap_evaluation_realtime(self, packet_buffer, flow_info=None):
        """
        Evaluate a single packet in real-time and extract features
        
        Parameters:
        - packet_buffer: Raw packet bytes (from scapy's bytes() conversion)
        - flow_info: Dictionary to maintain flow state across packets (optional)
        
        Returns:
        - List of extracted features
        """
        columns = [
            "ts","flow_duration","flow_byte",
            "src_mac", "dst_mac", "src_ip", "dst_ip", "src_port", "dst_port",
            "Protocol Type", "Duration",
            "Rate", "Srate", "Drate",
            "fin_flag_number","syn_flag_number","rst_flag_number",
            "psh_flag_number","ack_flag_number","urg_flag_number","ece_flag_number","cwr_flag_number",
            "ack_count", "syn_count", "fin_count", "urg_count", "rst_count",
            "max_duration","min_duration","sum_duration","average_duration","std_duration",
            "CoAP", "HTTP", "HTTPS", "DNS", "Telnet","SMTP", "SSH", "IRC", "TCP", "UDP", "DHCP","ARP", "ICMP", "IGMP", "IPv", "LLC",
            "Tot sum", "Min", "Max", "AVG", "Std","Tot size", "IAT", "Number", "MAC", "Magnitue", "Radius", "Covariance", "Variance", "Weight",
            "DS status", "Fragments",
            "Sequence number", "Protocol Version",
            "flow_idle_time", "flow_active_time"
        ]
        
        # Initialize flow tracking if not provided
        if flow_info is None:
            flow_info = {}
        
        # Get shared flow information or create new
        tcpflows = flow_info.get('tcpflows', {})
        udpflows = flow_info.get('udpflows', {})
        ip_flow = flow_info.get('ip_flow', {})
        ethsize = flow_info.get('ethsize', [])
        tcp_flow_flags = flow_info.get('tcp_flow_flags', {})
        incoming_pack = flow_info.get('incoming_pack', [])
        outgoing_pack = flow_info.get('outgoing_pack', [])
        
        ts = time.time()
        try:
            eth = dpkt.ethernet.Ethernet(packet_buffer)
        except Exception as e:
            print(f"Error parsing packet: {e}")
            return None
            
        # Initialize default values
        src_port, src_ip, dst_port, dst_ip = 0, 0, 0, 0
        duration, proto_type, protocol_name = 0, 0, ""
        flow_duration, flow_byte = 0, 0
        rate, srate, drate = 0, 0, 0
        max_duration, min_duration, sum_duration, average_duration, std_duration = 0, 0, 0, 0, 0
        total_du = 0
        first_pac_time = flow_info.get('first_pac_time', 0)
        last_pac_time = flow_info.get('last_pac_time', 0)
        
        # Get MAC address
        src_mac = ':'.join('%02x' % b for b in eth.src)
        dst_mac = ':'.join('%02x' % b for b in eth.dst)
        
        ethernet_frame_size = len(eth)
        ethernet_frame_type = eth.type
        total_du = total_du + ts
        
        # Initialize feature flags
        flag_valus = [0] * 8  # numerical values of packet(TCP) flags
        ack_count, syn_count, fin_count, urg_count, rst_count = 0, 0, 0, 0, 0
        
        # Layered flags
        udp, tcp, http, https, arp, smtp, irc, ssh, dns, ipv, icmp, igmp, mqtt, coap = 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        telnet, dhcp, llc, mac, rarp = 0, 0, 0, 0, 0
        sum_packets, min_packets, max_packets, mean_packets, std_packets = 0, 0, 0, 0, 0
        magnite, radius, correlation, covaraince, var_ratio, weight = 0, 0, 0, 0, 0, 0
        idle_time, active_time = 0, 0
        type_info, sub_type_info, ds_status, sequence, pack_id, fragments, wifi_dur = 0, 0, 0, 0, 0, 0, 0
        
        if eth.type == dpkt.ethernet.ETH_TYPE_IP or eth.type == dpkt.ethernet.ETH_TYPE_ARP:
            if len(ethsize) % 20 == 0:
                ethsize = []
                ip_flow = {}
                incoming_pack = []
                outgoing_pack = []
            
            dy = Dynamic_features()
            ethsize.append(ethernet_frame_size)
            
            sum_packets, min_packets, max_packets, mean_packets, std_packets = dy.dynamic_calculation(ethsize)
            
            last_pac_time = ts
            IAT = last_pac_time - first_pac_time if first_pac_time > 0 else 0
            first_pac_time = last_pac_time if first_pac_time == 0 else first_pac_time
            
            # Process IP packets
            if eth.type == dpkt.ethernet.ETH_TYPE_IP:
                ipv = 1
                ip = eth.data
                con_basic = Connectivity_features_basic(ip)
                
                # Connectivity_basic_features
                try:
                    src_ip = con_basic.get_source_ip()
                    dst_ip = con_basic.get_destination_ip()
                    src_port = con_basic.get_source_port()
                    dst_port = con_basic.get_destination_port()
                    proto_type = con_basic.get_protocol_type()
                except:
                    pass
                
                if dst_ip in ip_flow and ip_flow[dst_ip] == src_ip:
                    outgoing_pack.append(ethernet_frame_size)
                else:
                    incoming_pack.append(ethernet_frame_size)
                    ip_flow[src_ip] = dst_ip
                
                magnite, radius, correlation, covaraince, var_ratio, weight = dy.dynamic_two_streams(incoming_pack, outgoing_pack)
                
                # Connectivity_time_features
                con_time = Connectivity_features_time(ip)
                duration = con_time.duration()
                potential_packet = ip.data
                
                # Connectivity_features_flags_bytes
                conn_flags_bytes = Connectivity_features_flags_bytes(ip)
                src_byte_count, dst_byte_count = conn_flags_bytes.count({}, {})
                
                # L_three_layered_features
                l_three = L3(potential_packet)
                udp = l_three.udp()
                tcp = l_three.tcp()
                
                protocol_name = get_protocol_name(proto_type)
                if protocol_name == "ICMP":
                    icmp = 1
                elif protocol_name == "IGMP":
                    igmp = 1
                
                # L1_features
                l_one = L1(potential_packet)
                llc = l_one.LLC()
                mac = l_one.MAC()
                
                l_four_both = L4(src_port, dst_port)
                coap = l_four_both.coap()
                smtp = l_four_both.smtp()
                
                # Features related to UDP
                if type(potential_packet) == dpkt.udp.UDP:
                    # L4 features
                    l_four = L4(src_port, dst_port)
                    l_two = L2(src_port, dst_port)
                    dhcp = l_two.dhcp()
                    dns = l_four.dns()
                    
                    flow = sorted([(src_ip, src_port), (dst_ip, dst_port)])
                    flow = (flow[0], flow[1])
                    flow_data = {
                        'byte_count': len(eth),
                        'ts': ts
                    }
                    
                    if flow in udpflows:
                        udpflows[flow].append(flow_data)
                    else:
                        udpflows[flow] = [flow_data]
                    
                    packets = udpflows[flow]
                    number_of_packets_per_trabsaction = len(packets)
                    flow_byte, flow_duration, max_duration, min_duration, sum_duration, average_duration, std_duration, idle_time, active_time = get_flow_info(udpflows, flow)
                    src_to_dst_pkt, dst_to_src_pkt, src_to_dst_byte, dst_to_src_byte = get_src_dst_packets(udpflows, flow)
                
                # Features related to TCP
                elif type(potential_packet) == dpkt.tcp.TCP:
                    flag_valus = get_flag_values(ip.data)
                    
                    # L4 features based on TCP
                    l_four = L4(src_port, dst_port)
                    http = l_four.http()
                    https = l_four.https()
                    ssh = l_four.ssh()
                    irc = l_four.IRC()
                    smtp = l_four.smtp()
                    mqtt = l_four.mqtt()
                    telnet = l_four.telnet()
                    
                    try:
                        http_info = dpkt.http.Response(ip.data)
                        connection_status = http_info.status
                    except:
                        connection_status = 0
                    
                    flow = sorted([(src_ip, src_port), (dst_ip, dst_port)])
                    flow = (flow[0], flow[1])
                    flow_data = {
                        'byte_count': len(eth),
                        'ts': ts
                    }
                    
                    if flow in tcpflows:
                        tcpflows[flow].append(flow_data)
                        # comparing Flow state based on its flags
                        if flow in tcp_flow_flags:
                            ack_count, syn_count, fin_count, urg_count, rst_count = tcp_flow_flags[flow]
                            ack_count, syn_count, fin_count, urg_count, rst_count = compare_flow_flags(flag_valus, ack_count, syn_count, fin_count, urg_count, rst_count)
                            tcp_flow_flags[flow] = [ack_count, syn_count, fin_count, urg_count, rst_count]
                    else:
                        tcpflows[flow] = [flow_data]
                        ack_count, syn_count, fin_count, urg_count, rst_count = compare_flow_flags(flag_valus, ack_count, syn_count, fin_count, urg_count, rst_count)
                        tcp_flow_flags[flow] = [ack_count, syn_count, fin_count, urg_count, rst_count]
                    
                    packets = tcpflows[flow]
                    number_of_packets_per_trabsaction = len(packets)
                    flow_byte, flow_duration, max_duration, min_duration, sum_duration, average_duration, std_duration, idle_time, active_time = get_flow_info(tcpflows, flow)
                    src_to_dst_pkt, dst_to_src_pkt, src_to_dst_byte, dst_to_src_byte = get_src_dst_packets(tcpflows, flow)
                
                if flow_duration != 0:
                    rate = number_of_packets_per_trabsaction / flow_duration
                    srate = src_to_dst_pkt / flow_duration
                    drate = dst_to_src_pkt / flow_duration
            
            # Process ARP packets
            elif eth.type == dpkt.ethernet.ETH_TYPE_ARP:
                arp = 1
                # Use default values since ARP doesn't have IP/port
            
            # Process WiFi packets    
            elif eth.type == dpkt.ieee80211:
                try:
                    wifi_info = Communication_wifi(eth.data)
                    type_info, sub_type_info, ds_status, src_mac, dst_mac, sequence, pack_id, fragments, wifi_dur = wifi_info.calculating()
                except:
                    pass
            
            # Process RARP packets
            elif eth.type == dpkt.ethernet.ETH_TYPE_REVARP:
                rarp = 1

            # DEBUG
            # protocol_name_str = get_protocol_name(proto_type)
            # if protocol_name_str != "TCP" and protocol_name_str != "UDP":
            # print(f'{protocol_name_str}: {src_ip}:{src_port} -> {dst_ip}:{dst_port}, {src_mac}->{dst_mac}')

            # Features
            new_row = [
                ts,
                flow_duration,
                flow_byte,
                src_mac,
                dst_mac,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                proto_type,
                duration,
                rate,
                srate,
                drate,
                flag_valus[0],
                flag_valus[1],
                flag_valus[2],
                flag_valus[3],
                flag_valus[4],
                flag_valus[5],
                flag_valus[6],
                flag_valus[7],
                ack_count,
                syn_count,
                fin_count,
                urg_count,
                rst_count,
                max_duration,
                min_duration,
                sum_duration,
                average_duration,
                std_duration,
                coap,
                http,
                https,
                dns,
                telnet,
                smtp,
                ssh,
                irc,
                tcp,
                udp,
                dhcp,
                arp,
                icmp,
                igmp,
                ipv,
                llc,
                sum_packets,
                min_packets,
                max_packets,
                mean_packets,
                std_packets,
                ethernet_frame_size,
                IAT,
                len(ethsize),
                mac,
                magnite,
                radius,
                covaraince,
                var_ratio,
                weight,
                correlation,  # Added missing correlation feature
                ds_status,
                fragments,
                sequence,
                idle_time,
                active_time,
            ]
            
            # Update flow_info with current state
            flow_info.update({
                'tcpflows': tcpflows,
                'udpflows': udpflows,
                'ip_flow': ip_flow,
                'ethsize': ethsize,
                'tcp_flow_flags': tcp_flow_flags,
                'incoming_pack': incoming_pack,
                'outgoing_pack': outgoing_pack,
                'first_pac_time': first_pac_time,
                'last_pac_time': last_pac_time
            })
            
            return new_row
        
        return None


