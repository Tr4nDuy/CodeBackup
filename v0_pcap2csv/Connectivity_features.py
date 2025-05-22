from Supporting_functions import ip_to_str


class Connectivity_features_basic:
    def __init__(self,packet):
        self.packet = packet

    def get_source_ip(self):
        try:
            return ip_to_str(self.packet.src)
        except:
            return None
        
    def get_destination_ip(self):
        try:
            return ip_to_str(self.packet.dst)
        except:
            return None

    def get_source_port(self):
        try:
            return self.packet.data.sport
        except:
            return None

    def get_destination_port(self):
        try:
            return self.packet.data.dport
        except:
            return None

    def get_protocol_type(self):
        return self.packet.p

class Connectivity_features_time:
    def __init__(self,packet):
        self.packet = packet
    def ttl(self):
        """
        Return the Time-to-Live (TTL) value of the packet. 
        This is not related to duration but rather to the hop limit of the packet.
        """
        return self.packet.ttl
        
    def duration(self):
        """
        Deprecated: This function misleadingly returns TTL value, not actual duration.
        Use ttl() instead for correctness.
        """
        # For backward compatibility
        return self.ttl()

    def jitter(self):
        pass

    def inter_arrival_time(self):
        pass

    def active_time(self):
        pass

    def idle_time(self):
        pass

class Connectivity_features_flags_bytes:
    def __init__(self,packet):
        self.packet = packet
    def get_flags_count(self):
        pass

    def count(self,src_ip_byte, dst_ip_byte):
        if self.packet.src not in src_ip_byte.keys():
            src_ip_byte[self.packet.src] = 1
        else:
            src_ip_byte[self.packet.src] = src_ip_byte[self.packet.src] + 1

        if self.packet.dst not in dst_ip_byte.keys():
            dst_ip_byte[self.packet.dst] = 1
        else:
            dst_ip_byte[self.packet.dst] = dst_ip_byte[self.packet.dst] + 1
            

        return src_ip_byte[self.packet.src], dst_ip_byte[self.packet.dst]