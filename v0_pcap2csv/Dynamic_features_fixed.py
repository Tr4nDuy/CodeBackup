# filepath: c:\Users\ADMIN\Desktop\CodeBackup\v0_pcap2csv\Dynamic_features.py
import numpy as np
import itertools
from scipy import stats

class Dynamic_features:
    def dynamic_calculation(self, ethsize):
        """
        Tính toán các đặc trưng thống kê cơ bản từ danh sách kích thước frame
        
        :param ethsize: Danh sách kích thước các frame Ethernet
        :return: sum, min, max, mean, std
        """
        sum_packets = sum(ethsize)
        min_packets = min(ethsize)
        max_packets = max(ethsize)
        mean_packets = sum_packets / len(ethsize)
        std_packets = np.std(ethsize)

        return sum_packets, min_packets, max_packets, mean_packets, std_packets

    def dynamic_count(self, protcols_count):
        """
        Tính tổng số gói tin theo protocol
        
        :param protcols_count: Dictionary đếm số lượng gói tin theo protocol
        :return: Tổng số gói tin
        """
        packets = 0
        for k in protcols_count.keys():
            packets = packets + protcols_count[k]

        return packets

    def dynamic_two_streams(self, incoming, outgoing):
        """
        Tính toán các đặc trưng dựa trên hai luồng gói tin (vào/ra)
        
        :param incoming: Danh sách kích thước các gói tin vào
        :param outgoing: Danh sách kích thước các gói tin ra
        :return: magnitude, radius, correlation, covariance, var_ratio, weight
        """
        # Xử lý trường hợp incoming rỗng
        if len(incoming) == 0:
            inco_ave = inco_var = 0
        else:
            inco_ave = np.mean(incoming)
            inco_var = np.var(incoming)

        # Xử lý trường hợp outgoing rỗng
        if len(outgoing) == 0:
            outgoing_ave = outgo_var = 0
        else:
            outgoing_ave = np.mean(outgoing)
            outgo_var = np.var(outgoing)

        # Tính magnitude - căn bậc hai của tổng bình phương các giá trị trung bình
        magnite = (inco_ave + outgoing_ave) ** 0.5

        # Tính radius - căn bậc hai của tổng bình phương các phương sai
        radius = (inco_var + outgo_var) ** 0.5
        
        # Tính correlation chỉ khi cả hai luồng có dữ liệu và cùng độ dài
        correlation = 0
        try:
            if len(incoming) == len(outgoing) and len(incoming) >= 2:
                correlation, _ = stats.pearsonr(incoming, outgoing)
        except Exception:
            correlation = 0

        # Tính covariance
        covaraince = 0
        try:
            if len(incoming) > 0 and len(outgoing) > 0 and len(incoming) == len(outgoing):
                covaraince = sum((a - inco_ave) * (b - outgoing_ave) for (a, b) in zip(incoming, outgoing)) / len(incoming)
        except Exception:
            covaraince = 0
            
        # Tính tỷ lệ phương sai
        var_ratio = 0
        try:
            if outgo_var != 0:
                var_ratio = inco_var / outgo_var
        except Exception:
            var_ratio = 0

        # Tính weight - tích của số lượng gói tin
        weight = len(incoming) * len(outgoing) if len(incoming) > 0 and len(outgoing) > 0 else 0

        return magnite, radius, correlation, covaraince, var_ratio, weight
