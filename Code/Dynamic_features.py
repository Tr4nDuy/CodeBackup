import numpy as np
import itertools
from scipy import stats

class Dynamic_features:
    def dynamic_calculation(self,ethsize):
        sum_packets = sum(ethsize)
        min_packets = min(ethsize)
        max_packets = max(ethsize)
        mean_packets = sum_packets / len(ethsize)
        std_packets = np.std(ethsize)

        return sum_packets,min_packets,max_packets,mean_packets,std_packets

    def dynamic_count(self,protcols_count):   #calculates the Number feature
        packets = 0
        for k in protcols_count.keys():
            packets = packets + protcols_count[k]

        return packets

    def dynamic_two_streams(self, incoming, outgoing):
        # Filter out None values from incoming and outgoing lists
        incoming = [x for x in incoming if x is not None]
        outgoing = [x for x in outgoing if x is not None]
        
        if len(incoming) == 0:
            inco_ave = inco_var = 0
        else:
            inco_ave = np.mean(incoming)
            inco_var = np.var(incoming)

        if len(outgoing) == 0:
            outgoing_ave = outgo_var = 0
        else:
            outgoing_ave = np.mean(outgoing)
            outgo_var = np.var(outgoing)

        magnite = (inco_ave + outgoing_ave) ** 0.5

        radius = (inco_var + outgo_var) ** 0.5
        if (
            len(incoming) == len(outgoing)
            and len(outgoing) >= 2
            and np.std(incoming) != 0
            and np.std(outgoing) != 0
        ):
            try:
                correlation, p_value = stats.pearsonr(incoming, outgoing)
            except (ValueError, TypeError):
                correlation = 0
        else:
            correlation = 0


        covaraince = sum((a - inco_ave) * (b - outgoing_ave) for (a, b) in zip(incoming, outgoing)) / len(incoming)
        var_ratio = 0

        if outgo_var != 0:
            var_ratio = inco_var / outgo_var

        weight = len(incoming) * len(outgoing)

        return magnite, radius, correlation, covaraince, var_ratio, weight


