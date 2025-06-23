#!/usr/bin/env python3
# filepath: /home/duy/CodeBackup/Code/nids_analyzer.py
"""
Real-Time Network Intrusion Detection System (NIDS)
This script captures network packets in real-time, processes them in batches,
extracts features, and analyzes them with a pretrained machine learning model.
"""

import os
import argparse
import pickle
import joblib
import time
import logging
import socket
import numpy as np
import pandas as pd
from datetime import datetime
from scapy.all import sniff
import dpkt
import threading
from collections import deque
from sklearn.metrics import matthews_corrcoef
from sklearn.metrics.pairwise import pairwise_kernels

# Import local modules
from Feature_extraction import Feature_extraction
from Communication_features import Communication_wifi, Communication_zigbee
from Connectivity_features import Connectivity_features_basic, Connectivity_features_time, \
    Connectivity_features_flags_bytes
from Dynamic_features import Dynamic_features
from Layered_features import L3, L4, L2, L1
from Supporting_functions import get_protocol_name, get_flow_info, get_flag_values, compare_flow_flags, \
    get_src_dst_packets, calculate_incoming_connections, \
    calculate_packets_counts_per_ips_proto, calculate_packets_count_per_ports_proto

import warnings
warnings.simplefilter(action='ignore', category=FutureWarning)

# Define the kINN class to load the model properly
def K(X, Y=None, metric="poly", coef0=1, gamma=None, degree=3):
    if metric == "poly":
        k = pairwise_kernels(
            X, Y=Y, metric=metric, coef0=coef0, gamma=gamma, degree=degree
        )
    elif metric == "linear":
        k = pairwise_kernels(X, Y=Y, metric=metric)
    elif metric == "sigmoid":
        k = pairwise_kernels(X, Y=Y, metric=metric, coef0=coef0, gamma=gamma)
    elif metric == "rbf":
        k = pairwise_kernels(X, Y=Y, metric=metric, gamma=gamma)
    return k

def kernel_distance_matrix(matrix1=None, matrix2=None, kernel=None, gamma=None):
    """
    Calculate the distance between two matrices using the kernel trick.
    Parameters:
    - matrix1: The first input matrix (NumPy array).
    - matrix2: The second input matrix (NumPy array).
    - gamma: The gamma parameter for the RBF kernel.
    Returns:
    - distance_matrix: The distance matrix between the two input matrices.
    """
    if matrix1.shape[1] != matrix2.shape[1]:
        raise ValueError(
            "The number of features in the input matrices must be the same."
        )
    Kaa = []
    for i in range(len(matrix1)):
        Kaa.append(K(matrix1[i, :].reshape(1, -1), metric=kernel))
    Kaa = np.asarray(Kaa).ravel().reshape(len(Kaa), 1)
    Kab = K(matrix1, matrix2, metric=kernel)
    Kbb = []
    for i in range(len(matrix2)):
        Kbb.append(K(matrix2[i, :].reshape(1, -1), metric=kernel))
    Kbb = np.asarray(Kbb).ravel()
    d = Kaa - 2 * Kab + Kbb  # shape: (matrix1,matrix2)
    return d

def calculate_accuracy_for_label(y_true, y_predict, label):
    """
    Calculate accuracy for a specific label.
    Parameters:
    - y_true: The true labels (1D NumPy array).
    - y_predict: The predicted labels (1D NumPy array).
    - label: The specific label for which to calculate accuracy.
    Returns:
    - accuracy: The accuracy for the specified label.
    """
    mask = y_true == label
    true_labels_for_label = y_true[mask]
    predicted_labels_for_label = y_predict[mask]
    accuracy = np.mean(true_labels_for_label == predicted_labels_for_label)
    return accuracy

class kINN:
    def __init__(self, R=1, kernel="linear", mode="Supervise"):
        self.R = R
        self.kernel = kernel
        self.distance_matrix = None
        self.cluster_labels = None
        self.cluster_map = None
        self.N = None
        self.X = None
        self.M = None
        self.is_fit = False
        self.DNN_test = None
        self.distance_matrix_test = None
        self.mode = mode

    def _Bruteforce_threshold(self, y_test, y_pred, scores):
        min_th = 1e-7
        max_th = 1e-1
        __step = 10000
        mcc = 0
        ndr = 0
        y_pred_adv = y_pred

        __rag = np.unique(y_test)
        thr = -np.ones(len(__rag))

        for id in __rag[1:]:
            for x in np.linspace(min_th, max_th, num=__step):
                y_pred_adv_tmp = np.array(
                    [
                        -1 if (y_p == id) and (sc > x) else y_p
                        for y_p, sc in zip(y_pred, scores)
                    ]
                )
                mcc_tmp = matthews_corrcoef(y_test, y_pred_adv_tmp)
                ndr_tmp = calculate_accuracy_for_label(y_test, y_pred_adv_tmp, -1)
                if np.mean([mcc_tmp * 2, ndr_tmp]) > np.mean([mcc * 2, ndr]):
                    y_pred_adv = y_pred_adv_tmp
                    mcc = mcc_tmp
                    ndr = ndr_tmp
                    thr[id] = x
            y_pred = y_pred_adv
        
        return y_pred_adv, mcc, thr

    def _Bruteforce_threshold_1_cls(self, y_test, y_pred, scores):
        min_th = 1e-7
        max_th = 1e-1
        __step = 10000
        mcc = 0
        ndr = 0
        y_pred_adv = y_pred

        __rag = np.unique(y_test)
        thr = -np.ones(len(__rag))

        id = 0
        for x in np.linspace(min_th, max_th, num=__step):
            y_pred_adv_tmp = np.array(
                [
                    1 if (y_p == id) and (sc > x) else y_p
                    for y_p, sc in zip(y_pred, scores)
                ]
            )
            mcc_tmp = matthews_corrcoef(y_test, y_pred_adv_tmp)
            ndr_tmp = calculate_accuracy_for_label(y_test, y_pred_adv_tmp, 1)
            if np.mean([mcc_tmp * 2, ndr_tmp]) > np.mean([mcc * 2, ndr]):
                y_pred_adv = y_pred_adv_tmp
                mcc = mcc_tmp
                ndr = ndr_tmp
                thr[id] = x
        y_pred = y_pred_adv

        return y_pred_adv, mcc, thr

    def fit(self, X, y=None, single=False, type="distance"):
        """
        Fit the kINN model to the input data.
        
        Parameters:
        - X: Input data, a 2D numpy array where each row represents a sample.
        - y: Input label, a array where each row represents a label for corresponding label
        - type: the strategy to calculate distance, support:
                                                            + "distance" - use only distance
                                                            + "density" - use LOF score as weight when calculate distance
        """
        self.X = X
        if (y is None) and (self.mode == "1_Cls"):
            y = np.zeros(X.shape[0], dtype=int)
        self._fit_classify(X, y, type)
        self.is_fit = True
        if single == True:
            X_new = self.__map_to_single_point(X)
            return X_new, self.cluster_labels, self.cluster_map
        else:
            return self.cluster_labels, self.cluster_map
    
    def _calculate_lof(self, dis_mat, k_dis, d_nn, N_cnt):
        # calculate reachability distance
        re_dis_k = np.array(
            [[max(dis_mat[i, k], k_dis[k]) for k in range(N_cnt)] for i in range(N_cnt)]
        )

        # calculate Local Reachability Density (LRD)
        lrd = np.array([1.0 / np.mean(re_dis_k[x, d_nn[x]]) for x in range(N_cnt)])

        # calculate LOF
        lof = np.array([np.mean(lrd[d_nn[x]]) / lrd[x] for x in range(N_cnt)])

        return lof

    def _fit_classify(self, X, y, type="distance"):
        N = X.shape[0]
        
        D_NN = np.empty((N,), dtype=object)
        INNR = np.empty((N,), dtype=object)
        
        classes, cls_cnt = np.unique(y, return_counts=True)
        
        for cls, N_cnt in zip(classes, cls_cnt):
            indicates = np.asarray(y == cls).nonzero()[0]
            X_cls = X[indicates]
            y_cls = y[indicates]
            
            dis_mat = kernel_distance_matrix(
                matrix1=X_cls, matrix2=X_cls, kernel=self.kernel
            )
            
            if type == "density":
                k_dis = -np.ones(N_cnt, dtype=float)
                d_nn = np.empty((N_cnt,), dtype=object)
                re_dis_k = -np.ones((N_cnt, N_cnt), dtype=float)
                
                for i in range(N_cnt):
                    dis_mat[i, i] = 0
                    tmp = dis_mat[i, :].argsort()
                    
                    # Some case that 2 point are too close
                    dnn_tmp = [i]
                    cnt = 0
                    for x in tmp:
                        if abs(dis_mat[i, dnn_tmp[-1]] - dis_mat[i, x]) > 1e-9:
                            dnn_tmp.append(x)
                            cnt += 1
                            k_dis[i] = dis_mat[i, x]
                        else:
                            dnn_tmp.append(x)
                            
                        if cnt >= self.R:
                            break
                    d_nn[i] = np.array(dnn_tmp[1:])
                    
                lof = self._calculate_lof(dis_mat, k_dis, d_nn, N_cnt)
                
                # Update new matrix
                dis_mat = np.array(
                    [
                        [dis_mat[i, k] * lof[k] for k in range(N_cnt)]
                        for i in range(N_cnt)
                    ]
                )
                
            # calculate D_N
            for i in range(N_cnt):
                dis_mat[i, i] = 0
                tmp = dis_mat[i, :].argsort()
                
                id = indicates[i]
                D_NN[id] = np.array(indicates[tmp])
                
                # Some case that 2 point are too close
                dnn_tmp = [i]
                cnt = 0
                for x in tmp:
                    if abs(dis_mat[i, dnn_tmp[-1]] - dis_mat[i, x]) > 1e-9:
                        dnn_tmp.append(x)
                        cnt += 1
                    else:
                        dnn_tmp.append(x)
                        
                    if cnt >= self.R:
                        break
                        
                D_NN[id] = np.array(indicates[dnn_tmp[1:]])
                
            self.D_NN = D_NN
            
            for i in indicates:
                NN = D_NN[i]
                tmp = []
                for p in NN:
                    p_near_neighbor = D_NN[p]
                    if i in p_near_neighbor:
                        tmp.append(p)
                        
                pair = (i, tmp)
                INNR[i] = pair
                
        self.INNR = INNR
        self.N = N
        self.cluster_labels, self.no_cluser = self._label_clusters()
        
        cluster_map = np.full(self.no_cluser, -1)
        
        for x_tmp, y_tmp in zip(self.cluster_labels, y):
            if cluster_map[x_tmp] == -1:
                cluster_map[x_tmp] = y_tmp
            else:
                if cluster_map[x_tmp] != y_tmp:
                    print("Debug - Loi KNN")
                    
        self.cluster_map = cluster_map
            
    def _label_clusters(self):
        """
        Label clusters using deep find search (DFS) algorithm.
        
        Parameters:
        - X: Input data, a 2D numpy array where each row represents a sample.
        
        Returns:
        - labels: A numpy array containing cluster labels for each sample.
        
        """
        labels = -np.ones(self.N, dtype=int)
        current_label = 0
        
        for x in self.INNR:
            id = x[0]
            if labels[id] == -1:
                queue = [id]
                labels[id] = current_label
                for q in queue:
                    neighbors = self.INNR[q][1]
                    for neighbor in neighbors:
                        if labels[neighbor] == -1:
                            queue.append(neighbor)
                            labels[neighbor] = current_label
                current_label += 1
        return labels, current_label
        
    def _dfs_label_clusters(self, i, current_label, labels):
        """
        DFS algorithm to label clusters.
        
        Parameters:
        - X: Input data, a 2D numpy array where each row represents a sample.
        - i: Index of the current sample being explored.
        - current_label: Current cluster label.
        - labels: A numpy array containing cluster labels for each sample.
        
        """
        if labels[i] != -1:
            return
            
        labels[i] = current_label
        
        neighbors = self.INNR[i][1]
        for neighbor in neighbors:
            self._dfs_label_clusters(neighbor, current_label, labels)
            
    def __map_to_single_point(self, X):
        a = self.cluster_labels
        x_new = []
        a_new = []
        for cl in np.unique(a):
            mask = np.isin(a, cl)
            known = X[mask]
            a_new.append(self.cluster_map[cl])
        self.cluster_labels = np.array(a_new)
        
        return np.array(x_new)
        
    def find_nearest_neighbors(self, X, x_i):
        """
        Find the R nearest neighbors of x_i using kernel trick.
        
        Parameters:
        - x_i: The input sample.
        
        Returns:
        - neighbors: A set of R nearest neighbors for x_i.
        """
        if self.distance_matrix is None:
            raise ValueError("Model not fitted. Call fit() first.")
            
        # Calculate kernel vector
        kernel_vector = self.distance_matrix[x_i].flatten()
        
        # Get indices of R nearest neighbors
        nearest_indices = np.argsort(kernel_vector)[1:self.R+1]
        
        return set(nearest_indices)
        
    def predict(self, X_test, y=None):
        """
        Predict the cluster labels for the input samples.
        
        Parameters:
        - X_test: Input data, a 2D numpy array where each row represents a sample.
        
        Returns:
        - predicted_labels: A numpy array containing predicted cluster labels for each sample.
        """
        if not self.is_fit:
            raise ValueError("Model not fitted. Call fit() first.")
            
        N_test = X_test.shape[0]
        self.M = N_test
        dis_mat_X_test = kernel_distance_matrix(
            matrix1=X_test, matrix2=self.X, kernel=self.kernel
        )
        self.distance_matrix_test = dis_mat_X_test
        D_NN_test = []
        
        for i in range(N_test):
            tmp = dis_mat_X_test[i,].argsort()
            D_NN_test.append(tmp)
            
        D_NN_test = np.array(D_NN_test)
        self.D_NN_test = D_NN_test
        INNR_X_test = []
        
        for i in range(N_test):
            NN = D_NN_test[i, :self.R]
            tmp = []
            for p in NN:
                # Check if p is valid and D_NN exists
                if (hasattr(self, 'D_NN') and self.D_NN is not None and 
                    p < len(self.D_NN) and self.D_NN[p] is not None):
                    p_near_neighbor = self.D_NN[p]
                    if i in p_near_neighbor:
                        tmp.append(p)
            pair = (i, tmp)
            INNR_X_test.append(pair)
            
        self.INNR_test = INNR_X_test
        
        if self.mode == "Supervise":
            labels = self._predict_multi()
            return labels
        elif self.mode == "Novelty_multi":
            labels, mcc, threshold = self._predict_novelty(y)
            return labels, mcc, threshold
        else:
            labels, mcc, threshold = self._predict_1Class(y)
            return labels, mcc, threshold
    
    def _predict_multi(self):
        labels = -np.ones(self.M, dtype=int)
        for pair in self.INNR_test:
            idx = pair[0]
            if pair[1]:  # Check if neighbors list is not empty
                neighbors = pair[1]
                labels[idx] = self.cluster_map[self.cluster_labels[neighbors[0]]]
            else:
                labels[idx] = self.cluster_map[self.cluster_labels[self.D_NN_test[idx][0]]]
        return labels
        
    def _predict_novelty(self, y):
        scores_mat = self.distance_matrix_test
        y_pred = [self.cluster_labels[x] for x in np.argmin(scores_mat, axis=1)]
        
        for i in range(self.M):
            y_pred[i] = self.cluster_map[y_pred[i]]
            
        scores = np.amin(scores_mat, axis=1)
        y_pred_adv, mcc, threshold = self._Bruteforce_threshold(y, y_pred, scores)
        
        return y_pred_adv, mcc, threshold
        
    def _predict_1Class(self, y):
        scores_mat = self.distance_matrix_test
        y_pred = np.zeros(self.M, dtype=int)
        scores = np.amin(scores_mat, axis=1)
        y_pred_adv, mcc, threshold = self._Bruteforce_threshold_1_cls(y, y_pred, scores)
        
        return y_pred_adv, mcc, threshold

# Import SIEM connector if available
try:
    from siem_connector import SIEMConnector
    SIEM_AVAILABLE = True
except ImportError:
    SIEM_AVAILABLE = False
    print("Warning: SIEM connector not found. SIEM integration disabled.")

# Set global configurations
np.random.seed(42)
pd.set_option("display.max_columns", None)

# SIEM configuration
SIEM_SERVER = "192.168.30.10"  # Change to your SIEM server IP
SIEM_PORT = 5514

# Network zones configuration
NETWORK_ZONES = {
    "192.168.111.": "WAN",
    "192.168.20.": "LAN",
    "192.168.30.": "SERVER",
    "192.168.40.": "DMZ"
}

# Packet buffer and processing variables
packet_buffer = deque(maxlen=100)  # Buffer to store packets
buffer_lock = threading.Lock()     # Lock for thread-safe buffer operations
processing_event = threading.Event()  # Event to signal when buffer is ready for processing
stop_capture = threading.Event()   # Event to signal when to stop capturing
NUM_PROCESSING_THREADS = 3         # Number of processing threads
processing_threads = []            # List to track processing threads

# Global variables for model and processing
kinn_model = None
scaler = None
encoder = None
feature_columns = None
feature_extractor = None

def get_ip_zone(ip):
    """Determine the network zone of an IP address"""
    if ip is None or ip == 0 or str(ip) == "0" or str(ip) == "0.0.0.0":
        return "Unknown"
        
    ip_str = str(ip)
    for prefix, zone in NETWORK_ZONES.items():
        if ip_str.startswith(prefix):
            return zone
    return "Unknown"

def setup_logging():
    """Configure logging for the application"""
    logs_dir = os.path.join(os.path.dirname(__file__), "logs")
    os.makedirs(logs_dir, exist_ok=True)
    
    log_file_path = os.path.join(logs_dir, f"realtime_nids_{datetime.now().strftime('%Y%m%d')}.log")
    
    logging.basicConfig(
        filename=log_file_path,
        level=logging.INFO,
        format='%(asctime)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        force=True
    )
    
    # Also log to console
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(message)s')
    console.setFormatter(formatter)
    logging.getLogger('').addHandler(console)
    
    return logging.getLogger()

def load_models():
    """Load the ML model, scaler, and encoder"""
    global kinn_model, scaler, encoder
    
    # Paths to model files
    model_path = os.path.join(os.path.dirname(__file__), "..", "Saved model", "kinn_model.pkl")
    scaler_path = os.path.join(os.path.dirname(__file__), "..", "Saved model", "scaler.pkl")
    encoder_path = os.path.join(os.path.dirname(__file__), "..", "Saved model", "encoder.pkl")
    
    # Check if files exist
    if not all(os.path.isfile(p) for p in [model_path, scaler_path, encoder_path]):
        raise FileNotFoundError("Model files not found. Please check paths.")
    
    # Load model components
    try:
        with open(model_path, "rb") as f:
            saved_data = pickle.load(f)
        
        kinn_model = saved_data["model"]
        logging.info("Model loaded successfully.")
        
        scaler = joblib.load(scaler_path)
        encoder = joblib.load(encoder_path)
        logging.info("Scaler and encoder loaded successfully.")
        
        return True
    except Exception as e:
        logging.error(f"Error loading models: {str(e)}")
        return False

def process_packet(packet):
    """Callback function for each captured packet"""
    # Convert scapy packet to raw bytes for dpkt
    raw_packet = bytes(packet)
    
    # Add packet to buffer
    with buffer_lock:
        packet_buffer.append(raw_packet)
        
        # If buffer is full, signal processing thread
        if len(packet_buffer) >= packet_buffer.maxlen:
            processing_event.set()

def extract_features_from_buffer():
    """Extract features from packets in buffer"""
    global feature_extractor
    
    # Initialize feature extraction
    if feature_extractor is None:
        feature_extractor = Feature_extraction()
    
    # Make a copy of the buffer and clear it
    with buffer_lock:
        # Make a copy of current packets in buffer
        packets_to_process = list(packet_buffer)
        packet_buffer.clear()
    
    logging.info(f"Processing batch of {len(packets_to_process)} packets")
    
    # List to store features for each packet
    all_features = []
    flow_info = {}  # To store information about flows

    # Process each packet and extract features
    for packet in packets_to_process:
        try:
            features_row = feature_extractor.pcap_evaluation_realtime(packet, flow_info)
            if features_row:
                all_features.append(features_row)
        except Exception as e:
            logging.error(f"Error extracting features: {str(e)}")
    
    if not all_features:
        logging.warning("No valid features extracted from packets.")
        return None

    # Create DataFrame with features
    feature_data = np.array(all_features)
    
    # Keep track of src_ip and dst_ip for logging
    src_ips = [row[5] for row in all_features]  # Assuming src_ip is at index 5
    dst_ips = [row[6] for row in all_features]  # Assuming dst_ip is at index 6

    # Columns to include in the feature set (should match model's expected input)
    columns = [
        "ts", "flow_duration", "flow_byte", 
        "src_mac", "dst_mac", "src_ip", "dst_ip", "src_port", "dst_port",
        "Protocol Type", "Duration",
        "Rate", "Srate", "Drate",
        "fin_flag_number", "syn_flag_number", "rst_flag_number",
        "psh_flag_number", "ack_flag_number", "urg_flag_number", "ece_flag_number", "cwr_flag_number",
        "ack_count", "syn_count", "fin_count", "urg_count", "rst_count",
        "max_duration", "min_duration", "sum_duration", "average_duration", "std_duration",
        "CoAP", "HTTP", "HTTPS", "DNS", "Telnet", "SMTP", "SSH", "IRC", "TCP", "UDP", "DHCP", "ARP", "ICMP", "IGMP", "IPv", "LLC",
        "Tot sum", "Min", "Max", "AVG", "Std", "Tot size", "IAT", "Number", "MAC", "Magnitue", "Radius", "Covariance", "Variance", "Weight", "Correlation",
        "DS status", "Fragments",
        "Sequence number", #"Protocol Version",
        "flow_idle_time", "flow_active_time"
    ]
    
    # Select only the features needed for the model (exclude timestamp, IPs, etc.)
    selected_columns = [
        "flow_duration", "flow_byte", "src_port", "dst_port", "Duration", "Rate",
        "Srate", "Drate", "fin_flag_number", "syn_flag_number", "rst_flag_number",
        "psh_flag_number", "ack_flag_number", "urg_flag_number", "ece_flag_number",
        "cwr_flag_number", "ack_count", "syn_count", "fin_count", "urg_count",
        "rst_count", "CoAP", "HTTP", "HTTPS", "DNS", "Telnet", "SMTP", "SSH", "IRC",
        "TCP", "UDP", "DHCP", "ARP", "ICMP", "IGMP", "IPv", "LLC", "Tot sum", "Min",
        "Max", "AVG", "Std", "Tot size", "IAT", "Magnitue", "Radius", "Covariance",
        "Variance", "Weight", "DS status", "Fragments", "Sequence number",
        "flow_idle_time", "flow_active_time"
    ]
    
    # Create DataFrame with all columns for easier indexing
    df = pd.DataFrame(feature_data, columns=columns)

    # Create DataFrame with only selected features for model
    model_features = df[selected_columns].fillna(0).infer_objects(copy=False)
    model_features.insert(0, "", range(1, len(df) + 1))
    
    # Store src_ip and dst_ip for logging
    log_data = {
        'src_ip': src_ips,
        'dst_ip': dst_ips
    }
    # print(df["Protocol Type"])
    return model_features, log_data

def analyze_features(features, log_data):
    """Analyze extracted features using the machine learning model"""
    global kinn_model, scaler, encoder
    
    if features is None or features.empty:
        logging.warning("No features to analyze")
        return
    
    try:
        # Scale features
        X_transformed = scaler.transform(features.values)
        
        # Make predictions
        y_pred = kinn_model.predict(X_transformed)
        
        # Transform to human-readable labels
        y_pred_labels = encoder.inverse_transform(y_pred)
        
        logging.info(f"Successfully analyzed {len(y_pred)} packets")
        
        # Log mapping for event descriptions
        log_mapping = {
            "0_normal": "Normal Traffic",
            "TCP": "TCP Scanning Attack",
            "UDP": "UDP Scanning Attack",
            "ICMP": "ICMP Scanning Attack", 
            "ARP": "ARP Scanning Attack"
        }
        
        # Count of each event type
        event_counts = {event_type: 0 for event_type in log_mapping.values()}
        event_counts["Unknown"] = 0
        
        # Process each prediction
        for i, label in enumerate(y_pred_labels):
            # Get source and destination information
            src_ip = log_data['src_ip'][i]
            dst_ip = log_data['dst_ip'][i]
            src_port = features.iloc[i]["src_port"]
            dst_port = features.iloc[i]["dst_port"]
            
            # Map label to event description
            event = log_mapping.get(label, "Unknown event")
            
            # Update event counts
            if event == "Unknown event":
                event_counts["Unknown"] += 1
            else:
                event_counts[event] += 1
            
            # Log the detection
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            log_message = f"Detection: Label='{label}'"
            logging.info(log_message)
            
            # Send to SIEM if it's not normal traffic
            if SIEM_AVAILABLE:                  # and event != "Normal Traffic":
                try:
                    # Get source zone
                    src_zone = get_ip_zone(src_ip)
                    
                    # Calculate confidence
                    confidence = 0.95 if event != "Unknown event" else 0.5
                    
                    # Determine protocol from label
                    protocol = label if label in ["TCP", "UDP", "ICMP", "ARP", "0_normal"] else "Unknown"
                    
                    # Connect to SIEM
                    siem = SIEMConnector(SIEM_SERVER, SIEM_PORT)
                    
                    # Format log data
                    siem_log = siem.format_detection_log(
                        src_ip=str(src_ip) if src_ip and src_ip != 0 else "0.0.0.0",
                        dst_ip=str(dst_ip) if dst_ip and dst_ip != 0 else "0.0.0.0",
                        src_port=int(src_port) if isinstance(src_port, (int, float)) else 0,
                        dst_port=int(dst_port) if isinstance(dst_port, (int, float)) else 0,
                        event_type=event,
                        confidence=confidence,
                        protocol=protocol,
                        zone=src_zone,
                        additional_data={
                            "detection_time": timestamp,
                            "original_label": label
                        }
                    )
                    
                    # Send log to SIEM
                    result = siem.send_log_tcp(siem_log)
                    #logging.info(f"SIEM log sent: {result}")
                    siem.close()
                except Exception as e:
                    logging.error(f"Error sending to SIEM: {str(e)}")
        
        # Print statistics
        logging.info("=" * 50)
        logging.info("Event Statistics:")
        for event_type, count in event_counts.items():
            if count > 0:
                logging.info(f"- {event_type}: {count} packets")
        logging.info("=" * 50)
        
    except Exception as e:
        logging.error(f"Error during analysis: {str(e)}")

def processing_thread_function():
    """Thread function to process packets when buffer is full"""
    logging.info("Processing thread started")
    
    while not stop_capture.is_set():
        # Wait for signal that buffer is ready for processing
        processing_event.wait(timeout=5)  # Wait up to 5 seconds
        
        # If buffer has packets, process them
        if len(packet_buffer) > 0:
            try:
                # Extract features
                features, log_data = extract_features_from_buffer()
                
                # Analyze features if we have any
                if features is not None and not features.empty:
                    analyze_features(features, log_data)
            except Exception as e:
                logging.error(f"Error in processing thread: {str(e)}")
        
        # Reset the event
        processing_event.clear()

def main():
    """Main function to run the real-time NIDS"""
    global stop_capture
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Real-time Network Intrusion Detection System")
    parser.add_argument("-i", "--interface", default="ens33", help="Network interface to monitor")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 for unlimited)")
    parser.add_argument("-t", "--timeout", type=int, default=0, help="Timeout in seconds (0 for no timeout)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    args = parser.parse_args()
      # Setup logging
    logger = setup_logging()
    if args.verbose:
        for handler in logger.handlers:
            handler.setLevel(logging.DEBUG)
    
    logger.info("Starting Real-time Network Intrusion Detection System")
    logger.info(f"Monitoring interface: {args.interface}")
    
    try:
        # Load models
        if not load_models():
            logger.error("Failed to load models. Exiting.")
            return 1
        
        # Start multiple processing threads
        global processing_threads
        for i in range(NUM_PROCESSING_THREADS):
            process_thread = threading.Thread(target=processing_thread_function, name=f"ProcessingThread-{i}")
            process_thread.daemon = True
            processing_threads.append(process_thread)
            process_thread.start()
        
        logger.info(f"Started {NUM_PROCESSING_THREADS} packet processing threads")
        logger.info("Starting packet capture...")
        
        sniff_kwargs = {
            "iface": args.interface,
            "prn": process_packet,
            "store": False
            # "filter": "arp"  
        }

        if args.count > 0:
            sniff_kwargs["count"] = args.count
        if args.timeout > 0:
            sniff_kwargs["timeout"] = args.timeout

        try:
            sniff(**sniff_kwargs)
        except KeyboardInterrupt:
            logger.info("Keyboard interrupt received. Stopping capture.")
        except Exception as e:
            logger.error(f"Error during packet capture: {str(e)}")
          # Signal processing threads to stop and wait for any remaining packets
        stop_capture.set()
        processing_event.set()  # Wake up the processing threads
        
        # Wait for all processing threads to finish
        for thread in processing_threads:
            thread.join(timeout=5)
        
        logger.info("NIDS has been stopped")
        
    except Exception as e:
        logger.error(f"Error in main function: {str(e)}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
