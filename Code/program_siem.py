import pandas as pd
import numpy as np
import os
import pickle
import joblib
import time
import logging
import argparse
import json
import socket
import socket
from datetime import datetime
from sklearn.metrics import matthews_corrcoef
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics.pairwise import pairwise_kernels
from tqdm import tqdm
import warnings
import sys
import sys

warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")

# Set global configurations
np.random.seed(42)
pd.set_option("display.max_columns", None)

__MODE = "Supervise"
__SEED = 42
__SCALER = "QuantileTransformer"

class NIDSLogger:
    """Enhanced logger for SIEM integration with JSON output and network zones"""
    """Enhanced logger for SIEM integration with JSON output and network zones"""
    
    def __init__(self, log_dir="logs", siem_server="192.168.30.10", siem_port=5514):
    def __init__(self, log_dir="logs", siem_server="192.168.30.10", siem_port=5514):
        self.log_dir = log_dir
        self.siem_server = siem_server
        self.siem_port = siem_port
        self.siem_server = siem_server
        self.siem_port = siem_port
        os.makedirs(log_dir, exist_ok=True)
        
        # Setup JSON logger for SIEM
        self.json_logger = logging.getLogger('nids_json')
        self.json_logger.setLevel(logging.INFO)
        
        # Clear existing handlers to avoid duplicates
        for handler in self.json_logger.handlers[:]:
            self.json_logger.removeHandler(handler)
        
        # Clear existing handlers to avoid duplicates
        for handler in self.json_logger.handlers[:]:
            self.json_logger.removeHandler(handler)
        
        # JSON log handler
        json_handler = logging.FileHandler(
            os.path.join(log_dir, 'nids_detections.log'),
            encoding='utf-8'
        )
        json_handler.setFormatter(logging.Formatter('%(message)s'))
        self.json_logger.addHandler(json_handler)
        
        # Standard logger for debugging
        self.debug_logger = logging.getLogger('nids_debug')
        self.debug_logger.setLevel(logging.DEBUG)
        
        # Clear existing handlers
        for handler in self.debug_logger.handlers[:]:
            self.debug_logger.removeHandler(handler)
        
        # Clear existing handlers
        for handler in self.debug_logger.handlers[:]:
            self.debug_logger.removeHandler(handler)
        
        debug_handler = logging.FileHandler(
            os.path.join(log_dir, 'nids_debug.log'),
            encoding='utf-8'
        )
        debug_formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        debug_handler.setFormatter(debug_formatter)
        self.debug_logger.addHandler(debug_handler)
        
        # Statistics
        self.stats = {
            'total_processed': 0,
            'normal_detected': 0,
            'attacks_detected': 0,
            'tcp_scans': 0,
            'udp_scans': 0,
            'icmp_sweeps': 0,
            'arp_scans': 0,
            'start_time': datetime.now(),
            'zones': {}
            'start_time': datetime.now(),
            'zones': {}
        }
    
    def send_to_siem(self, log_entry):
        """Send log entry to SIEM server via syslog"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)  # 2 second timeout
            
            # Create syslog message
            priority = 14  # facility=1 (user), severity=6 (info)
            if log_entry.get('is_attack', False):
                priority = 11  # facility=1, severity=3 (error)
            
            syslog_msg = f"<{priority}>{json.dumps(log_entry)}"
            print(f"Sending to SIEM: {syslog_msg}")
            sock.sendto(syslog_msg.encode('utf-8'), (self.siem_server, self.siem_port))
            sock.close()
            return True
        except Exception as e:
            self.debug_logger.error(f"Failed to send to SIEM: {e}")
            return False
    
    def log_detection(self, features, prediction, confidence, zone="unknown", interface="unknown", processing_time=None):
        """Log detection result in JSON format for SIEM with network zone information"""
        
        # Update statistics
        self.stats['total_processed'] += 1
        if zone not in self.stats['zones']:
            self.stats['zones'][zone] = {
                'total': 0, 'attacks': 0, 'normal': 0
            }
        
        self.stats['zones'][zone]['total'] += 1
        
        if zone not in self.stats['zones']:
            self.stats['zones'][zone] = {
                'total': 0, 'attacks': 0, 'normal': 0
            }
        
        self.stats['zones'][zone]['total'] += 1
        
        if prediction == '0_normal':
            self.stats['normal_detected'] += 1
            self.stats['zones'][zone]['normal'] += 1
            self.stats['zones'][zone]['normal'] += 1
        else:
            self.stats['attacks_detected'] += 1
            self.stats['zones'][zone]['attacks'] += 1
            self.stats['zones'][zone]['attacks'] += 1
            if prediction == 'TCP':
                self.stats['tcp_scans'] += 1
            elif prediction == 'UDP':
                self.stats['udp_scans'] += 1
            elif prediction == 'ICMP':
                self.stats['icmp_sweeps'] += 1
            elif prediction == 'ARP':
                self.stats['arp_scans'] += 1
        
        # Determine risk level based on zone and attack type
        risk_level = self._calculate_risk_level(prediction, zone)
        
        # Determine risk level based on zone and attack type
        risk_level = self._calculate_risk_level(prediction, zone)
        
        # Create structured log entry
        log_entry = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f'),
            'event_type': 'network_detection',
            'prediction': prediction,
            'confidence': float(confidence) if confidence is not None else None,
            'is_attack': prediction != '0_normal',
            'severity': 'high' if prediction != '0_normal' else 'info',
            'risk_level': risk_level,
            'network_zone': zone,
            'interface': interface,
            'risk_level': risk_level,
            'network_zone': zone,
            'interface': interface,
            'processing_time_ms': processing_time,
            'sensor_id': f'nids-ubuntu-{interface}',
            'sensor_location': f'Ubuntu Router - {zone} Zone',
            'version': '2.1',
            'host': 'ubuntu-router-192.168.111.133'
        }        
            'sensor_id': f'nids-ubuntu-{interface}',
            'sensor_location': f'Ubuntu Router - {zone} Zone',
            'version': '2.1',
            'host': 'ubuntu-router-192.168.111.133'
        }        
        # Add network features if available
        try:
            if hasattr(features, 'columns'):
                # Extract key network features for logging
                feature_dict = features.iloc[0].to_dict() if len(features) > 0 else {}
                
                # Map common feature names to standardized fields
                field_mapping = {
                    'Src IP': 'source_ip',
                    'Dst IP': 'destination_ip', 
                    'Src Port': 'source_port',
                    'Dst Port': 'destination_port',
                    'Protocol': 'protocol',
                    'Flow Duration': 'flow_duration',
                    'Tot Fwd Pkts': 'forward_packets',
                    'Tot Bwd Pkts': 'backward_packets',
                    'TotLen Fwd Pkts': 'forward_bytes',
                    'TotLen Bwd Pkts': 'backward_bytes',
                    'Flow Byts/s': 'bytes_per_second',
                    'Flow Pkts/s': 'packets_per_second'
                }
                
                for original, mapped in field_mapping.items():
                    if original in feature_dict:
                        log_entry[mapped] = feature_dict[original]
                        
        except Exception as e:
            self.debug_logger.error(f"Error extracting features for logging: {e}")
        
        # Add attack classification
        if prediction != '0_normal':
            attack_mapping = {
                'TCP': {
                    'attack_type': 'TCP Port Scan',
                    'category': 'reconnaissance',
                    'attack_risk_level': 8
                    'attack_risk_level': 8
                },
                'UDP': {
                    'attack_type': 'UDP Port Scan', 
                    'category': 'reconnaissance',
                    'attack_risk_level': 7
                    'attack_risk_level': 7
                },
                'ICMP': {
                    'attack_type': 'ICMP Sweep',
                    'category': 'reconnaissance', 
                    'attack_risk_level': 6
                    'attack_risk_level': 6
                },
                'ARP': {
                    'attack_type': 'ARP Scan',
                    'category': 'reconnaissance',
                    'attack_risk_level': 5
                    'attack_risk_level': 5
                }
            }
            
            if prediction in attack_mapping:
                log_entry.update(attack_mapping[prediction])
        else:
            log_entry.update({
                'attack_type': 'normal_traffic',
                'category': 'benign',
                'attack_risk_level': 1
                'attack_risk_level': 1
            })
        
        # Log as JSON
        self.json_logger.info(json.dumps(log_entry))
        
        # Send to SIEM if possible
        self.send_to_siem(log_entry)
        
        # Send to SIEM if possible
        self.send_to_siem(log_entry)
        
        # Debug log
        self.debug_logger.info(
            f"Zone: {zone} | Detection: {prediction} (confidence: {confidence:.4f})" 
            if confidence is not None else f"Zone: {zone} | Detection: {prediction}"
            f"Zone: {zone} | Detection: {prediction} (confidence: {confidence:.4f})" 
            if confidence is not None else f"Zone: {zone} | Detection: {prediction}"
        )
    
    def _calculate_risk_level(self, prediction, zone):
        """Calculate risk level based on attack type and network zone"""
        base_risk = {
            '0_normal': 1,
            'TCP': 8,
            'UDP': 7, 
            'ICMP': 6,
            'ARP': 5
        }.get(prediction, 5)
        
        # Zone multipliers (higher risk in critical zones)
        zone_multiplier = {
            'WAN': 1.2,      # External facing - higher risk
            'DMZ': 1.1,      # Partially trusted
            'SERVER': 1.3,   # Critical systems
            'LAN': 1.0       # Internal network
        }.get(zone, 1.0)
        
        return min(10, int(base_risk * zone_multiplier))
    
    def _calculate_risk_level(self, prediction, zone):
        """Calculate risk level based on attack type and network zone"""
        base_risk = {
            '0_normal': 1,
            'TCP': 8,
            'UDP': 7, 
            'ICMP': 6,
            'ARP': 5
        }.get(prediction, 5)
        
        # Zone multipliers (higher risk in critical zones)
        zone_multiplier = {
            'WAN': 1.2,      # External facing - higher risk
            'DMZ': 1.1,      # Partially trusted
            'SERVER': 1.3,   # Critical systems
            'LAN': 1.0       # Internal network
        }.get(zone, 1.0)
        
        return min(10, int(base_risk * zone_multiplier))
    
    def log_stats(self):
        """Log current statistics"""
        runtime = datetime.now() - self.stats['start_time']
        
        stats_entry = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f'),
            'event_type': 'statistics',
            'runtime_seconds': runtime.total_seconds(),
            'total_processed': self.stats['total_processed'],
            'normal_detected': self.stats['normal_detected'],
            'attacks_detected': self.stats['attacks_detected'],
            'tcp_scans': self.stats['tcp_scans'],
            'udp_scans': self.stats['udp_scans'], 
            'icmp_sweeps': self.stats['icmp_sweeps'],
            'arp_scans': self.stats['arp_scans'],
            'detection_rate': (self.stats['attacks_detected'] / max(1, self.stats['total_processed'])) * 100,
            'zones_stats': self.stats['zones'],
            'sensor_id': 'nids-ubuntu-router',
            'host': 'ubuntu-router-192.168.111.133'
            'zones_stats': self.stats['zones'],
            'sensor_id': 'nids-ubuntu-router',
            'host': 'ubuntu-router-192.168.111.133'
        }
        
        self.json_logger.info(json.dumps(stats_entry))
        self.debug_logger.info(f"Statistics logged: {self.stats}")
        
        return stats_entry
        
        return stats_entry

def K(X, Y=None, metric="poly", coef0=1, gamma=None, degree=3):
    """Compute kernel matrix between X and Y."""
    params = {}
    if metric == "poly":
        params = {"coef0": coef0, "gamma": gamma, "degree": degree}
    elif metric == "sigmoid":
        params = {"coef0": coef0, "gamma": gamma}
    elif metric == "rbf":
        params = {"gamma": gamma}
    
    return pairwise_kernels(X, Y=Y, metric=metric, **params)

def kernel_distance_matrix(matrix1, matrix2, kernel="linear", gamma=None):
    """Calculate distance matrix between two matrices using specified kernel."""
    if matrix1.shape[1] != matrix2.shape[1]:
        raise ValueError("The number of features in the input matrices must be the same.")
    
    Kaa = np.array([K(x.reshape(1, -1), metric=kernel) for x in matrix1]).flatten()
    Kbb = np.array([K(x.reshape(1, -1), metric=kernel) for x in matrix2]).flatten()
    Kab = K(matrix1, matrix2, metric=kernel)
    
    distance_matrix = np.zeros((len(matrix1), len(matrix2)))
    for i in range(len(matrix1)):
        for j in range(len(matrix2)):
            distance_matrix[i, j] = Kaa[i] - 2 * Kab[i, j] + Kbb[j]
    
    return distance_matrix

class kINN:
    """k-Irregular Nearest Neighbor classifier with enhanced logging"""
    
    def __init__(self, k=3, kernel="poly", gamma=None, coef0=1, degree=3, weight='uniform'):
        self.k = k
        self.kernel = kernel
        self.gamma = gamma
        self.coef0 = coef0
        self.degree = degree
        self.weight = weight
        self.is_fitted = False
        self.logger = None
        
        # Additional attributes for compatibility with original model
        self.R = k  # Alias for compatibility
        self.is_fit = False  # Alias for compatibility
        self.X = None  # Training data (original name)
        self.X_train = None  # Training data (new name)
        self.y_train = None
        self.cluster_labels = None
        self.cluster_map = None
        self.INNR = None
        self.D_NN = None
        self.mode = "Supervise"
        
    def load_model_compatible(self, model_path):
        """Load a model saved by program.py with full compatibility"""
        try:
            with open(model_path, 'rb') as f:
                loaded_data = pickle.load(f)
            
            # Check if model is saved as dictionary (new format) or direct object (old format)
            if isinstance(loaded_data, dict) and 'model' in loaded_data:
                # New format: model saved as dictionary with metadata
                old_model = loaded_data['model']
                
                # Also save external data
                self.external_cluster_train = loaded_data.get('cluster_train')
                self.external_cluster_map = loaded_data.get('cluster_map') 
                self.external_parameters = loaded_data.get('parameters', {})
                
                if self.logger:
                    self.logger.debug_logger.info(f"Loaded model from dictionary format with parameters: {self.external_parameters}")
                    
            else:
                # Old format: direct kINN object
                old_model = loaded_data
                self.external_cluster_train = None
                self.external_cluster_map = None
                self.external_parameters = {}
            
            # Copy all attributes from old model
            for attr_name in dir(old_model):
                if not attr_name.startswith('_') and hasattr(old_model, attr_name):
                    attr_value = getattr(old_model, attr_name)
                    setattr(self, attr_name, attr_value)
            
            # Ensure compatibility aliases
            if hasattr(old_model, 'R'):
                self.k = old_model.R
                self.R = old_model.R
            if hasattr(old_model, 'is_fit'):
                self.is_fitted = old_model.is_fit
                self.is_fit = old_model.is_fit
            if hasattr(old_model, 'X'):
                self.X_train = old_model.X
                self.X = old_model.X
                
            if self.logger:
                self.logger.debug_logger.info(f"Successfully loaded compatible model: R={self.R}, kernel={self.kernel}")
                if hasattr(self, 'X') and self.X is not None:
                    self.logger.debug_logger.info(f"Training data shape: {self.X.shape}")
                if hasattr(self, 'cluster_labels') and self.cluster_labels is not None:
                    self.logger.debug_logger.info(f"Cluster labels shape: {self.cluster_labels.shape}")
                if hasattr(self, 'cluster_map') and self.cluster_map is not None:
                    self.logger.debug_logger.info(f"Cluster map shape: {self.cluster_map.shape}")
                    
        except Exception as e:
            if self.logger:
                self.logger.debug_logger.error(f"Error loading compatible model: {e}")
            raise
        
    def fit(self, X, y):
        """Fit the k-INN model"""
        try:
            self.X_train = np.array(X)
            self.y_train = np.array(y)
            self.X = self.X_train  # Compatibility alias
            self.is_fitted = True
            self.is_fit = True  # Compatibility alias
            if self.logger:
                self.logger.debug_logger.info(f"Model fitted with {len(X)} training samples")
            return self
        except Exception as e:
            if self.logger:
                self.logger.debug_logger.error(f"Error in fit: {e}")
            raise
    
    def predict(self, X):
        """Predict using k-INN with enhanced error handling and compatibility with original model"""
        start_time = time.time()
        
        try:
            # Check if model is fitted
            if not (hasattr(self, 'is_fitted') and self.is_fitted) and not (hasattr(self, 'is_fit') and self.is_fit):
                raise ValueError("Model must be fitted before making predictions")
            
            # Prepare input data
            X = np.array(X)
            if len(X.shape) == 1:
                X = X.reshape(1, -1)
            
            # Check if this is a model loaded from program.py (has original structure)
            if hasattr(self, 'cluster_labels') and hasattr(self, 'cluster_map') and hasattr(self, 'X'):
                # Use original model's prediction method
                return self._predict_original_model(X)
            
            # Use new model's prediction method
            return self._predict_new_model(X)
            
        except Exception as e:
            if hasattr(self, 'logger') and self.logger:
                self.logger.debug_logger.error(f"Error in predict: {e}")
            raise
    
    def _predict_original_model(self, X_test):
        """Predict using the original model structure from program.py"""
        try:
            # This mimics the predict method from program.py
            N_test = X_test.shape[0]
            self.M = N_test
            
            # Calculate distance matrix
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
                NN = D_NN_test[i, 1:self.R+1]
                tmp = []
                for p in NN:
                    # Check validity and D_NN existence
                    if (hasattr(self, 'D_NN') and self.D_NN is not None and 
                        p < len(self.D_NN) and self.D_NN[p] is not None):
                        p_near_neighbor = self.D_NN[p]
                        if i in p_near_neighbor:
                            tmp.append(p)
                pair = (i, tmp)
                INNR_X_test.append(pair)
                
            self.INNR_test = INNR_X_test
            
            # Use original prediction logic
            if hasattr(self, 'mode') and self.mode == "Supervise":
                labels = self._predict_multi()
                # Convert to format expected by new system
                predictions = labels
                confidences = np.ones(len(predictions)) * 0.8  # Default confidence
                return predictions, confidences
            else:
                # Fallback to simple nearest neighbor
                predictions = []
                confidences = []
                for i in range(N_test):
                    nearest_idx = D_NN_test[i, 0]
                    if hasattr(self, 'cluster_labels') and hasattr(self, 'cluster_map'):
                        cluster_label = self.cluster_labels[nearest_idx]
                        prediction = self.cluster_map[cluster_label]
                    else:
                        prediction = 0  # Default prediction
                    predictions.append(prediction)
                    confidences.append(0.7)  # Default confidence
                return np.array(predictions), np.array(confidences)
                
        except Exception as e:
            if hasattr(self, 'logger') and self.logger:
                self.logger.debug_logger.error(f"Error in original model prediction: {e}")
            raise
    
    def _predict_multi(self):
        """Multi-class prediction method from original model"""
        labels = -np.ones(self.M, dtype=int)
        for pair in self.INNR_test:
            idx = pair[0]
            if pair[1]:  # Check if neighbor list is not empty
                neighbors = pair[1]
                labels[idx] = self.cluster_map[self.cluster_labels[neighbors[0]]]
            else:                labels[idx] = self.cluster_map[
                    self.cluster_labels[self.D_NN_test[idx][0]]
                ]
        return labels
    
    def _predict_new_model(self, X):
        """Predict using new model structure"""
        start_time = time.time()
        
        # Determine training data attribute name
        train_data_attr = 'X_train' if hasattr(self, 'X_train') else 'X' 
        train_data = getattr(self, train_data_attr)
        
        # Validate dimensions
        if X.shape[1] != train_data.shape[1]:
            raise ValueError(f"Feature dimension mismatch: expected {train_data.shape[1]}, got {X.shape[1]}")
        
        # Get k parameter
        k_param = getattr(self, 'k', getattr(self, 'R', 3))
        
        predictions = []
        confidences = []
        for i, x in enumerate(X):
            try:
                x = x.reshape(1, -1)
                
                # Calculate distances using kernel
                distances = kernel_distance_matrix(
                    x, train_data, 
                    kernel=self.kernel, 
                    gamma=getattr(self, 'gamma', None)
                ).flatten()
                
                # Find k nearest neighbors
                k_indices = np.argsort(distances)[:k_param]
                
                # Get labels
                if hasattr(self, 'y_train'):
                    k_labels = self.y_train[k_indices]
                else:
                    # Default to class 0
                    k_labels = np.zeros(k_param)
                
                k_distances = distances[k_indices]
                
                # Calculate weights
                weight_type = getattr(self, 'weight', 'uniform')
                if weight_type == 'distance':
                    weights = 1 / (k_distances + 1e-8)
                else:
                    weights = np.ones(len(k_labels))
                
                # Weighted voting
                unique_labels, label_indices = np.unique(k_labels, return_inverse=True)
                label_weights = np.bincount(label_indices, weights=weights)
                
                predicted_label = unique_labels[np.argmax(label_weights)]
                confidence = np.max(label_weights) / np.sum(label_weights)
                
                # Log each prediction if logger available
                if hasattr(self, 'logger') and self.logger:
                    processing_time = (time.time() - start_time) * 1000
                    feature_df = pd.DataFrame([x.flatten()])
                    self.logger.log_detection(
                        feature_df, predicted_label, confidence, processing_time=processing_time
                    )
            
            except Exception as inner_e:
                # Handle error for individual sample
                if hasattr(self, 'logger') and self.logger:
                    self.logger.debug_logger.error(f"Error predicting sample {i}: {inner_e}")
                  # Default prediction
                predicted_label = 0
                confidence = 0.5
            
            predictions.append(predicted_label)
            confidences.append(confidence)
        
        return np.array(predictions), np.array(confidences)

def adapt_kINN_model(old_model, logger=None):
    """Convert from old kINN model (program.py) to new kINN model (program_siem.py)"""
    try:
        # Create new model with parameters from old model
        new_model = kINN(
            k=getattr(old_model, 'R', 3),  # Default k=3 if R not found
            kernel=getattr(old_model, 'kernel', 'poly'),  
            gamma=None,  # Not in old model
            coef0=1,     # Default
            degree=3,    # Default
            weight='uniform'
        )
        
        # Transfer training data
        if hasattr(old_model, 'X') and old_model.X is not None:
            new_model.X_train = old_model.X
            
            # Try to get labels
            if hasattr(old_model, 'cluster_labels') and hasattr(old_model, 'cluster_map'):
                # Map cluster labels to actual labels using cluster_map
                labels = []
                for cl in old_model.cluster_labels:
                    if cl < len(old_model.cluster_map):
                        labels.append(old_model.cluster_map[cl])
                    else:
                        labels.append(0)  # Default label if mapping fails
                new_model.y_train = np.array(labels)
            else:
                # Create dummy labels if not available
                new_model.y_train = np.zeros(len(old_model.X))
        
        # Mark as fitted if old model was fitted
        new_model.is_fitted = getattr(old_model, 'is_fit', False)
        
        # Attach logger
        if logger:
            new_model.logger = logger
            logger.debug_logger.info("Successfully adapted old kINN model to new format")
            
        return new_model
    except Exception as e:
        if logger:
            logger.debug_logger.error(f"Error adapting kINN model: {e}")
        raise

def load_models(model_dir):
    """Load trained models with comprehensive error handling and model adaptation"""
    logger = NIDSLogger()
    
    try:
        # Load kINN model
        model_path = os.path.join(model_dir, 'kinn_model.pkl')
        with open(model_path, 'rb') as f:
            original_model = pickle.load(f)
        
        # Check model type and adapt if needed
        if hasattr(original_model, 'is_fit') and not hasattr(original_model, 'is_fitted'):
            logger.debug_logger.info(f"Detected old kINN model format, adapting...")
            model = adapt_kINN_model(original_model, logger)
        else:
            model = original_model
            
        model.logger = logger  # Attach logger
        logger.debug_logger.info(f"Loaded kINN model from {model_path}")
        
        # Check if model has required attributes
        required_attrs = ['X_train', 'y_train', 'kernel', 'is_fitted']
        missing_attrs = [attr for attr in required_attrs if not hasattr(model, attr)]
        if missing_attrs:
            logger.debug_logger.warning(f"Model missing required attributes: {missing_attrs}")
        
        # Load scaler
        scaler_path = os.path.join(model_dir, 'scaler.pkl')
        scaler = joblib.load(scaler_path)
        logger.debug_logger.info(f"Loaded scaler from {scaler_path}")
        
        # Load label encoder
        encoder_path = os.path.join(model_dir, 'label_encoder.pkl')
        with open(encoder_path, 'rb') as f:
            label_encoder = pickle.load(f)
        logger.debug_logger.info(f"Loaded label encoder from {encoder_path}")
        logger.debug_logger.info(f"Label classes: {label_encoder.classes_}")
        
        return model, scaler, label_encoder, logger
        
    except Exception as e:
        logger.debug_logger.error(f"Error loading models: {e}")
        raise

def process_data_for_prediction(data_path, scaler, feature_columns=None):
    """Process CSV data for prediction with enhanced error handling and feature validation"""
    try:
        # Load data
        df = pd.read_csv(data_path)
        print(f"Loaded data: {df.shape}")
        
        if df.empty:
            raise ValueError("No data found in the CSV file")
        
        # Get scaler's feature names if available
        scaler_features = None
        if hasattr(scaler, 'feature_names_in_'):
            scaler_features = scaler.feature_names_in_.tolist()
            print(f"Scaler was trained on {len(scaler_features)} features")
        
        # Determine features to use
        if feature_columns is None:
            if scaler_features:
                feature_columns = scaler_features
                print("Using feature columns from scaler")
            else:
                feature_columns = [col for col in df.columns if col.lower() != 'label']
                print("Using all non-label columns as features")
        
        # Check if required columns exist
        missing_cols = [col for col in feature_columns if col not in df.columns]
        if missing_cols:
            print(f"WARNING: Missing columns in input data: {missing_cols}")
            # Create missing columns with zeros
            for col in missing_cols:
                df[col] = 0
                print(f"Added missing column '{col}' with zeros")
        
        # Handle extra columns not needed
        extra_cols = [col for col in df.columns if col not in feature_columns and col.lower() != 'label']
        if extra_cols:
            print(f"NOTE: {len(extra_cols)} extra columns not used by the model: {extra_cols[:5]}...")
        
        # Ensure columns are in the right order if scaler expects specific order
        if scaler_features:
            for col in scaler_features:
                if col not in df.columns:
                    df[col] = 0  # Add missing columns with zeros
            
            # Reorder columns to match scaler's expected order
            X = df[scaler_features].copy()
            print(f"Reordered columns to match scaler's expected format ({len(scaler_features)} features)")
        else:
            # Extract features in original order
            X = df[feature_columns].copy()
        
        # Handle missing values
        missing_count = X.isnull().sum().sum()
        if missing_count > 0:
            print(f"WARNING: Found {missing_count} missing values, filling with median/mode")
            for col in X.columns:
                if X[col].dtype in ['int64', 'float64']:
                    X[col].fillna(X[col].median(), inplace=True)
                else:
                    X[col].fillna(X[col].mode()[0] if not X[col].mode().empty else 0, inplace=True)
        
        # Check for infinity or very large values that might cause scaling issues
        inf_count = np.isinf(X.select_dtypes(include=['float64', 'int64']).values).sum()
        if inf_count > 0:
            print(f"WARNING: Found {inf_count} infinite values, replacing with large finite values")
            X = X.replace([np.inf, -np.inf], [1e30, -1e30])
        
        # Scale features
        try:
            X_scaled = scaler.transform(X)
            print(f"Successfully scaled {X.shape[1]} features for {X.shape[0]} samples")
        except Exception as scale_error:
            print(f"ERROR during scaling: {scale_error}")
            print(f"Input shape: {X.shape}, Expected by scaler: {scaler.n_features_in_ if hasattr(scaler, 'n_features_in_') else 'Unknown'}")
            raise
        
        return X_scaled, df
        
    except Exception as e:
        print(f"Error processing data: {e}")
        raise

def main():
    """Enhanced main function with JSON logging and network zone support"""
    """Enhanced main function with JSON logging and network zone support"""
    parser = argparse.ArgumentParser(description='NIDS - Network Intrusion Detection System')
    parser.add_argument('data', help='Path to CSV data file')
    parser.add_argument('data', help='Path to CSV data file')
    parser.add_argument('--models', default='../Saved model', help='Path to model directory')
    parser.add_argument('--output', default='predictions.csv', help='Output file for predictions')
    parser.add_argument('--zone', default='unknown', help='Network zone (WAN/LAN/SERVER/DMZ)')
    parser.add_argument('--interface', default='unknown', help='Network interface name')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--zone', default='unknown', help='Network zone (WAN/LAN/SERVER/DMZ)')
    parser.add_argument('--interface', default='unknown', help='Network interface name')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    
    args = parser.parse_args()
    
    try:
        if args.debug:
            print("=== NIDS Real-time Detection System ===")
            print(f"Zone: {args.zone} | Interface: {args.interface}")
            print(f"Loading models from: {args.models}")
        if args.debug:
            print("=== NIDS Real-time Detection System ===")
            print(f"Zone: {args.zone} | Interface: {args.interface}")
            print(f"Loading models from: {args.models}")
        
        # Load models
        model, scaler, label_encoder, logger = load_models(args.models)
        
        if args.debug:
            print(f"Processing data from: {args.data}")
        if args.debug:
            print(f"Processing data from: {args.data}")
        
        # Process data
        X_scaled, original_df = process_data_for_prediction(args.data, scaler)
        
        if len(X_scaled) == 0:
            logger.debug_logger.warning("No data to process")
            return
        
        if args.debug:
            print("Making predictions...")
        if len(X_scaled) == 0:
            logger.debug_logger.warning("No data to process")
            return
        
        if args.debug:
            print("Making predictions...")
        start_time = time.time()
        
        # Make predictions
        predictions, confidences = model.predict(X_scaled)
        
        processing_time = (time.time() - start_time) * 1000  # Convert to milliseconds
        processing_time = (time.time() - start_time) * 1000  # Convert to milliseconds
        
        # Decode predictions
        try:
            decoded_predictions = label_encoder.inverse_transform(predictions)
        except ValueError as e:
            logger.debug_logger.error(f"Could not decode predictions: {e}")
            logger.debug_logger.error(f"Could not decode predictions: {e}")
            decoded_predictions = predictions
        
        # Log each detection with zone information
        for i, (pred, conf) in enumerate(zip(decoded_predictions, confidences)):
            # Get features for this row
            features = original_df.iloc[i:i+1] if i < len(original_df) else None
            
            # Log detection
            logger.log_detection(
                features=features,
                prediction=pred,
                confidence=conf,
                zone=args.zone,
                interface=args.interface,
                processing_time=processing_time / len(predictions)
            )
            
            # Print alert for attacks (optional, for debugging)
            if args.debug and pred != '0_normal':
                print(f"ALERT: {pred} detected in {args.zone} zone (confidence: {conf:.4f})")
        
        # Create results DataFrame and save
        # Log each detection with zone information
        for i, (pred, conf) in enumerate(zip(decoded_predictions, confidences)):
            # Get features for this row
            features = original_df.iloc[i:i+1] if i < len(original_df) else None
            
            # Log detection
            logger.log_detection(
                features=features,
                prediction=pred,
                confidence=conf,
                zone=args.zone,
                interface=args.interface,
                processing_time=processing_time / len(predictions)
            )
            
            # Print alert for attacks (optional, for debugging)
            if args.debug and pred != '0_normal':
                print(f"ALERT: {pred} detected in {args.zone} zone (confidence: {conf:.4f})")
        
        # Create results DataFrame and save
        results_df = original_df.copy()
        results_df['Prediction'] = decoded_predictions
        results_df['Confidence'] = confidences
        results_df['Network_Zone'] = args.zone
        results_df['Interface'] = args.interface
        results_df['Processing_Time_MS'] = processing_time / len(predictions)
        results_df['Network_Zone'] = args.zone
        results_df['Interface'] = args.interface
        results_df['Processing_Time_MS'] = processing_time / len(predictions)
        
        # Save results
        results_df.to_csv(args.output, index=False)
        
        # Log summary statistics
        attack_count = sum(1 for pred in decoded_predictions if pred != '0_normal')
        
        if args.debug:
            print(f"Processed {len(decoded_predictions)} packets")
            print(f"Attacks detected: {attack_count}")
            print(f"Processing time: {processing_time:.2f}ms total")
          # Periodic stats logging (every 100 processed packets)
        if logger.stats['total_processed'] % 100 == 0:
            logger.log_stats()
        
        # Log summary statistics
        attack_count = sum(1 for pred in decoded_predictions if pred != '0_normal')
        
        if args.debug:
            print(f"Processed {len(decoded_predictions)} packets")
            print(f"Attacks detected: {attack_count}")
            print(f"Processing time: {processing_time:.2f}ms total")
          # Periodic stats logging (every 100 processed packets)
        if logger.stats['total_processed'] % 100 == 0:
            logger.log_stats()
        
        # Log final statistics
        logger.log_stats()
        
        # Print summary
        unique_predictions, counts = np.unique(decoded_predictions, return_counts=True)
        if args.debug:
            print("\n=== Detection Summary ===")
            for pred, count in zip(unique_predictions, counts):
                percentage = (count / len(predictions)) * 100
                print(f"{pred}: {count} ({percentage:.1f}%)")
            
            print(f"\nJSON logs saved to: {logger.log_dir}")
            print("System ready for SIEM integration!")
        if args.debug:
            print("\n=== Detection Summary ===")
            for pred, count in zip(unique_predictions, counts):
                percentage = (count / len(predictions)) * 100
                print(f"{pred}: {count} ({percentage:.1f}%)")
            
            print(f"\nJSON logs saved to: {logger.log_dir}")
            print("System ready for SIEM integration!")
        
    except FileNotFoundError:
        print(f"Error: Data file {args.data} not found")
        sys.exit(1)
    except FileNotFoundError:
        print(f"Error: Data file {args.data} not found")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        if 'logger' in locals():
            logger.debug_logger.error(f"Fatal error: {e}")
        sys.exit(1)
        print(f"Error: {e}")
        if 'logger' in locals():
            logger.debug_logger.error(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
