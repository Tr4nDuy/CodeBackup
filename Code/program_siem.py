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
from datetime import datetime
from sklearn.metrics import matthews_corrcoef
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics.pairwise import pairwise_kernels
from tqdm import tqdm
import warnings
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
    
    def __init__(self, log_dir="logs", siem_server="192.168.30.10", siem_port=5514):
        self.log_dir = log_dir
        self.siem_server = siem_server
        self.siem_port = siem_port
        os.makedirs(log_dir, exist_ok=True)
        
        # Setup JSON logger for SIEM
        self.json_logger = logging.getLogger('nids_json')
        self.json_logger.setLevel(logging.INFO)
        
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
        
        if prediction == '0_normal':
            self.stats['normal_detected'] += 1
            self.stats['zones'][zone]['normal'] += 1
        else:
            self.stats['attacks_detected'] += 1
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
            'processing_time_ms': processing_time,
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
                },
                'UDP': {
                    'attack_type': 'UDP Port Scan', 
                    'category': 'reconnaissance',
                    'attack_risk_level': 7
                },
                'ICMP': {
                    'attack_type': 'ICMP Sweep',
                    'category': 'reconnaissance', 
                    'attack_risk_level': 6
                },
                'ARP': {
                    'attack_type': 'ARP Scan',
                    'category': 'reconnaissance',
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
            })
        
        # Log as JSON
        self.json_logger.info(json.dumps(log_entry))
        
        # Send to SIEM if possible
        self.send_to_siem(log_entry)
        
        # Debug log
        self.debug_logger.info(
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
        }
        
        self.json_logger.info(json.dumps(stats_entry))
        self.debug_logger.info(f"Statistics logged: {self.stats}")
        
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
        
    def fit(self, X, y):
        """Fit the k-INN model"""
        try:
            self.X_train = np.array(X)
            self.y_train = np.array(y)
            self.is_fitted = True
            if self.logger:
                self.logger.debug_logger.info(f"Model fitted with {len(X)} training samples")
            return self
        except Exception as e:
            if self.logger:
                self.logger.debug_logger.error(f"Error in fit: {e}")
            raise
            
    def predict(self, X):
        """Predict using k-INN with enhanced error handling"""
        start_time = time.time()
        
        try:
            if not self.is_fitted:
                raise ValueError("Model must be fitted before making predictions")
                
            X = np.array(X)
            if len(X.shape) == 1:
                X = X.reshape(1, -1)
                
            if X.shape[1] != self.X_train.shape[1]:
                raise ValueError(f"Feature dimension mismatch: expected {self.X_train.shape[1]}, got {X.shape[1]}")
            
            predictions = []
            confidences = []
            
            for i, x in enumerate(X):
                x = x.reshape(1, -1)
                
                # Calculate distances using kernel
                distances = kernel_distance_matrix(
                    x, self.X_train, 
                    kernel=self.kernel, 
                    gamma=self.gamma
                ).flatten()
                
                # Find k nearest neighbors
                k_indices = np.argsort(distances)[:self.k]
                k_labels = self.y_train[k_indices]
                k_distances = distances[k_indices]
                
                # Calculate weights
                if self.weight == 'distance':
                    weights = 1 / (k_distances + 1e-8)
                else:
                    weights = np.ones(len(k_labels))
                
                # Weighted voting
                unique_labels, label_indices = np.unique(k_labels, return_inverse=True)
                label_weights = np.bincount(label_indices, weights=weights)
                
                predicted_label = unique_labels[np.argmax(label_weights)]
                confidence = np.max(label_weights) / np.sum(label_weights)
                
                predictions.append(predicted_label)
                confidences.append(confidence)
                
                # Log each prediction if logger available
                if self.logger:
                    processing_time = (time.time() - start_time) * 1000
                    # Note: We don't have access to original features here, 
                    # so we'll create a simple DataFrame for logging
                    feature_df = pd.DataFrame([x.flatten()])
                    self.logger.log_detection(
                        feature_df, predicted_label, confidence, processing_time
                    )
            
            return np.array(predictions), np.array(confidences)
            
        except Exception as e:
            if self.logger:
                self.logger.debug_logger.error(f"Error in predict: {e}")
            raise

def load_models(model_dir):
    """Load trained models with comprehensive error handling"""
    logger = NIDSLogger()
    
    try:
        # Load kINN model
        model_path = os.path.join(model_dir, 'kinn_model.pkl')
        with open(model_path, 'rb') as f:
            model = pickle.load(f)
        model.logger = logger  # Attach logger
        logger.debug_logger.info(f"Loaded kINN model from {model_path}")
        
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
    """Process CSV data for prediction with enhanced error handling"""
    try:
        # Load data
        df = pd.read_csv(data_path)
        print(f"Loaded data: {df.shape}")
        
        if df.empty:
            raise ValueError("No data found in the CSV file")
        
        # Use all columns except Label if feature_columns not specified
        if feature_columns is None:
            feature_columns = [col for col in df.columns if col.lower() != 'label']
        
        # Check if required columns exist
        missing_cols = [col for col in feature_columns if col not in df.columns]
        if missing_cols:
            raise ValueError(f"Missing columns: {missing_cols}")
        
        # Extract features
        X = df[feature_columns].copy()
        
        # Handle missing values
        if X.isnull().sum().sum() > 0:
            print("Warning: Found missing values, filling with median/mode")
            for col in X.columns:
                if X[col].dtype in ['int64', 'float64']:
                    X[col].fillna(X[col].median(), inplace=True)
                else:
                    X[col].fillna(X[col].mode()[0] if not X[col].mode().empty else 0, inplace=True)
        
        # Scale features
        X_scaled = scaler.transform(X)
        
        return X_scaled, df
        
    except Exception as e:
        print(f"Error processing data: {e}")
        raise

def main():
    """Enhanced main function with JSON logging and network zone support"""
    parser = argparse.ArgumentParser(description='NIDS - Network Intrusion Detection System')
    parser.add_argument('data', help='Path to CSV data file')
    parser.add_argument('--models', default='../Saved model', help='Path to model directory')
    parser.add_argument('--output', default='predictions.csv', help='Output file for predictions')
    parser.add_argument('--zone', default='unknown', help='Network zone (WAN/LAN/SERVER/DMZ)')
    parser.add_argument('--interface', default='unknown', help='Network interface name')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    
    args = parser.parse_args()
    
    try:
        if args.debug:
            print("=== NIDS Real-time Detection System ===")
            print(f"Zone: {args.zone} | Interface: {args.interface}")
            print(f"Loading models from: {args.models}")
        
        # Load models
        model, scaler, label_encoder, logger = load_models(args.models)
        
        if args.debug:
            print(f"Processing data from: {args.data}")
        
        # Process data
        X_scaled, original_df = process_data_for_prediction(args.data, scaler)
        
        if len(X_scaled) == 0:
            logger.debug_logger.warning("No data to process")
            return
        
        if args.debug:
            print("Making predictions...")
        start_time = time.time()
        
        # Make predictions
        predictions, confidences = model.predict(X_scaled)
        
        processing_time = (time.time() - start_time) * 1000  # Convert to milliseconds
        
        # Decode predictions
        try:
            decoded_predictions = label_encoder.inverse_transform(predictions)
        except ValueError as e:
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
        results_df = original_df.copy()
        results_df['Prediction'] = decoded_predictions
        results_df['Confidence'] = confidences
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
        
    except FileNotFoundError:
        print(f"Error: Data file {args.data} not found")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        if 'logger' in locals():
            logger.debug_logger.error(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
