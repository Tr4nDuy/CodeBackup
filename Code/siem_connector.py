#!/usr/bin/env python3
# File: siem_connector.py
# Purpose: Send detection results to ELK Stack

import socket
import json
import logging
import os
import time
from datetime import datetime

class SIEMConnector:
    def __init__(self, server_ip="192.168.30.10", logstash_port=5514):
        self.server_ip = server_ip
        self.logstash_port = logstash_port
        self.socket = None
        
        # Setup logging
        logs_dir = os.path.join(os.path.dirname(__file__), "logs")
        os.makedirs(logs_dir, exist_ok=True)
        
        self.logger = logging.getLogger("SIEMConnector")
        self.logger.setLevel(logging.INFO)
        
        # Create file handler for logs
        log_file = os.path.join(logs_dir, "siem_connector.log")
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.INFO)
        
        # Create formatter and add to handlers
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        
        # Add handlers to logger
        self.logger.addHandler(file_handler)
        
    def connect_tcp(self):
        """Establish a TCP connection to Logstash"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.server_ip, self.logstash_port))
            #self.logger.info(f"Successfully connected to Logstash at {self.server_ip}:{self.logstash_port}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to connect to Logstash: {str(e)}")
            return False
            
    def send_log_tcp(self, log_data):
        """Send a log message to Logstash via TCP"""
        if not self.socket:
            if not self.connect_tcp():
                self.logger.warning("Skipping log send - not connected")
                return False
        
        try:
            # Convert log_data to JSON string with newline
            log_json = json.dumps(log_data) + "\n"
            self.socket.sendall(log_json.encode())
            #self.logger.info(f"Log sent to Logstash: {log_data.get('event_id', 'unknown')}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to send log: {str(e)}")
            # Try to reconnect on next attempt
            self.socket = None
            return False
    
    def format_detection_log(self, src_ip, dst_ip, src_port, dst_port, event_type, confidence, protocol, zone="unknown", additional_data=None):
        """Format detection data for SIEM consumption"""
        # Ensure IP addresses are string format and handle 0 values correctly
        src_ip_str = str(src_ip) if src_ip and src_ip != 0 and src_ip != '0' else "0.0.0.0"
        dst_ip_str = str(dst_ip) if dst_ip and dst_ip != 0 and dst_ip != '0' else "0.0.0.0"
        
        # Validate IP format to make sure these are valid IP addresses for Elasticsearch
        if src_ip_str.isdigit() or src_ip_str == '0':
            src_ip_str = "0.0.0.0"
        if dst_ip_str.isdigit() or dst_ip_str == '0':
            dst_ip_str = "0.0.0.0"
            
        event_id = f"NIDS-{int(time.time())}-{hash(src_ip_str + dst_ip_str) % 10000}"
        
        log_data = {
            "event_id": event_id,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "source_ip": src_ip_str,
            "destination_ip": dst_ip_str,
            "source_port": int(src_port) if isinstance(src_port, (int, float)) else 0,
            "destination_port": int(dst_port) if isinstance(dst_port, (int, float)) else 0,
            "event_type": event_type,
            "confidence": float(confidence),
            "protocol": protocol,
            "network_zone": zone,
            "detection_source": "NIDS-kINN"
        }
        
        # Add additional data if provided
        if additional_data:
            log_data.update(additional_data)
            
        return log_data
    
    def close(self):
        """Close the connection"""
        if self.socket:
            try:
                self.socket.close()
                #self.logger.info("SIEM connection closed")
            except:
                pass
            self.socket = None

# Usage example
if __name__ == "__main__":
    # Test the connector
    siem = SIEMConnector()
    
    test_log = siem.format_detection_log(
        src_ip="192.168.111.100",
        dst_ip="192.168.30.10",
        src_port=12345,
        dst_port=80,
        event_type="Port Scan",
        confidence=0.95,
        protocol="TCP",
        zone="LAN"
    )
    
    # Try to send via TCP
    result = siem.send_log_tcp(test_log)
    print(f"TCP send result: {result}")
    
    siem.close()
