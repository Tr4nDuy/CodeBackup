# Real-Time Network Intrusion Detection System

This document describes the implementation of the real-time Network Intrusion Detection System (NIDS), which is an enhancement over the previous version that required pcap and csv file processing.

## Overview

The real-time NIDS captures network packets directly from a network interface, processes them in batches of 100 packets, and analyzes them using a pre-trained kINN (k-Inverse Nearest Neighbors) machine learning model. This approach offers several advantages over the previous implementation:

- **No temporary files**: The system no longer creates temporary pcap or csv files, which reduces I/O operations and increases performance.
- **Flow-aware processing**: Packets are processed in batches to maintain flow context, preserving the correlation between related packets.
- **Lower memory footprint**: By processing packets in real-time, the system uses less memory compared to capturing large pcap files.
- **Immediate detection**: Threats are detected and reported as soon as a batch is processed, reducing the time between an attack and detection.
- **SIEM integration**: The system can send detection events directly to a SIEM system for centralized logging and alerting.

## Components

1. `nids_analyzer.py`: The main script that captures packets, processes them in batches, and analyzes them using the pre-trained model.
2. `Feature_extraction.py`: Updated to include a `pcap_evaluation_realtime` method that processes a single packet while maintaining flow state.
3. `start_realtime_nids.sh`: Script to easily start the real-time NIDS.

## Usage

To start the real-time NIDS, run:

```bash
sudo ./start_realtime_nids.sh -i <interface_name>
```

Options:
- `-i, --interface INTERFACE`: Network interface to monitor (default: ens33)
- `-v, --verbose`: Enable verbose logging
- `-h, --help`: Display help message and exit

## Implementation Details

### Packet Processing Pipeline

1. **Capture**: Packets are captured from the specified network interface using scapy's `sniff` function.
2. **Buffering**: Captured packets are added to a buffer until 100 packets are collected.
3. **Feature Extraction**: Features are extracted from each packet in the buffer, maintaining flow state across packets.
4. **Preprocessing**: Features are scaled using the pre-trained scaler to match the model's expected input.
5. **Analysis**: The kINN model analyzes the packet features and classifies them.
6. **Reporting**: Detection results are logged and optionally sent to a SIEM.

### Flow State Preservation

To maintain flow state across packets, the system uses a `flow_info` dictionary that tracks:
- TCP and UDP flows
- Flow durations
- Packet counts per flow
- TCP flags per flow
- Incoming/outgoing packet streams

This ensures that flow-based features (like flow duration, packet counts, etc.) are correctly calculated even when processing packets in batches.

## Requirements

- Python 3.6 or higher
- Scapy
- dpkt
- NumPy
- pandas
- scikit-learn
- Root/sudo privileges (required for packet capture)

## Advantages Over Previous Implementation

1. **Efficiency**: No need to write and read temporary files, reducing disk I/O.
2. **Speed**: Faster analysis due to in-memory processing.
3. **Simplicity**: Single Python script instead of multiple bash scripts.
4. **Maintainability**: Clearer code structure and easier to extend.
5. **Real-time capability**: Detection happens immediately after capturing a batch of packets.

## Future Improvements

- **Packet filtering**: Add filtering options to focus on specific traffic types.
- **Adaptive batch sizing**: Adjust batch size based on traffic volume and system resources.
- **Multi-interface monitoring**: Monitor multiple interfaces simultaneously.
- **Traffic visualization**: Real-time visualization of network traffic and threats.
