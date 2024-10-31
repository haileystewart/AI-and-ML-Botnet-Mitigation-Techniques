"""
traffic_analysis.py

This script is responsible for pre-processing the CTU-13-captured network traffic. It will:
- Parse the captured traffic to extract key features, such as:
    - Packet size
    - Protocol type
    - Time intervals between packets
    - Frequency of C&C requests
- These features will help quantify the traffic and identify patterns that could indicate botnet activity.
"""

import pandas as pd
from scapy.all import *
import os
from datetime import datetime, timezone

# Ensure the /processed_data directory exists for phase2
output_dir = "C:/Users/hailey/botnet-detection-ml-techniques/src/phase2/processed_data"

# Update dataset paths to match the relative path from the main project directory
dataset_paths = [
    os.path.join("CTU-13-Dataset", "1", "botnet-capture-20110810-neris.pcap"),
    os.path.join("CTU-13-Dataset", "2", "botnet-capture-20110811-neris.pcap"),
    os.path.join("CTU-13-Dataset", "3", "botnet-capture-20110812-rbot.pcap"),
    os.path.join("CTU-13-Dataset", "4", "botnet-capture-20110815-rbot-dos.pcap"),
    os.path.join("CTU-13-Dataset", "5", "botnet-capture-20110815-fast-flux.pcap"),
    os.path.join("CTU-13-Dataset", "6", "botnet-capture-20110816-donbot.pcap"),
    os.path.join("CTU-13-Dataset", "7", "botnet-capture-20110816-sogou.pcap"),
    os.path.join("CTU-13-Dataset", "8", "botnet-capture-20110816-qvod.pcap"),
    os.path.join("CTU-13-Dataset", "9", "botnet-capture-20110817-bot.pcap"),
    os.path.join("..", "..", "CTU-13-Dataset", "10", "botnet-capture-20110818-filtered.pcap"),
    os.path.join("CTU-13-Dataset", "11", "botnet-capture-20110818-bot-2.pcap"),
    os.path.join("CTU-13-Dataset", "12", "botnet-capture-20110819-bot.pcap"),
    os.path.join("CTU-13-Dataset", "13", "botnet-capture-20110815-fast-flux-2.pcap"),
]

# Define C&C server IPs for each corresponding PCAP file (update accordingly)
c2_ips = [
    "147.32.84.165",  # C&C IP for botnet-capture-20110810-neris.pcap
    "147.32.84.165",  # C&C IP for botnet-capture-20110811-neris.pcap
    "147.32.84.165",  # C&C IP for botnet-capture-20110812-rbot.pcap
    None,             # No known C2 IP for botnet-capture-20110815-rbot-dos.pcap
    None,             # No known C2 IP for botnet-capture-20110815-fast-flux.pcap
    "147.32.84.165",  # C&C IP for botnet-capture-20110816-donbot.pcap
    None,             # No known C2 IP for botnet-capture-20110816-sogou.pcap
    None,             # No known C2 IP for botnet-capture-20110816-qvod.pcap
    "147.32.84.165",  # C&C IP for botnet-capture-20110817-bot.pcap
    "147.32.84.165",  # C&C IP for botnet-capture-20110818-bot.pcap
    "147.32.84.165",  # C&C IP for botnet-capture-20110818-bot-2.pcap
    "147.32.84.165",  # C&C IP for botnet-capture-20110819-bot.pcap
    None              # No known C2 IP for botnet-capture-20110815-fast-flux-2.pcap
]

def parse_pcap(file):
    packets = rdpcap(file)
    data = []
    
    for packet in packets:
        if IP in packet and (TCP in packet or UDP in packet):
            timestamp = float(packet.time)
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet.sprintf("%IP.proto%")
            packet_size = len(packet)
            readable_time = datetime.fromtimestamp(timestamp, timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
            
            data.append({
                'timestamp': readable_time,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'protocol': protocol,
                'packet_size': packet_size
            })
    
    return pd.DataFrame(data)

def calculate_time_intervals(df):
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df['time_interval'] = df['timestamp'].diff().dt.total_seconds().fillna(0)
    return df

def filter_cnc_traffic(df, c2_server_ip):
    if c2_server_ip:
        return df[(df['src_ip'] == c2_server_ip) | (df['dst_ip'] == c2_server_ip)]
    return df

if __name__ == "__main__":
    for pcap_file, c2_server_ip in zip(dataset_paths, c2_ips):
        if not os.path.exists(pcap_file):
            print(f"File not found: {pcap_file}")
            continue

        print(f"Analyzing {pcap_file}...")
        parsed_traffic = parse_pcap(pcap_file)
        parsed_traffic_with_intervals = calculate_time_intervals(parsed_traffic)
        cnc_traffic = filter_cnc_traffic(parsed_traffic_with_intervals, c2_server_ip)

        output_file = os.path.join('../phase2/processed_data', os.path.basename(pcap_file).replace('.pcap', '_processed.csv'))
        cnc_traffic.to_csv(output_file, index=False)
        print(f"Data saved to {output_file}\n")
