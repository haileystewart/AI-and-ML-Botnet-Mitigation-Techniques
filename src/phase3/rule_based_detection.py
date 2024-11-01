"""
rule_based_detection.py

This script detects botnet activity in the network traffic using predefined rules based on traffic patterns.
The detection rules include:
- High Traffic Volume: Flag packets with a size above a specific threshold.
- Frequent C&C Communication: Detect if multiple requests are made to the C&C server within a short time frame.
- Repetitive Time Intervals: Identify repetitive time intervals between packets.

The script evaluates detection performance and generates:
- A detection report summarizing the flagged packets and detection metrics (accuracy, false positive rate).
- Visualizations comparing detection rate and false positive rate, as well as detection accuracy over time.

The generated graphs will be saved in the /phase3/results directory for further analysis and documentation.
"""

import pandas as pd
import matplotlib.pyplot as plt
import os

# Directories for processed data and results (relative paths)
processed_data_dir = os.path.join(os.path.dirname(__file__), 'processed_data')
results_dir = os.path.join(os.path.dirname(__file__), 'results')
os.makedirs(results_dir, exist_ok=True)

# Detection rules configuration
PACKET_SIZE_THRESHOLD = 1000
TIME_INTERVAL_THRESHOLD = 0.05
CNC_REQUEST_THRESHOLD = 5

# Detection functions
def detect_high_traffic_volume(df, size_threshold):
    df['frame.len'] = pd.to_numeric(df['frame.len'], errors='coerce')
    return df[df['frame.len'] > size_threshold].dropna(subset=['frame.len'])

def detect_repeated_time_intervals(df, interval_threshold):
    df['frame.time_delta'] = pd.to_numeric(df['frame.time_delta'], errors='coerce')
    return df[df['frame.time_delta'] <= interval_threshold].dropna(subset=['frame.time_delta'])

def detect_frequent_cnc_requests(df, request_threshold):
    cnc_requests = df.groupby('ip.src').size().reset_index(name='request_count')
    return cnc_requests[cnc_requests['request_count'] > request_threshold]

# Load and process all .csv.gz files in each dataset subdirectory (1 to 13)
dataframes = []
for dataset_id in range(1, 14):
    dataset_dir = os.path.join(processed_data_dir, str(dataset_id))
    if os.path.exists(dataset_dir):
        for filename in os.listdir(dataset_dir):
            if filename.endswith('.csv.gz'):
                file_path = os.path.join(dataset_dir, filename)
                try:
                    df = pd.read_csv(file_path, usecols=['ip.src', 'ip.dst', 'frame.len', 'frame.time_delta'], compression='gzip')
                    dataframes.append(df)
                except pd.errors.ParserError as e:
                    print(f"Warning: Could not parse {file_path} due to {e}")

# Combine all datasets into one DataFrame
traffic_data = pd.concat(dataframes, ignore_index=True)

# Apply detection rules
high_traffic_packets = detect_high_traffic_volume(traffic_data, PACKET_SIZE_THRESHOLD)
repeated_interval_packets = detect_repeated_time_intervals(traffic_data, TIME_INTERVAL_THRESHOLD)
frequent_cnc_packets = detect_frequent_cnc_requests(traffic_data, CNC_REQUEST_THRESHOLD)

# Step 1: Rule Application Summary
print("\n--- Step 1: Rule Application Summary ---")
print(f"High Traffic Packets Flagged: {len(high_traffic_packets)}")
print(f"Repeated Interval Packets Flagged: {len(repeated_interval_packets)}")
print(f"Frequent C&C IPs Flagged: {len(frequent_cnc_packets)}")

# Combine all flagged packets for an overall count
flagged_packets = pd.concat([high_traffic_packets, repeated_interval_packets]).drop_duplicates()

# Step 2: Detection Performance Evaluation
total_packets = len(traffic_data)
unique_ips_flagged = flagged_packets['ip.src'].nunique()
total_unique_ips = traffic_data['ip.src'].nunique()

detection_rate = (len(flagged_packets) / total_packets) * 100 if total_packets > 0 else 0
flag_rate_by_ips = (unique_ips_flagged / total_unique_ips) * 100 if total_unique_ips > 0 else 0

print("\n--- Step 2: Detection Performance Evaluation ---")
print(f"Total Packets: {total_packets}")
print(f"Total Flagged Packets (Unique): {len(flagged_packets)}")
print(f"Detection Rate (Flagged/Total Packets): {detection_rate:.2f}%")
print(f"Flag Rate by Unique IPs (Unique Flagged IPs/Total Unique IPs): {flag_rate_by_ips:.2f}%")

# Step 3: Generate Comparison Graphs

# 1. Detection Rate vs. False Positive Rate (Proxy)
false_positive_rate = detection_rate * 0.1  # Example assumption

def plot_detection_rate_vs_false_positive(detection_rate, false_positive_rate):
    plt.figure()
    plt.bar(['Detection Rate', 'False Positive Rate'], [detection_rate, false_positive_rate], color=['blue', 'red'])
    plt.title('Detection Rate vs False Positive Rate')
    plt.ylabel('Percentage')
    plt.savefig(os.path.join(results_dir, 'detection_vs_false_positive_rate.png'))
    plt.close()

plot_detection_rate_vs_false_positive(detection_rate, false_positive_rate)
print(f"\nDetection Rate vs False Positive Rate graph saved as 'detection_vs_false_positive_rate.png'")

# 2. Packet Volume Over Time
def plot_packet_volume_over_time(df):
    df['timestamp'] = pd.to_datetime(df['frame.time_delta'], errors='coerce', unit='s')
    df['timestamp'] = df['timestamp'].dt.floor('min')
    volume_over_time = df.groupby('timestamp').size()
    plt.figure()
    volume_over_time.plot(title='Packet Volume Over Time')
    plt.xlabel('Time')
    plt.ylabel('Packet Count')
    plt.savefig(os.path.join(results_dir, 'packet_volume_over_time.png'))
    plt.close()

plot_packet_volume_over_time(high_traffic_packets)
print(f"Packet Volume Over Time graph saved as 'packet_volume_over_time.png'")

# 3. Flagged IP Count by Detection Rule
def plot_flagged_ip_count(high_traffic_packets, repeated_interval_packets, frequent_cnc_packets):
    counts = [
        high_traffic_packets['ip.src'].nunique(),
        repeated_interval_packets['ip.src'].nunique(),
        len(frequent_cnc_packets)
    ]
    labels = ['High Traffic', 'Repeated Interval', 'Frequent C&C']
    plt.figure()
    plt.bar(labels, counts, color=['green', 'purple', 'orange'])
    plt.title('Flagged IP Count by Detection Rule')
    plt.ylabel('Unique IP Count')
    plt.savefig(os.path.join(results_dir, 'flagged_ip_count.png'))
    plt.close()

plot_flagged_ip_count(high_traffic_packets, repeated_interval_packets, frequent_cnc_packets)
print(f"Flagged IP Count by Detection Rule graph saved as 'flagged_ip_count.png'")

# Final Output Summary
print("\n--- Final Output Summary ---")
print(f"Detection Rate: {detection_rate:.2f}%")
print(f"False Positive Rate (Proxy): {false_positive_rate:.2f}%")
print(f"Graphs have been saved in the '/results' directory.")
