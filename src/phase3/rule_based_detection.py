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

The generated graphs will be saved in the /results/phase3 directory for further analysis and documentation.
"""

import pandas as pd
import matplotlib.pyplot as plt
import os

# Ensure the /results/phase3 directory exists
os.makedirs('../results/phase3', exist_ok=True)

# Load the pre-processed traffic data from the updated path under phase3/processed_data
traffic_data = pd.read_csv('C:/Users/hailey/botnet-detection-ml-techniques/src/phase3/processed_data/processed_traffic_data.csv')

# Detection rules configuration
PACKET_SIZE_THRESHOLD = 75
CNC_REQUEST_THRESHOLD = 2
TIME_INTERVAL_THRESHOLD = 2

# Detection functions
def detect_high_traffic_volume(df, size_threshold):
    flagged_packets = df[df['packet_size'] > size_threshold]
    return flagged_packets

def detect_frequent_cnc_requests(df, request_threshold):
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    cnc_requests = df.groupby([df['timestamp'].dt.floor('S'), 'src_ip']).size().reset_index(name='request_count')
    flagged_requests = cnc_requests[cnc_requests['request_count'] > request_threshold]
    return flagged_requests

def detect_repeated_time_intervals(df, time_interval_threshold):
    flagged_intervals = df[df['time_interval'] == time_interval_threshold]
    return flagged_intervals

# Apply detection rules
high_traffic_packets = detect_high_traffic_volume(traffic_data, PACKET_SIZE_THRESHOLD)
frequent_cnc_packets = detect_frequent_cnc_requests(traffic_data, CNC_REQUEST_THRESHOLD)
repeated_interval_packets = detect_repeated_time_intervals(traffic_data, TIME_INTERVAL_THRESHOLD)

# Combine all flagged packets
flagged_packets = pd.concat([high_traffic_packets, frequent_cnc_packets, repeated_interval_packets]).drop_duplicates()

# Step 4: Create comparison graphs
def plot_detection_rate_vs_false_positive_rate(detection_rate, false_positive_rate):
    plt.figure(figsize=(8, 6))
    plt.bar(['Detection Rate', 'False Positive Rate'], [detection_rate, false_positive_rate], color='green')
    plt.title('Detection Rate vs False Positive Rate')
    plt.ylabel('Percentage (%)')
    plt.savefig('../results/phase3/detection_vs_false_positive_rate.png')
    plt.close()

def plot_detection_accuracy_over_time(accuracy_over_time):
    plt.figure(figsize=(8, 6))
    plt.plot(accuracy_over_time['time'], accuracy_over_time['accuracy'], marker='o', color='blue')
    plt.title('Detection Accuracy Over Time')
    plt.xlabel('Time (Seconds)')
    plt.ylabel('Accuracy (%)')
    plt.savefig('../results/phase3/detection_accuracy_over_time.png')
    plt.close()

# Evaluate Detection Performance
def evaluate_detection(flagged_packets, actual_traffic):
    total_packets = len(actual_traffic)
    true_positives = len(flagged_packets[flagged_packets['is_botnet'] == True])
    false_positives = len(flagged_packets[flagged_packets['is_botnet'] == False])
    accuracy = true_positives / total_packets * 100 if total_packets > 0 else 0
    false_positive_rate = false_positives / total_packets * 100 if total_packets > 0 else 0
    return accuracy, false_positive_rate

# Generate detection metrics
accuracy, false_positive_rate = evaluate_detection(flagged_packets, traffic_data)

# Plot results
plot_detection_rate_vs_false_positive_rate(accuracy, false_positive_rate)
accuracy_over_time = pd.DataFrame({'time': [0, 1, 2], 'accuracy': [accuracy] * 3})
plot_detection_accuracy_over_time(accuracy_over_time)

print("Phase 3 comparison graphs saved to /results/phase3/")
