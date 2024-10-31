"""
Botnet Architecture Analysis Script

This script analyzes botnet traffic using the CTU-13 dataset.
It extracts communication patterns, IP addresses, packet sizes, and timestamps from the provided .pcap files.
The goal is to study real botnet behavior in the dataset and document patterns related to C&C communication.
"""

import pyshark
import pandas as pd
import os
from datetime import datetime
import matplotlib.pyplot as plt

# Paths to CTU-13 dataset files
dataset_paths = [
    os.path.join("..", "..", "CTU-13-Dataset", "1", "botnet-capture-20110810-neris.pcap"),
    os.path.join("..", "..", "CTU-13-Dataset", "2", "botnet-capture-20110811-neris.pcap"),
    os.path.join("..", "..", "CTU-13-Dataset", "3", "botnet-capture-20110812-rbot.pcap"),
    os.path.join("..", "..", "CTU-13-Dataset", "4", "botnet-capture-20110815-rbot-dos.pcap"),
    os.path.join("..", "..", "CTU-13-Dataset", "5", "botnet-capture-20110815-fast-flux.pcap"),
    os.path.join("..", "..", "CTU-13-Dataset", "6", "botnet-capture-20110816-donbot.pcap"),
    os.path.join("..", "..", "CTU-13-Dataset", "7", "botnet-capture-20110816-sogou.pcap"),
    os.path.join("..", "..", "CTU-13-Dataset", "8", "botnet-capture-20110816-qvod.pcap"),
    os.path.join("..", "..", "CTU-13-Dataset", "9", "botnet-capture-20110817-bot.pcap"),
    os.path.join("..", "..", "CTU-13-Dataset", "10", "botnet-capture-20110818-filtered.pcap"),
    os.path.join("..", "..", "CTU-13-Dataset", "11", "botnet-capture-20110818-bot-2.pcap"),
    os.path.join("..", "..", "CTU-13-Dataset", "12", "botnet-capture-20110819-bot.pcap"),
    os.path.join("..", "..", "CTU-13-Dataset", "13", "botnet-capture-20110815-fast-flux-2.pcap"),
]

# Base output directory for processed data
base_output_dir = "C:/Users/hailey/botnet-detection-ml-techniques/src/phase1/processed_data"
os.makedirs(base_output_dir, exist_ok=True)

def analyze_pcap(file_path, sample_size=1000):
    """
    Analyze a sample of a pcap file to extract botnet communication patterns.

    Args:
        file_path (str): Path to the pcap file
        sample_size (int): Number of packets to sample for testing

    Returns:
        DataFrame: A DataFrame containing extracted data for analysis
    """
    try:
        cap = pyshark.FileCapture(file_path, display_filter="ip")  # Filtering IP packets only
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return pd.DataFrame()  # Return an empty DataFrame if loading fails

    data = []

    # Process only a sample to test logic; adjust sample_size for larger processing
    for i, pkt in enumerate(cap):
        if i >= sample_size:  # Limit to sample size
            break
        try:
            # Extract key packet data
            src_ip = pkt.ip.src
            dst_ip = pkt.ip.dst
            protocol = pkt.transport_layer
            packet_size = int(pkt.length)
            timestamp = pkt.sniff_time

            data.append({
                'timestamp': timestamp,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'protocol': protocol,
                'packet_size': packet_size
            })
        except AttributeError:
            # Skip packets without expected fields
            continue

    cap.close()
    df = pd.DataFrame(data)
    df.drop_duplicates(inplace=True)
    return df

def analyze_ctu13_datasets():
    """
    Analyze each pcap file in the CTU-13 dataset to document botnet communication patterns.
    """
    for file_path in dataset_paths:
        print(f"Analyzing {file_path}...")
        data = analyze_pcap(file_path, sample_size=1000)
        if data.empty:
            continue

        # Determine dataset number from the file path
        dataset_number = os.path.basename(os.path.dirname(file_path))

        # Create a unique directory for each dataset
        dataset_output_dir = os.path.join(base_output_dir, dataset_number)
        os.makedirs(dataset_output_dir, exist_ok=True)

        # Architecture Comparison: Centralized vs. Decentralized
        ip_comm_freq = data.groupby(['src_ip', 'dst_ip']).size().reset_index(name='comm_count')
        centralized_ips = ip_comm_freq['dst_ip'].value_counts().head(10)
        
        # Save Top communication frequencies as CSV
        top_communication_freq_path = os.path.join(dataset_output_dir, f"dataset_{dataset_number}_top_communication_freq.csv")
        centralized_ips.to_frame(name='frequency').reset_index().to_csv(top_communication_freq_path, index=False)
        print(f"Top communication frequencies saved to {top_communication_freq_path}")

        # Frequency of C2 Communication
        c2_communication = data.groupby('dst_ip').size().reset_index(name='c2_comm_count')
        
        # Save C2 communication frequencies as CSV
        c2_comm_freq_path = os.path.join(dataset_output_dir, f"dataset_{dataset_number}_c2_comm_freq.csv")
        c2_communication.to_csv(c2_comm_freq_path, index=False)
        print(f"C2 communication frequencies saved to {c2_comm_freq_path}")

        # Summary of Protocols Used
        protocol_counts = data['protocol'].value_counts()

        # Detect DDoS Indicators and Anomalies
        udp_data = data[data['protocol'] == 'UDP']
        if not udp_data.empty:
            udp_freq = udp_data['timestamp'].value_counts()
            
            # Save UDP traffic frequency summary as CSV
            udp_freq_summary_path = os.path.join(dataset_output_dir, f"dataset_{dataset_number}_udp_freq_summary.csv")
            udp_freq.describe().to_frame(name='UDP_Frequency_Stats').to_csv(udp_freq_summary_path, index=True)
            print(f"UDP frequency summary saved to {udp_freq_summary_path}")

        # Save Packet Size Distribution Histogram as a figure
        plt.figure(figsize=(8, 6))
        plt.hist(data['packet_size'], bins=50, color='skyblue', edgecolor='black')
        plt.xlabel('Packet Size (Bytes)')
        plt.ylabel('Frequency')
        plt.title(f'Packet Size Distribution - Dataset {dataset_number}')
        
        fig_path = os.path.join(dataset_output_dir, f"dataset_{dataset_number}_packet_size_distribution.png")
        plt.savefig(fig_path)
        plt.close()
        print(f"Packet size distribution saved to {fig_path}")

        # Summarize and save results for each dataset
        results = {
            'Dataset': f"Dataset {dataset_number}",
            'Unique Src IPs': data['src_ip'].nunique(),
            'Unique Dst IPs': data['dst_ip'].nunique(),
            'Average Packet Size': data['packet_size'].mean(),
            'Protocol Distribution': protocol_counts.to_dict(),
            'UDP Traffic Peak': udp_freq.max() if not udp_data.empty else 'N/A'
        }

        summary_path = os.path.join(dataset_output_dir, f"dataset_{dataset_number}_summary.csv")
        pd.DataFrame([results]).to_csv(summary_path, index=False)
        print(f"Summary saved to {summary_path}\n")

if __name__ == "__main__":
    analyze_ctu13_datasets()
