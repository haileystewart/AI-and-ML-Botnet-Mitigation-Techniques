"""
feature_extraction.py

This script extracts meaningful features from the pre-processed network traffic files.
The key features to extract include:
- Packet sizes
- Communication frequency between bots and the C2 server
- Traffic volume (number of packets and data transferred over time)

The extracted data will be used in the traffic pattern analysis and visualization stages.
"""

import pandas as pd
import os

# Define the dataset paths
dataset_paths = [
    'C:/Users/hailey/botnet-detection-ml-techniques/src/phase2/processed_data/botnet-capture-20110810-neris_processed.csv',
    'C:/Users/hailey/botnet-detection-ml-techniques/src/phase2/processed_data/botnet-capture-20110811-neris_processed.csv',
    'C:/Users/hailey/botnet-detection-ml-techniques/src/phase2/processed_data/botnet-capture-20110812-rbot_processed.csv',
    'C:/Users/hailey/botnet-detection-ml-techniques/src/phase2/processed_data/botnet-capture-20110815-fast-flux_processed.csv',
    'C:/Users/hailey/botnet-detection-ml-techniques/src/phase2/processed_data/botnet-capture-20110815-fast-flux-2_processed.csv',
    'C:/Users/hailey/botnet-detection-ml-techniques/src/phase2/processed_data/botnet-capture-20110815-rbot-dos_processed.csv',
    'C:/Users/hailey/botnet-detection-ml-techniques/src/phase2/processed_data/botnet-capture-20110816-donbot_processed.csv',
    'C:/Users/hailey/botnet-detection-ml-techniques/src/phase2/processed_data/botnet-capture-20110816-qvod_processed.csv',
    'C:/Users/hailey/botnet-detection-ml-techniques/src/phase2/processed_data/botnet-capture-20110816-sogou_processed.csv',
    'C:/Users/hailey/botnet-detection-ml-techniques/src/phase2/processed_data/botnet-capture-20110817-bot_processed.csv',
    'C:/Users/hailey/botnet-detection-ml-techniques/src/phase2/processed_data/botnet-capture-20110818-bot-2_processed.csv',
    'C:/Users/hailey/botnet-detection-ml-techniques/src/phase2/processed_data/botnet-capture-20110818-filtered_processed.csv',
    'C:/Users/hailey/botnet-detection-ml-techniques/src/phase2/processed_data/botnet-capture-20110819-bot_processed.csv'
]

# Define the base output directory for extracted features
output_dir = "C:/Users/hailey/botnet-detection-ml-techniques/src/phase2/processed_data/feature_extraction"

# Create subdirectories for each feature type
packet_sizes_dir = os.path.join(output_dir, "packet_sizes")
communication_freq_dir = os.path.join(output_dir, "communication_frequency")
traffic_volume_dir = os.path.join(output_dir, "traffic_volume")

os.makedirs(packet_sizes_dir, exist_ok=True)
os.makedirs(communication_freq_dir, exist_ok=True)
os.makedirs(traffic_volume_dir, exist_ok=True)

def extract_packet_sizes(df):
    """
    Extract packet size information from the network traffic data.
    Args:
    df (DataFrame): Pre-processed traffic data
    Returns:
    DataFrame: Packet size data for analysis
    """
    packet_sizes = df[['packet_size']]  # Assuming packet size is stored in a column named 'packet_size'
    return packet_sizes

def extract_communication_frequency(df):
    """
    Extract communication frequency between bots and the C2 server.
    Args:
    df (DataFrame): Pre-processed traffic data
    Returns:
    DataFrame: Communication frequency data
    """
    communication_freq = df.groupby(['src_ip', 'dst_ip']).size().reset_index(name='communication_count')
    return communication_freq

def extract_traffic_volume(df):
    """
    Extract traffic volume over time (number of packets and data transferred).
    Args:
    df (DataFrame): Pre-processed traffic data
    Returns:
    DataFrame: Traffic volume data with timestamps
    """
    traffic_volume = df.groupby('timestamp').agg(
        packet_size_sum=('packet_size', 'sum'),  # Sum of packet sizes gives total data transferred at a given time
        packet_count=('packet_size', 'count')    # Count the number of packets transferred at a given time
    ).reset_index()
    
    return traffic_volume

if __name__ == "__main__":
    for dataset_path in dataset_paths:
        # Load each dataset
        if not os.path.exists(dataset_path):
            print(f"File not found: {dataset_path}")
            continue
        
        print(f"Processing {dataset_path}...")
        traffic_data = pd.read_csv(dataset_path)
        
        # Extract features
        packet_sizes = extract_packet_sizes(traffic_data)
        communication_freq = extract_communication_frequency(traffic_data)
        traffic_volume = extract_traffic_volume(traffic_data)
        
        # Define output file names based on the input file name
        base_name = os.path.basename(dataset_path).replace('_processed.csv', '')

        # Save each feature type to its respective folder
        packet_sizes.to_csv(f'{packet_sizes_dir}/{base_name}_packet_sizes.csv', index=False)
        communication_freq.to_csv(f'{communication_freq_dir}/{base_name}_communication_frequency.csv', index=False)
        traffic_volume.to_csv(f'{traffic_volume_dir}/{base_name}_traffic_volume.csv', index=False)
        
        print(f"Extracted features saved for {base_name}.\n")
