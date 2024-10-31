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

# Define the base path to the processed data for each dataset (1 to 13)
base_path = "C:/Users/hailey/botnet-detection-ml-techniques/src/phase2/processed_data"

# Define paths for each processed dataset CSV file, located in their respective folders
dataset_paths = [
    os.path.join(base_path, "1", "botnet-capture-20110810-neris_processed.csv"),
    os.path.join(base_path, "2", "botnet-capture-20110811-neris_processed.csv"),
    os.path.join(base_path, "3", "botnet-capture-20110812-rbot_processed.csv"),
    os.path.join(base_path, "4", "botnet-capture-20110815-rbot-dos_processed.csv"),
    os.path.join(base_path, "5", "botnet-capture-20110815-fast-flux_processed.csv"),
    os.path.join(base_path, "6", "botnet-capture-20110816-donbot_processed.csv"),
    os.path.join(base_path, "7", "botnet-capture-20110816-sogou_processed.csv"),
    os.path.join(base_path, "8", "botnet-capture-20110816-qvod_processed.csv"),
    os.path.join(base_path, "9", "botnet-capture-20110817-bot_processed.csv"),
    os.path.join(base_path, "10", "botnet-capture-20110818-filtered_processed.csv"),
    os.path.join(base_path, "11", "botnet-capture-20110818-bot-2_processed.csv"),
    os.path.join(base_path, "12", "botnet-capture-20110819-bot_processed.csv"),
    os.path.join(base_path, "13", "botnet-capture-20110815-fast-flux-2_processed.csv"),
]

def extract_packet_sizes(df):
    """Extract packet size information from the network traffic data."""
    return df[['packet_size']]

def extract_communication_frequency(df):
    """Extract communication frequency between bots and the C2 server."""
    return df.groupby(['src_ip', 'dst_ip']).size().reset_index(name='communication_count')

def extract_traffic_volume(df):
    """Extract traffic volume over time (number of packets and data transferred)."""
    return df.groupby('timestamp').agg(
        packet_size_sum=('packet_size', 'sum'),
        packet_count=('packet_size', 'count')
    ).reset_index()

if __name__ == "__main__":
    for dataset_path in dataset_paths:
        # Check if the dataset file exists
        if not os.path.exists(dataset_path):
            print(f"File not found: {dataset_path}")
            continue
        
        print(f"Processing {dataset_path}...")
        traffic_data = pd.read_csv(dataset_path)
        
        # Extract the dataset number from the path
        dataset_number = os.path.basename(os.path.dirname(dataset_path))
        
        # Define the output directory for each dataset
        dataset_output_dir = os.path.join(base_path, dataset_number)
        os.makedirs(dataset_output_dir, exist_ok=True)

        # Extract features
        packet_sizes = extract_packet_sizes(traffic_data)
        communication_freq = extract_communication_frequency(traffic_data)
        traffic_volume = extract_traffic_volume(traffic_data)
        
        # Define output paths for each feature type within the dataset folder
        base_name = os.path.basename(dataset_path).replace('_processed.csv', '')
        packet_sizes.to_csv(os.path.join(dataset_output_dir, f"{base_name}_packet_sizes.csv"), index=False)
        communication_freq.to_csv(os.path.join(dataset_output_dir, f"{base_name}_communication_frequency.csv"), index=False)
        traffic_volume.to_csv(os.path.join(dataset_output_dir, f"{base_name}_traffic_volume.csv"), index=False)
        
        print(f"Extracted features saved for Dataset {dataset_number}.\n")
