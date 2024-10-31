"""
traffic_visualization.py

This script generates visualizations of the analyzed network traffic using Matplotlib. 
The visualizations include:
- Packet Size Distribution: Histogram showing the distribution of packet sizes.
- Communication Frequency: Bar chart showing the frequency of communication between bots and the C2 server.
- Traffic Volume Over Time: Line graph showing the total packet size transferred over time.

The generated graphs will be saved in the /phase2/results directory, separated into folders based on the dataset number.
"""

import pandas as pd
import matplotlib.pyplot as plt
import os

# Ensure the base results directory exists
base_results_dir = 'C:/Users/hailey/botnet-detection-ml-techniques/src/phase2/results'
os.makedirs(base_results_dir, exist_ok=True)

# Mapping of dataset names to folder numbers
dataset_folder_map = {
    "20110810-neris": "1",
    "20110811-neris": "2",
    "20110812-rbot": "3",
    "20110815-rbot-dos": "4",
    "20110815-fast-flux": "5",
    "20110816-donbot": "6",
    "20110816-sogou": "7",
    "20110816-qvod": "8",
    "20110817-bot": "9",
    "20110818-filtered": "10",
    "20110818-bot-2": "11",
    "20110819-bot": "12",
    "20110815-fast-flux-2": "13",
}

# Define paths to the extracted feature files
packet_sizes_dir = 'C:/Users/hailey/botnet-detection-ml-techniques/src/phase2/processed_data/feature_extraction/packet_sizes'
communication_freq_dir = 'C:/Users/hailey/botnet-detection-ml-techniques/src/phase2/processed_data/feature_extraction/communication_frequency'
traffic_volume_dir = 'C:/Users/hailey/botnet-detection-ml-techniques/src/phase2/processed_data/feature_extraction/traffic_volume'

# Step 1: Generate Packet Size Distribution Histogram
def plot_packet_size_distribution(df, base_name, output_dir):
    plt.figure(figsize=(8, 6))
    filtered_df = df[df['packet_size'] <= 2000]  # Limit packet size range to 2000 bytes
    plt.hist(filtered_df['packet_size'], bins=50, color='skyblue', edgecolor='black')
    plt.yscale('log')  # Use log scale for the y-axis to reveal patterns in lower frequencies
    plt.title(f'Packet Size Distribution - {base_name}')
    plt.xlabel('Packet Size (Bytes)')
    plt.ylabel('Frequency (Log Scale)')
    plt.grid(True)
    plt.savefig(os.path.join(output_dir, f'{base_name}_packet_size_distribution.png'))
    plt.close()

# Step 2: Generate Communication Frequency Bar Chart
def plot_communication_frequency(df, base_name, output_dir, threshold=100):
    # Ensure communication_count column is of integer type
    df['communication_count'] = pd.to_numeric(df['communication_count'], errors='coerce').fillna(0).astype(int)

    # Filter IPs below the threshold
    df = df[df['communication_count'] >= threshold]
    
    # Focus on the top 20 most frequent communicators
    top_ips = df.nlargest(20, 'communication_count')
    
    plt.figure(figsize=(10, 6))
    plt.bar(top_ips['src_ip'], top_ips['communication_count'], color='salmon')
    plt.title(f'Communication Frequency Between Bots and C2 Server - {base_name}')
    plt.xlabel('Bot IP Address')
    plt.ylabel('Number of Communications')
    plt.xticks(rotation=45, ha='right')
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, f'{base_name}_communication_frequency.png'))
    plt.close()

# Step 3: Generate Traffic Volume Over Time Line Graph
def plot_traffic_volume_over_time(df, base_name, output_dir, interval='5min'):
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df.set_index('timestamp', inplace=True)
    resampled_df = df.resample(interval).sum()  # Aggregate over specified time interval
    resampled_df['packet_count_smooth'] = resampled_df['packet_count'].rolling(window=5, min_periods=1).mean()  # Smoothing
    plt.figure(figsize=(10, 6))
    plt.plot(resampled_df.index, resampled_df['packet_count_smooth'], marker='o', linestyle='-', color='purple')
    plt.title(f'Traffic Volume Over Time - {base_name}')
    plt.xlabel('Time')
    plt.ylabel('Packet Count (Smoothed)')
    plt.xticks(rotation=45)
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, f'{base_name}_traffic_volume_over_time.png'))
    plt.close()

if __name__ == "__main__":
    # Iterate through each dataset and create visualizations
    for feature_dir, plot_function in [
        (packet_sizes_dir, plot_packet_size_distribution),
        (communication_freq_dir, plot_communication_frequency),
        # Pass interval explicitly for the traffic volume visualization
        (traffic_volume_dir, lambda df, base_name, output_dir: plot_traffic_volume_over_time(df, base_name, output_dir, interval='5min'))
    ]:
        for filename in os.listdir(feature_dir):
            file_path = os.path.join(feature_dir, filename)
            
            # Strip the prefix "botnet-capture-" from the base_name before mapping
            base_name = filename.replace("botnet-capture-", "").replace('_packet_sizes.csv', '').replace('_communication_frequency.csv', '').replace('_traffic_volume.csv', '')

            # Determine the corresponding folder number using the mapping
            folder_number = dataset_folder_map.get(base_name)
            if folder_number is None:
                print(f"Dataset {base_name} not recognized in mapping. Skipping...")
                continue

            # Create the results subdirectory for the dataset
            output_dir = os.path.join(base_results_dir, folder_number)
            os.makedirs(output_dir, exist_ok=True)
            
            print(f"Processing {filename} for Dataset {folder_number}...")

            # Load the data and generate the corresponding plot based on feature type
            df = pd.read_csv(file_path)
            plot_function(df, base_name, output_dir)

    print("Phase 2 visualizations saved to /results/phase2/, organized by dataset folders.")
