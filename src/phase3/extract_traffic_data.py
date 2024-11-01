import os
import subprocess
import gzip
import pandas as pd

# Define the paths to each PCAP file in the CTU-13 dataset
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

# Define output directory for the extracted CSV files in phase3 processed data
output_base_dir = os.path.join(os.path.dirname(__file__), 'processed_data')
os.makedirs(output_base_dir, exist_ok=True)

# Sampling rate: Keep every nth packet (e.g., every 10th packet)
sample_rate = 10

# Loop through each dataset path and run the tshark command
for index, dataset_path in enumerate(dataset_paths):
    # Set the dataset ID based on its index in the list (1 to 13)
    dataset_id = str(index + 1)
    output_dir = os.path.join(output_base_dir, dataset_id)
    os.makedirs(output_dir, exist_ok=True)  # Ensure the directory exists for each dataset

    # Define output file path for the compressed .gz file
    output_file = os.path.join(output_dir, f"extracted_traffic_{dataset_id}.csv.gz")

    # Command to extract relevant fields using tshark with filtering and compression
    tshark_command = [
        "C:\\Program Files\\Wireshark\\tshark.exe",
        "-r", dataset_path,
        "-T", "fields",
        "-e", "frame.time",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "frame.len",
        "-e", "frame.time_delta",
        "-Y", "frame.len >= 100",  # Filter out packets smaller than 100 bytes
        "-E", "header=y",
        "-E", "separator=,"
    ]

    # Run tshark command and compress output to a .gz file
    with gzip.open(output_file, "wt") as f:
        try:
            result = subprocess.run(tshark_command, stdout=subprocess.PIPE, text=True, check=True)
            lines = result.stdout.splitlines()

            # Write header
            f.write(lines[0] + '\n') 

            # Write every nth packet based on the sample rate
            for i, line in enumerate(lines[1:], start=1):
                if i % sample_rate == 0:
                    f.write(line + '\n')

            print(f"Extracted and compressed data for dataset {dataset_id} to {output_file}")
        except subprocess.CalledProcessError as e:
            print(f"Error processing {dataset_path}: {e}")
