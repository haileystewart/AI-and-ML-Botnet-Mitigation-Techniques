# Phase 2: Network Traffic Analysis

## Overview
In Phase 2, the objective was to analyze botnet traffic across a series of simulated datasets to extract patterns that could improve botnet detection methods. We pre-processed the captured traffic, extracted meaningful features, and visualized the traffic patterns, providing insights into botnet communication behaviors and C2 (Command and Control) server interactions.

---

## Key Tasks

### 1. Pre-process the Captured Traffic (`traffic_analysis.py`)
- **Data Source**: Filtered Wireshark-captured network traffic across 13 datasets from the CTU-13 dataset.
- **Key Features Extracted**:
  - **Packet Size**: Enabled us to see data volume trends in communication across various datasets.
  - **Protocol Type**: Communications used both TCP and UDP protocols, with some datasets showing a high frequency of UDP traffic likely associated with DDoS or spamming behavior.
  - **Time Intervals Between Packets**: Allowed tracking of communication frequency and timing variations across datasets.
  - **Frequency of C&C Requests**: Highlighted communication patterns with the C2 server, revealing frequent requests in some datasets while others had fewer, less consistent interactions.

### 2. Feature Extraction (`feature_extraction.py`)
- **Processed Features**:
  - **Packet Size Distribution**: Aggregated packet sizes across each dataset revealed differences in data transfer volume, likely reflecting varied botnet tasks.
  - **Communication Frequency Between Bots and the C2 Server**: Showed varying interaction levels, with some datasets featuring high-frequency communications while others had minimal interactions.
  - **Traffic Volume Over Time**: Aggregated data highlighted traffic spikes in certain datasets, potentially indicating DDoS activity or increased C&C traffic.

### 3. Traffic Pattern Identification and Visualization (`traffic_visualization.py`)
- **Visualizations Generated Using Matplotlib**:
  - **Packet Size Distribution**: Displayed packet sizes, often focusing on a limited range (0–2000 bytes) to better highlight patterns.
  - **Communication Frequency**: For datasets with numerous IPs, we filtered out low-communication IPs and focused on the top communicators with the C2 server.
  - **Traffic Volume Over Time**: Aggregated traffic over 5-minute intervals with data smoothing to show trends and spikes.

---

## Key Insights

- **Packet Size Distribution**: Packet sizes varied across datasets, with some datasets showing clusters around lower sizes, indicating potential C&C messaging, while others included larger packets, likely data exfiltration or spamming. Log scaling revealed patterns in less frequent packet sizes.
  - **Example**: ![Packet Size Distribution](../results/phase2/1/20110810-neris_packet_size_distribution.png)

- **Communication Frequency**: Datasets showed differences in bot-to-C2 server communication. Some datasets (e.g., `20110816-qvod`) revealed concentrated communication from a few IPs, while others had dispersed patterns. By filtering out low-frequency IPs, we identified key bot IPs with high communication counts.
  - **Example**: ![Communication Frequency](../results/phase2/1/20110810-neris_communication_frequency.png)

- **Traffic Volume Over Time**: Certain datasets exhibited significant spikes, especially those using UDP for potentially disruptive activities (e.g., spamming or DDoS attacks). Aggregating traffic over time intervals helped reveal peak activity, highlighting potential malicious behavior.
  - **Example**: ![Traffic Volume Over Time](../results/phase2/1/20110810-neris_traffic_volume_over_time.png)

---

## Additional Adjustments and Insights

### Filtering and Aggregation
- **Packet Sizes**: Restricted to a 0–2000 byte range for better clarity, with log scaling to reveal less frequent patterns.
- **Communication Frequency Graphs**: Focused on top communicators by filtering out low-communication IPs, allowing us to emphasize key bot-to-C2 interactions.
- **Traffic Volume**: Aggregated over larger time intervals and smoothed, reducing noise and highlighting peak periods.

### Distinct Patterns Across Datasets
- **TCP and UDP Usage**: Certain datasets featured predominantly TCP traffic with uniform packet sizes, suggesting standard C&C communication.
- **High UDP Traffic**: Indicative of potential DDoS or spamming activity in some datasets. Analyzing protocol distribution and packet sizes across datasets provided insights into different botnet activities.

---

## Deliverables

- **`traffic_analysis.py`**: Script for parsing and pre-processing traffic data across multiple datasets.
- **`feature_extraction.py`**: Script for extracting and saving key traffic features.
- **`traffic_visualization.py`**: Script for visualizing traffic patterns and organizing results into dataset-specific folders.
- **Traffic Graphs**: Detailed visualizations for each dataset:
  - Packet Size Distribution
  - Communication Frequency
  - Traffic Volume Over Time
- **Storage**: All graphs are stored in `/results/phase2/`, organized by dataset folders for easy reference and comparison.
