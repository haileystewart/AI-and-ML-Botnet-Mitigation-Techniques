# Phase 1: Understanding Botnet Architecture and Detection Methods

## Overview
The purpose of Phase 1 was to analyze botnet architecture by examining communication patterns, attack methods, and existing detection techniques. Through the CTU-13 dataset, we studied different botnet behaviors, identifying key features that can aid in creating enhanced detection strategies in subsequent phases.

## Botnet Architecture and Communication Models
Botnets generally use one of two main architectures:
- **Centralized**: Bots communicate with a specific Command and Control (C&C) server, which can be detected if the server IPs are known.
- **Decentralized (Peer-to-Peer)**: Bots communicate with each other, forming a distributed network that is more challenging to detect and disrupt.

## Attack Methods Observed
Across the analyzed datasets, we observed various botnet attack strategies:
- **Distributed Denial of Service (DDoS)**: High UDP traffic volumes indicated potential DDoS activity.
- **Data Exfiltration and Spam**: Characterized by specific packet sizes and frequent TCP traffic.

## Detection Techniques Applied
To extract botnet behaviors, we focused on three detection techniques:
1. **Signature-Based Detection**: Looked for known patterns in botnet communication.
2. **Behavior-Based Detection**: Monitored network activity for abnormal patterns.
3. **Anomaly-Based Detection**: Used statistical models to identify deviations from typical traffic baselines, which is useful for detecting new or unknown botnet behaviors.

## Detailed Analysis of CTU-13 Dataset

### Findings and File Links for Each Dataset
For each pcap file in the CTU-13 dataset, we analyzed key metrics such as unique IPs, protocol usage, and packet size distribution. Here’s a summary of the results along with links to detailed data:

| Dataset | Unique Src IPs | Unique Dst IPs | Protocol Dist. (TCP/UDP) | Packet Size (Mean) | Top Communication Frequencies | C2 Communication Frequencies | UDP Traffic Summary | Packet Size Distribution |
|---------|----------------|----------------|---------------------------|---------------------|-------------------------------|-----------------------------|----------------------|---------------------------|
| 1       | 14            | 27             | 884 TCP / 111 UDP         | 460 bytes          | [Top Freq](processed_data/1/dataset_1_top_communication_freq.csv) | [C2 Freq](processed_data/1/dataset_1_c2_comm_freq.csv) | [UDP Summary](processed_data/1/dataset_1_udp_freq_summary.csv) | [Packet Dist](processed_data/1/dataset_1_packet_size_distribution.png) |
| 2       | 17            | 18             | 790 TCP / 194 UDP         | 462 bytes          | [Top Freq](processed_data/2/dataset_2_top_communication_freq.csv) | [C2 Freq](processed_data/2/dataset_2_c2_comm_freq.csv) | [UDP Summary](processed_data/2/dataset_2_udp_freq_summary.csv) | [Packet Dist](processed_data/2/dataset_2_packet_size_distribution.png) |
| 3       | 77            | 88             | 992 TCP / 8 UDP           | 77 bytes           | [Top Freq](processed_data/3/dataset_3_top_communication_freq.csv) | [C2 Freq](processed_data/3/dataset_3_c2_comm_freq.csv) | [UDP Summary](processed_data/3/dataset_3_udp_freq_summary.csv) | [Packet Dist](processed_data/3/dataset_3_packet_size_distribution.png) |
| 4       | 6             | 11             | 359 TCP / 322 UDP         | 526 bytes          | [Top Freq](processed_data/4/dataset_4_top_communication_freq.csv) | [C2 Freq](processed_data/4/dataset_4_c2_comm_freq.csv) | [UDP Summary](processed_data/4/dataset_4_udp_freq_summary.csv) | [Packet Dist](processed_data/4/dataset_4_packet_size_distribution.png) |
| 5       | 9             | 22             | 895 TCP / 99 UDP          | 433 bytes          | [Top Freq](processed_data/5/dataset_5_top_communication_freq.csv) | [C2 Freq](processed_data/5/dataset_5_c2_comm_freq.csv) | [UDP Summary](processed_data/5/dataset_5_udp_freq_summary.csv) | [Packet Dist](processed_data/5/dataset_5_packet_size_distribution.png) |
| 6       | 2             | 2              | 999 TCP                   | 738 bytes          | [Top Freq](processed_data/6/dataset_6_top_communication_freq.csv) | [C2 Freq](processed_data/6/dataset_6_c2_comm_freq.csv) | N/A                      | [Packet Dist](processed_data/6/dataset_6_packet_size_distribution.png) |
| 7       | 10            | 14             | 940 TCP / 56 UDP          | 509 bytes          | [Top Freq](processed_data/7/dataset_7_top_communication_freq.csv) | [C2 Freq](processed_data/7/dataset_7_c2_comm_freq.csv) | [UDP Summary](processed_data/7/dataset_7_udp_freq_summary.csv) | [Packet Dist](processed_data/7/dataset_7_packet_size_distribution.png) |
| 8       | 10            | 11             | 925 TCP / 73 UDP          | 635 bytes          | [Top Freq](processed_data/8/dataset_8_top_communication_freq.csv) | [C2 Freq](processed_data/8/dataset_8_c2_comm_freq.csv) | [UDP Summary](processed_data/8/dataset_8_udp_freq_summary.csv) | [Packet Dist](processed_data/8/dataset_8_packet_size_distribution.png) |
| 9       | 9             | 20             | 971 TCP / 29 UDP          | 368 bytes          | [Top Freq](processed_data/9/dataset_9_top_communication_freq.csv) | [C2 Freq](processed_data/9/dataset_9_c2_comm_freq.csv) | [UDP Summary](processed_data/9/dataset_9_udp_freq_summary.csv) | [Packet Dist](processed_data/9/dataset_9_packet_size_distribution.png) |
| 10      | 19            | 23             | 297 TCP / 654 UDP         | 136 bytes          | [Top Freq](processed_data/10/dataset_10_top_communication_freq.csv) | [C2 Freq](processed_data/10/dataset_10_c2_comm_freq.csv) | [UDP Summary](processed_data/10/dataset_10_udp_freq_summary.csv) | [Packet Dist](processed_data/10/dataset_10_packet_size_distribution.png) |
| 11      | 11            | 15             | 789 TCP / 198 UDP         | 106 bytes          | [Top Freq](processed_data/11/dataset_11_top_communication_freq.csv) | [C2 Freq](processed_data/11/dataset_11_c2_comm_freq.csv) | [UDP Summary](processed_data/11/dataset_11_udp_freq_summary.csv) | [Packet Dist](processed_data/11/dataset_11_packet_size_distribution.png) |
| 12      | 7             | 6              | 949 TCP / 50 UDP          | 804 bytes          | [Top Freq](processed_data/12/dataset_12_top_communication_freq.csv) | [C2 Freq](processed_data/12/dataset_12_c2_comm_freq.csv) | [UDP Summary](processed_data/12/dataset_12_udp_freq_summary.csv) | [Packet Dist](processed_data/12/dataset_12_packet_size_distribution.png) |
| 13      | 9             | 44             | 940 TCP / 60 UDP          | 440 bytes          | [Top Freq](processed_data/13/dataset_13_top_communication_freq.csv) | [C2 Freq](processed_data/13/dataset_13_c2_comm_freq.csv) | [UDP Summary](processed_data/13/dataset_13_udp_freq_summary.csv) | [Packet Dist](processed_data/13/dataset_13_packet_size_distribution.png) |

### Notable Observations

1. **Centralized vs. Decentralized Architecture**:
   - Across datasets, most botnets displayed centralized architecture, evident by the frequent communication with specific IPs likely representing C&C servers.
   - The communication patterns (as seen in the top communication frequencies for each dataset) showed that each botnet had a limited set of destination IPs for C&C.

2. **Protocol Distribution**:
   - TCP was the dominant protocol in most captures, used for stable, reliable communication with C&C servers.
   - Notably, UDP traffic spikes were seen in certain datasets (e.g., Dataset 10), which may indicate DDoS or spam activities, as UDP is often employed for high-volume, low-reliability attacks.

3. **Packet Size Distribution**:
   - Packet sizes varied across datasets, often clustered around smaller values typical of control messages.
   - Larger packet sizes observed in certain datasets (e.g., Dataset 6) might signify data exfiltration activities or payload transfers.
