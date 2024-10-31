# Improving Botnet Detection and Mitigation Techniques Using Machine Learning

## Overview
This project aims to explore and enhance botnet detection techniques using both traditional rule-based methods and machine learning algorithms. By simulating botnet attacks and analyzing network traffic, we evaluate the effectiveness of existing detection systems and propose improvements using machine learning models like Naive Bayes and Decision Trees.

## Project Phases
1. **Botnet Architecture & Detection Methods**: Study traditional botnet detection methods.
2. **Network Traffic Analysis**: Simulate botnet attacks and analyze traffic patterns.
3. **Rule-Based Detection**: Experiment with detection rules to refine traditional methods.
4. **Machine Learning Models**: Train and evaluate machine learning models to detect botnet activity.

## Repo Structure
- **/docs**: Contains the project documentation, including the proposal, final paper, and notes.
- **/src**: All code related to the project, organized by phases.
- **/data**: Datasets and network traffic logs used in the experiments.
- **/results**: Performance metrics, graphs, and other results from the experiments.
- **/notebooks**: Jupyter notebooks for exploratory data analysis and testing models.
- **/utils**: Reusable scripts for data pre-processing, traffic analysis, and feature extraction.

## How to Run
1. Clone the repository:  
   `git clone https://github.com/your-username/botnet-detection-ml.git`
2. Install dependencies:  
   `pip install -r requirements.txt`
3. Run the traffic analysis code in Phase 1:  
   `python src/Phase1/traffic_analysis.py`
4. Train machine learning models in Phase 4:  
   `python src/Phase4/train_ml_model.py`
