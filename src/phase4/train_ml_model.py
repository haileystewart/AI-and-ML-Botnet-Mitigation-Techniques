# Python script to train and evaluate machine learning models for detecting botnets (Naive Bayes, Decision Trees, etc.).

import os
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest

# Step 1: Load your dataset
processed_data_dir = os.path.join(os.path.dirname(__file__), 'processed_data')
dataframes = []
for dataset_id in range(1, 14):
    dataset_dir = os.path.join(processed_data_dir, str(dataset_id))
    if os.path.exists(dataset_dir):
        for filename in os.listdir(dataset_dir):
            if filename.endswith('.csv.gz'):
                file_path = os.path.join(dataset_dir, filename)
                try:
                    df = pd.read_csv(file_path, usecols=['frame.len'], compression='gzip')
                    dataframes.append(df)
                except pd.errors.ParserError as e:
                    print(f"Warning: Could not parse {file_path} due to {e}")

# Combine all datasets into one DataFrame
traffic_data = pd.concat(dataframes, ignore_index=True)

# Assuming 'label' is the column for malicious/benign labels
# And other columns are your features
X = traffic_data.copy()
y = traffic_data['label']

# Step 2: Split the data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Step 3: Initialize and train the Random Forest & Naive Bayes models
rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
rf_model.fit(X_train, y_train)
nb_model = GaussianNB()
nb_model.fit(X_train, y_train)

# Step 4: Make predictions on the test set
y_pred_rf = rf_model.predict(X_test)
y_pred_nb = nb_model.predict(X_test)

# Step 5: Evaluate the model
accuracy = dict()
precision = dict()
recall = dict()
f1 = dict()
conf = dict()

accuracy["RF"] = accuracy_score(y_test, y_pred_rf)
precision["RF"] = precision_score(y_test, y_pred_rf)
recall["RF"] = recall_score(y_test, y_pred_rf)
f1["RF"] = f1_score(y_test, y_pred_rf)
conf["RF"] = confusion_matrix(y_test, y_pred_rf)

accuracy["NB"] = accuracy_score(y_test, y_pred_nb)
precision["NB"] = precision_score(y_test, y_pred_nb)
recall["NB"] = recall_score(y_test, y_pred_nb)
f1["NB"] = f1_score(y_test, y_pred_nb)
conf["NB"] = confusion_matrix(y_test, y_pred_nb)

print("Accuracy:", accuracy)
print("Precision:", precision)
print("Recall:", recall)
print("F1 Score:", f1)
print("Confusion Matrix:\n", conf)

# Preprocess: Standardize the features for better clustering performance
scaler = StandardScaler()
X_scaled = scaler.fit_transform(traffic_data)

# Initialize and fit the DBSCAN model
dbscan_model = DBSCAN(eps=0.5, min_samples=5)
dbscan_labels = dbscan_model.fit_predict(X_scaled)

# Add the labels back to the dataset for analysis
traffic_data["Cluster"] = dbscan_labels

# Print a summary of clusters
print(traffic_data["Cluster"].value_counts())

# Initialize and fit the Isolation Forest model
iso_forest = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
outlier_labels = iso_forest.fit_predict(traffic_data)

# Add the labels back to the dataset for analysis
traffic_data["Forest"] = outlier_labels  # -1 indicates an anomaly, 1 indicates normal

# Print a summary of anomalies
print(traffic_data["Forest"].value_counts())