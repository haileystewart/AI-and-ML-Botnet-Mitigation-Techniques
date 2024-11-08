# Python script to train and evaluate machine learning models for detecting botnets (Naive Bayes, Decision Trees, etc.).
import os
import pandas as pd
import socket
import struct
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import roc_curve, auc

traffic_data = pd.read_csv("labeled_traffic_data.csv")
traffic_data = traffic_data.drop(columns="request_count")

'''
There are a couple of pre-processing things we must do before
we can work with the data properly. 
Some of the IPs in the dataset have \ at the end of them which must be removed.
Some of the entries are Null which must be resolved.
'''
def ip_to_int(ip):
    if type(ip) == str:
        ip = ip.strip().rstrip("\\")
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    return ip

traffic_data["ip.src"] = traffic_data["ip.src"].apply(ip_to_int)
traffic_data["ip.dst"] = traffic_data["ip.dst"].apply(ip_to_int)

fill_values = {
    "ip.dst": 0,  
    "frame.len": traffic_data["frame.len"].median(),  
    "frame.time_delta": traffic_data["frame.len"].median()
}
traffic_data.fillna(value=fill_values, inplace=True)

# Assuming 'label' is the column for malicious/benign labels
X = traffic_data.drop(columns="label")
y = traffic_data["label"]

# Split the data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=27)

# Initialize and train the Random Forest & Naive Bayes models
rf_model = RandomForestClassifier(n_estimators=100, random_state=27)
rf_model.fit(X_train, y_train)
nb_model = GaussianNB()
nb_model.fit(X_train, y_train)

# Make predictions on the test set
y_pred_rf = rf_model.predict(X_test)
y_pred_nb = nb_model.predict(X_test)

def get_analyitics(model, confirmed, predictions):
    metrics = {
        "Model": model,
        "Accuracy": accuracy_score(confirmed, predictions),
        "Precision": precision_score(confirmed, predictions, pos_label="malicious"),
        "Recall": recall_score(confirmed, predictions, pos_label="malicious"),
        "F1 Score": f1_score(confirmed, predictions, pos_label="malicious")
    }
    conf = confusion_matrix(confirmed, predictions)
    return metrics, conf

metrics_rf, conf_rf = get_analyitics("Random Forest", y_test, y_pred_rf)
metrics_nb, conf_nb = get_analyitics("Naive Bayes", y_test, y_pred_nb)

def display_analytics(model, metrics, conf):
    print("Accuracy for %s: %f" % (model, metrics["Accuracy"]))
    print("Precision for %s: %f" % (model, metrics["Precision"]))
    print("Recall for %s: %f" % (model, metrics["Recall"]))
    print("F1 Score for %s: %f" % (model, metrics["F1 Score"]))

    # Plot confusion matrix for Random Forest
    plt.figure(figsize=(12, 5))
    sns.heatmap(conf, annot=True, fmt="d", cmap="Blues", cbar=False)
    plt.title("Confusion Matrix - %s" % model)
    plt.xlabel("Predicted Label")
    plt.ylabel("True Label")
    plt.tight_layout()
    plt.show()

display_analytics("RF", metrics_rf, conf_rf)
display_analytics("NB", metrics_nb, conf_nb)

def visualize_metrics():
    # Get probability scores for positive class (1) from each model
    y_prob_rf = rf_model.predict_proba(X_test)[:, 1]
    y_prob_nb = nb_model.predict_proba(X_test)[:, 1]

    # Compute ROC curve and AUC for each model
    fpr_rf, tpr_rf, _ = roc_curve(y_test, y_prob_rf, pos_label="malicious")
    roc_auc_rf = auc(fpr_rf, tpr_rf)

    fpr_nb, tpr_nb, _ = roc_curve(y_test, y_prob_nb, pos_label="malicious")
    roc_auc_nb = auc(fpr_nb, tpr_nb)

    # Plot ROC curves
    plt.figure(figsize=(10, 6))
    plt.plot(fpr_rf, tpr_rf, color="blue", lw=2, label=f"Random Forest (AUC = {roc_auc_rf:.2f})")
    plt.plot(fpr_nb, tpr_nb, color="green", lw=2, label=f"Naive Bayes (AUC = {roc_auc_nb:.2f})")
    plt.plot([0, 1], [0, 1], color="grey", linestyle="--")  # Diagonal line for reference
    plt.title("ROC Curve for Random Forest and Naive Bayes")
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.legend(loc="lower right")
    plt.show()

results_dir = os.path.join(os.path.dirname(__file__), "results")
os.makedirs(results_dir, exist_ok=True)

metrics_df = pd.DataFrame([metrics_rf, metrics_nb])
metrics_df.to_csv(os.path.join(results_dir, "metrics.csv"), index=False)
visualize_metrics()