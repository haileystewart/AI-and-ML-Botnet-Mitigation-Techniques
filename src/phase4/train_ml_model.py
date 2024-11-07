# Python script to train and evaluate machine learning models for detecting botnets (Naive Bayes, Decision Trees, etc.).
import pandas as pd
import socket
import struct
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

# Load your dataset
traffic_data = pd.read_csv("labeled_traffic_data.csv")
traffic_data = traffic_data.drop(columns="request_count")

# Convert IP address to integer
def ip_to_int(ip):
    if type(ip) == str:
        ip = ip.strip().rstrip("\\")
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    return ip

traffic_data['ip.src'] = traffic_data['ip.src'].apply(ip_to_int)
traffic_data['ip.dst'] = traffic_data['ip.dst'].apply(ip_to_int)

fill_values = {
    'ip.dst': 0,  # Replace NaN in 'column1' with 0
    'frame.len': traffic_data['frame.len'].median(),  # Replace NaN in 'column2' with the median
    'frame.time_delta': traffic_data['frame.len'].median()
}
traffic_data.fillna(value=fill_values, inplace=True)

# Assuming 'label' is the column for malicious/benign labels
X = traffic_data.drop(columns="label")
y = traffic_data['label']

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

def get_analyitics(confirmed, predictions):
# Evaluate the model
    accuracy = dict()
    precision = dict()
    recall = dict()
    f1 = dict()
    conf = dict()

    accuracy= accuracy_score(confirmed, predictions)
    precision = precision_score(confirmed, predictions, pos_label='malicious')
    recall = recall_score(confirmed, predictions, pos_label='malicious')
    f1 = f1_score(confirmed, predictions, pos_label='malicious')
    conf = confusion_matrix(confirmed, predictions)
    return accuracy, precision, recall, f1, conf

accuracy_rf, precision_rf, recall_rf, f1_rf, conf_rf = get_analyitics(y_test, y_pred_rf)
accuracy_nb, precision_nb, recall_nb, f1_nb, conf_nb = get_analyitics(y_test, y_pred_nb)

def display_analytics(model, accuracy, precision, recall, f1, conf):
    print("Accuracy for %s: %f" % (model, accuracy))
    print("Precision for %s: %f" % (model, precision))
    print("Recall for %s: %f" % (model, recall))
    print("F1 Score for %s: %f" % (model, f1))
    print("Confusion Matrix for %s: \n%s\n" % (model, conf))

display_analytics("RF", accuracy_rf, precision_rf, recall_rf, f1_rf, conf_rf)
display_analytics("NB", accuracy_nb, precision_nb, recall_nb, f1_nb, conf_nb)