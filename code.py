import pandas as pd
import requests
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import math
import logging
from scapy.all import sniff, DNS, DNSQR

# Logging setup
logging.basicConfig(filename="dns_detection_log.log", level=logging.INFO, format="%(asctime)s - %(message)s")

# Threat Intelligence Integration: Fetch malicious domains from OpenPhish
def fetch_malicious_domains():
    """Fetch known malicious domains from OpenPhish."""
    API_URL = "https://openphish.com/feed.txt"
    response = requests.get(API_URL)
    malicious_domains = response.text.splitlines()
    return malicious_domains

# Train machine learning model
def train_model(X_train, y_train):
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    return model

# Feature extraction from DNS query
def extract_features(query):
    """Extract relevant features from DNS query."""
    query_length = len(query)
    subdomains = query.split('.')
    subdomain_count = len(subdomains) - 1
    entropy = calculate_entropy(query)

    return {
        "query_length": query_length,
        "subdomain_count": subdomain_count,
        "entropy": entropy
    }

# Calculate Shannon entropy of a string
def calculate_entropy(data):
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0
    prob = [data.count(c) / len(data) for c in set(data)]
    return -sum(p * math.log2(p) for p in prob)

# Packet processing callback for Scapy
def process_packet(packet):
    """Process captured DNS packets."""
    if packet.haslayer(DNS) and packet[DNS].opcode == 0:  # Check if it's a standard query
        query = packet[DNSQR].qname.decode('utf-8').strip('.')
        print(f"Captured DNS query: {query}")

        # Extract features
        features = extract_features(query)
        query_features = [[features["query_length"], features["subdomain_count"], features["entropy"]]]

        # Prediction using the trained model
        prediction = model.predict(query_features)[0]

        if prediction == 1:  # Malicious/Tunneling detected
            print(f"The domain '{query}' is classified as Malicious.")
        else:
            print(f"The domain '{query}' is classified as Benign.")

        # Threat Intelligence Integration: Check against known malicious domains
        if query in malicious_domains:
            print(f"The domain '{query}' is known to be Malicious (from threat intelligence).")
        logging.info(f"Processed query '{query}' - Prediction: {'Malicious' if prediction == 1 else 'Benign'}")

# Main execution flow
def main():
    # Fetch threat intelligence data
    global malicious_domains
    malicious_domains = fetch_malicious_domains()

    # Load dataset and train machine learning model
    # Replace this dataset with a sample for model training (you can simulate)
    data = pd.read_csv("dnsquery.csv")  # Replace with your dataset for training
    X = data[["qd_qname_len", "qd_qname_shannon", "qdcount"]]
    y = data["label"]

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

    global model
    model = train_model(X_train, y_train)

    # Evaluate the model on test data
    y_pred = model.predict(X_test)
    print(classification_report(y_test, y_pred))

    # Start capturing DNS packets
    print("Starting live DNS packet capture...")
    sniff(filter="udp port 53", prn=process_packet, store=False)

# Run the script
if __name__ == "__main__":
    main()