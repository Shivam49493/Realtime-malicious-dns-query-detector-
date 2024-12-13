# Realtime-malicious-dns-query-detector-
This script implements a system for detecting potentially malicious DNS queries using a combination of machine learning and threat intelligence.
Threat Intelligence Integration:

The fetch_malicious_domains() function fetches a list of known malicious domains from OpenPhish, a threat intelligence feed.
This data is used to cross-check user-entered domains, adding a layer of intelligence to the detection process.
Dataset Loading and Preprocessing:

The load_dataset() function reads a dataset (dnsquery.csv) containing DNS-related features and labels (e.g., whether a query is benign or malicious).
Features like query length, Shannon entropy of the query, and query count (qdcount) are extracted for training a machine learning model.
Feature Extraction:

The extract_features() function calculates properties of a DNS query, such as its length, the number of subdomains, and its Shannon entropy (a measure of randomness).
These features are used as input for the machine learning model.
Entropy Calculation:

Shannon entropy is calculated using the calculate_entropy() function, which assesses the randomness in the query string. High entropy may indicate obfuscation or tunneling attempts.
Machine Learning Model:

A RandomForestClassifier is trained using features extracted from the dataset to classify queries as benign or malicious.
The trained model predicts user-input domain queries and checks for suspicious patterns.
Interactive Domain Classification:

The script accepts user input for domains and predicts their classification based on the trained model.
It also checks the domain against the OpenPhish threat feed.
Logging:

Logs are generated to track execution details using Python's logging module.
