import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib

# Load your CIC-IDS 2017 data
print("🚀 Training script started")

df = pd.read_csv("cleaned_PortScan.pcap_ISCX.csv")

# Map to 3 risk levels
def map_label_to_risk(label):
    if label == "BENIGN":
        return 0  # Low
    elif label in ["FTP-Patator", "SSH-Patator"]:
        return 1  # Medium
    else:
        return 2  # High

df["Risk"] = df["Label"].apply(map_label_to_risk)
features = [
    "Flow Duration", "Total Fwd Packets", "Fwd Packet Length Mean",
    "SYN Flag Count", "RST Flag Count", "Packet Length Mean"
]

X = df[features]
y = df["Risk"]

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

model = RandomForestClassifier()
model.fit(X_train, y_train)

joblib.dump(model, "risk_model.pkl")
print("✅ Training finished")
