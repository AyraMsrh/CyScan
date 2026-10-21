import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
import joblib

# Load data
data = pd.read_csv("ml_action_training_data.csv")

# Combine reason and confidence into text features
data["text"] = data["reason"] + " confidence:" + data["confidence"].astype(str)

# Vectorize text
vectorizer = TfidfVectorizer()
X = vectorizer.fit_transform(data["text"])
y = data["action"]

# Train model
model = LogisticRegression(max_iter=1000)
model.fit(X, y)

# Save model + vectorizer
joblib.dump(model, "ml_action_model.pkl")
joblib.dump(vectorizer, "ml_action_vectorizer.pkl")

print("✅ Model trained and saved successfully.")
