from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split
import pandas as pd
import joblib

df = pd.read_csv("data/preprocessed_cic_ids.csv")

X = df.drop("label", axis=1)
y = df["label"]  # e.g., 1 = High Risk, 0 = Low Risk

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

model = DecisionTreeClassifier()
model.fit(X_train, y_train)

joblib.dump(model, "models/risk_model.pkl")
