import pandas as pd
import numpy as np
import time
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_selection import SelectFromModel
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import SVC
from sklearn.metrics import classification_report, accuracy_score
from sklearn.linear_model import SGDClassifier  # Faster linear classifier
from sklearn.svm import LinearSVC 

# Load dataset
df = pd.read_csv('cleaned_PortScan.pcap_ISCX.csv')

# Drop columns with all missing values
df.dropna(axis=1, how='all', inplace=True)

# Fill missing values with 0
df.fillna(0, inplace=True)

# Drop unnamed index column if exists
df.drop(columns=[col for col in df.columns if 'Unnamed' in col], inplace=True)

# Separate features and target
X = df.drop('Label', axis=1)
y = df['Label']

# Clean data: Replace inf/-inf with NaN, then drop NaN rows
X.replace([np.inf, -np.inf], np.nan, inplace=True)
X.dropna(inplace=True)
y = y[X.index]  # Align target with cleaned X

# Feature selection using Logistic Regression
selector = SelectFromModel(estimator=LogisticRegression(max_iter=1000, solver='liblinear'))
selector.fit(X, y)
X_selected = selector.transform(X)

# Train/test split
X_train, X_test, y_train, y_test = train_test_split(X_selected, y, test_size=0.3, random_state=42)

# Models to train
models = {
    "Decision Tree": DecisionTreeClassifier(),
    "K-Nearest Neighbors": KNeighborsClassifier(),
    "SVM (Linear Kernel)": LinearSVC(max_iter=10000, random_state=42)
}

best_model = None
best_accuracy = 0

# Train and evaluate models
for name, model in models.items():
    start = time.time()
    model.fit(X_train, y_train)
    end = time.time()

    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)

    print(f"\n--- {name} ---")
    print(classification_report(y_test, y_pred, zero_division=0))
    print(f"[INFO] Accuracy: {accuracy:.4f} | Training time: {end - start:.2f} sec")

    if accuracy > best_accuracy:
        best_accuracy = accuracy
        best_model = model

# Save best model
joblib.dump(best_model, 'cic_model.pkl')
print(f"\n[✔] Best model ({best_model.__class__.__name__}) saved as cic_model.pkl")

#add 10 cross fold validation for SVM and k-NN