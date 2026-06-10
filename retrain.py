"""Quick retrain of all classifiers using the current scikit-learn version.
Fixes the InconsistentVersionWarning from pre-existing .pkl files.
Usage: python retrain.py
"""
import pickle
import numpy as np
import pandas as pd
from sklearn import tree, neighbors
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPClassifier

CSV = "DATA/labeled_data/dataset-data-imblance.csv"

df = pd.read_csv(CSV, encoding='latin-1')
X = df.iloc[:, :-2].values
y = df.iloc[:, -2].values
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=0)

classifiers = {
    "ExtraTreeClassifier":    tree.ExtraTreeClassifier(),
    "DecisionTreeClassifier": tree.DecisionTreeClassifier(),
    "RandomForestClassifier": RandomForestClassifier(n_jobs=-1),
    "KNeighborsClassifier":   neighbors.KNeighborsClassifier(n_neighbors=7),
    "MLPClassifier":          MLPClassifier(max_iter=300),
}

best = (0.0, "")
for name, clf in classifiers.items():
    np.random.seed(1234)
    clf.fit(X_train, y_train)
    acc = accuracy_score(y_test, clf.predict(X_test))
    path = f"MODELS/model_{name}.pkl"
    with open(path, "wb") as f:
        pickle.dump(clf, f)
    print(f"  {name:30s}  acc={acc:.4f}  → {path}")
    if acc > best[0]:
        best = (acc, name)

print(f"\nBest: {best[1]} ({best[0]:.4f})")
