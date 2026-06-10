# About: Train multiple classifiers on labelled HTTP log data and save models.
# Usage: python train.py -l DATA/labeled_data/dataset.csv

import argparse
import pickle

import numpy as np
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from matplotlib import pyplot
from sklearn import tree, neighbors
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPClassifier
from yellowbrick.classifier import ClassificationReport


TRAINING_ALGORITHMS = [
    'ExtraTreeClassifier',
    'DecisionTreeClassifier',
    'RandomForestClassifier',
    'KNeighborsClassifier',
    'MLPClassifier',
]

CLASS_NAMES = ['normal', 'sql injection', 'XSS', 'directory traversal']


def get_args() -> dict:
    parser = argparse.ArgumentParser()
    parser.add_argument('-l', '--csv_file', help='Labeled CSV file', required=True)
    return vars(parser.parse_args())


def build_classifier(algorithm: str):
    """Return an unfitted classifier instance for the given algorithm name."""
    match algorithm:
        case 'ExtraTreeClassifier':
            return tree.ExtraTreeClassifier()
        case 'DecisionTreeClassifier':
            return tree.DecisionTreeClassifier()
        case 'RandomForestClassifier':
            return RandomForestClassifier(n_jobs=1)
        case 'KNeighborsClassifier':
            return neighbors.KNeighborsClassifier(n_neighbors=7)
        case 'MLPClassifier':
            return MLPClassifier(max_iter=300)
        case _:
            raise ValueError(f'Unknown algorithm: {algorithm}')


def main() -> None:
    args = get_args()
    df = pd.read_csv(args['csv_file'], encoding='latin-1')
    X = df.iloc[:, :-2]
    y = df.iloc[:, -2]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=0
    )

    best_accuracy = 0.0
    best_model_path = ''
    best_algorithm = ''
    last_classifier = None

    for algorithm in TRAINING_ALGORITHMS:
        print(f'\n--- {algorithm} ---')
        np.random.seed(1234)

        classifier = build_classifier(algorithm)
        classifier.fit(X_train.values, y_train.values)
        predictions = classifier.predict(X_test.values)

        model_path = f'MODELS/model_{algorithm}.pkl'
        with open(model_path, 'wb') as fh:
            pickle.dump(classifier, fh)

        acc = accuracy_score(y_test, predictions)
        print(f'Accuracy: {acc:.4f}  →  saved to {model_path}')

        if acc > best_accuracy:
            best_accuracy = acc
            best_model_path = model_path
            best_algorithm = algorithm

        # Confusion matrix
        cm = confusion_matrix(y_test, predictions, labels=classifier.classes_)
        ax = plt.subplot()
        sns.heatmap(cm, annot=True, fmt='g', ax=ax, cmap='Greens')
        ax.set_xlabel('Predicted labels')
        ax.set_ylabel('True labels')
        ax.set_title(algorithm)
        ax.xaxis.set_ticklabels(CLASS_NAMES)
        ax.yaxis.set_ticklabels(CLASS_NAMES)
        plt.savefig('confusion_matrix.png')
        plt.show()

        # Classification report
        visualizer = ClassificationReport(
            classifier, cmap='Greens', colorbar=True,
            classes=CLASS_NAMES, support=True,
        )
        visualizer.fit(X_train.values, y_train.values)
        visualizer.score(X_test.values, y_test.values)
        visualizer.show()

        last_classifier = classifier

    print('\n========== BEST RESULTS ==========')
    print(f'Accuracy  : {best_accuracy:.4f}')
    print(f'Model     : {best_model_path}')
    print(f'Algorithm : {best_algorithm}')

    # Feature importances for the last tree-based model
    if last_classifier is not None and hasattr(last_classifier, 'feature_importances_'):
        importance = last_classifier.feature_importances_
        for i, v in enumerate(importance):
            print(f'Feature {i}: {v:.5f}')
        pyplot.bar(range(len(importance)), importance)
        pyplot.show()


if __name__ == '__main__':
    main()
