from sklearn import neighbors
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from utilities import *
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.metrics import confusion_matrix
from yellowbrick.classifier import ClassificationReport
from matplotlib import pyplot
import numpy as np
import random


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-l', '--csv_file', help = 'labeled csv file', required = True)
    return vars(parser.parse_args())

args = get_args()

csv_file = args['csv_file']
# training_algorithms = ['ExtraTreeClassifier','DecisionTreeClassifier','RandomForestClassifier','KNeighborsClassifier']
training_algorithms = ['RandomForestClassifier']
max_accuracy=0
max_model=''
max_algorithm=''

df = pd.read_csv(csv_file, encoding='latin-1')
df.to_numpy()
X = df.iloc[:, :-2]
y = df.iloc[:, -2]
df.to_numpy()

training_features,testing_features, traning_labels,  testing_labels = train_test_split(X, y, test_size=0.2, random_state=0)

for training_algorithm in training_algorithms:
    print(" --- "+training_algorithm+" --- ")
    if training_algorithm == 'ExtraTreeClassifier':
        attack_classifier = tree.ExtraTreeClassifier()

    elif training_algorithm == 'DecisionTreeClassifier':
        attack_classifier = tree.DecisionTreeClassifier()

    elif training_algorithm == 'KNeighborsClassifier':
        attack_classifier = neighbors.KNeighborsClassifier(n_neighbors = 7)

    elif training_algorithm == 'MLPClassifier':
        attack_classifier = MLPClassifier(max_iter=300)

    elif training_algorithm == 'RandomForestClassifier':
        attack_classifier = RandomForestClassifier(n_jobs=1) # n_jobs=1 means use single thread
    else:
        print('{} is not recognized as a training algorithm')
    
    np.random.seed(1234) # set same seed for reproducibility

    if attack_classifier != None:
        attack_classifier.fit(training_features.values, traning_labels.values)
        predictions = attack_classifier.predict(testing_features.values)
        model_file_name = 'MODELS/model_{}.pkl'.format(training_algorithm)
        pickle.dump(attack_classifier, open(model_file_name, 'wb'))

        accuracy_scoree=accuracy_score(testing_labels, predictions)
        print('accuracy score = ' + str(accuracy_scoree))
        print(model_file_name)

        if max_accuracy < accuracy_scoree:
            max_accuracy=accuracy_scoree
            max_model=model_file_name
            max_algorithm=training_algorithm
    # plot confusion matrix and classification report

    cm= confusion_matrix(testing_labels, predictions,labels=attack_classifier.classes_)
    ax = plt.subplot()
    sns.heatmap(cm, annot=True, fmt='g', ax=ax,cmap='Greens' )
    ax.set_xlabel('Predicted labels')
    ax.set_ylabel('True labels')
    ax.set_title(training_algorithm)
    ax.xaxis.set_ticklabels(['normal', 'sql injection','XSS','directory traversal'])
    ax.yaxis.set_ticklabels(['normal', 'sql injection','XSS','directory traversal'])
    plt.savefig('confusion_matrix.png')
    plt.show()



    visualizer = ClassificationReport(attack_classifier,cmap="Greens",colorbar=True, classes=['normal', 'sql injection','XSS','directory traversal'],support=True)
    visualizer.fit(training_features.values, traning_labels.values)
    visualizer.score(testing_features.values, testing_labels.values)
    visualizer.show()


# print(classification_report(testing_labels, predictions,target_names=['normal', 'sql injection','XSS','directory traversal']))

print('---------------------------- BEST RESULTS ---------------------------')
print('Accuracy '+str(max_accuracy))
print('model with max accuracy : '+ max_model)
print('Algorithm : '+ max_algorithm)


# get importance
importance = attack_classifier.feature_importances_
# summarize feature importance
for i,v in enumerate(importance):
 print('Feature: %0d, Score: %.5f' % (i,v))
# plot feature importance
pyplot.bar([x for x in range(len(importance))], importance)
pyplot.show()
