import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from scipy import interp
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelBinarizer
from sklearn.model_selection import KFold
from sklearn.metrics import confusion_matrix
from mlxtend.plotting import plot_confusion_matrix
from sklearn.metrics import accuracy_score
from sklearn.metrics import roc_curve
from sklearn.metrics import auc
import pickle
from names import names

forest_saved_file = 'forestPredictor.sav'
feature_mask = 'featuresMask.csv'
roc_file = 'ROC_plot_RForest.png'
confusion_matrix_file = 'confusion_matrix_plot_RForest.png'

data_csv = pd.read_csv('dropped.csv', delimiter='|', names=names, header=0)

# print(train_data_csv.head(5))

forest = RandomForestClassifier()

# convert class to binary (0, 1) from benign, malicious
lb = LabelBinarizer()
data_csv['class'] = lb.fit_transform(data_csv['class'].values)
print(data_csv.groupby(['class']).size())

# drop the URL column
data_csv.drop(columns=['url'], axis=1, inplace=True)
array = data_csv.values

# load Y with the classes, making sure they are of int type
Y = array[:, -1]
Y = Y.astype(int)

# drop the Class column
data_csv.drop(columns=['class'], axis=1, inplace=True)
array = data_csv.values

# load X with the features
X = array[:, 0: -1]

# set up for 10 fold cross validation
splits = 10
kf = KFold(n_splits=splits)
kf.get_n_splits(X, Y)

summation = 0

# build empty 2x2 matrix
matrix_sum = [2, 2]

tprs = []
aucs = []
mean_fpr = np.linspace(0, 1, 100)
i = 0

for train_index, test_index in kf.split(X, Y):
    X_train, X_test = X[train_index], X[test_index]
    Y_train, Y_test = Y[train_index], Y[test_index]
    forest.fit(X_train, Y_train)
    prediction = forest.predict(X_test)
    # print(classification_report(Y_test, prediction))
    matrix = confusion_matrix(Y_test, prediction)
    matrix_sum = matrix_sum + matrix
    summation += accuracy_score(Y_test, prediction)

    # Compute ROC curve
    probas_ = forest.fit(X[train_index], Y[train_index]).predict_proba(X[test_index])
    fpr, tpr, thresholds = roc_curve(Y[test_index], probas_[:, 1])
    tprs.append(interp(mean_fpr, fpr, tpr))
    tprs[-1][0] = 0.0
    roc_auc = auc(fpr, tpr)
    aucs.append(roc_auc)
    plt.plot(fpr, tpr, lw=1, alpha=0.3,
             label='ROC fold %d (AUC = %0.2f)' % (i, roc_auc))

    i += 1

print("Confusion Matrix")
print(matrix_sum)

# break out the True Positive, False Positive, False Negative and True Negative from the matrix
TP = matrix_sum[0][0]
FP = matrix_sum[0][1]
FN = matrix_sum[1][0]
TN = matrix_sum[1][1]

print("True Positive --- " + str(TP))
print("False Positive ---" + str(FP))
print("True Negative --- " + str(TN))
print("False Negative ---" + str(FN))

overall_accuracy = format((TP + TN) / (TP + TN + FP + FN) * 100, '.2f')
true_positive_rate = format(TP / (TP + FN) * 100, '.2f')
true_negative_rate = format(TN / (TN + FP) * 100, '.2f')
false_positive_rate = format(FP / (TN + FP) * 100, '.2f')
false_negative_rate = format(FN / (FN + TP) * 100, '.2f')
precision = format(TP / (TP + FP) * 100, '.2f')


# average accuracy of the model
average = (summation / splits) * 100
average = format(average, '.2f')


print("Average Accuracy of model: " + average + '%')
print("Overall Accuracy: " + overall_accuracy + '%')
print("True Positive Rate: " + true_positive_rate + '%')
print("True Negative Rate: " + true_negative_rate + '%')
print("False Positive Rate: " + false_positive_rate + '%')
print("False Negative Rate: " + false_negative_rate + '%')
print("Precision of model: " + precision)


# Calculate and print ROC curve
mean_tpr = np.mean(tprs, axis=0)
mean_tpr[-1] = 1.0
mean_auc = auc(mean_fpr, mean_tpr)
std_auc = np.std(aucs)
plt.plot(mean_fpr, mean_tpr, color='b',
         label=r'Mean ROC (AUC = %0.2f $\pm$ %0.2f)' % (mean_auc, std_auc),
         lw=2, alpha=.8)

std_tpr = np.std(tprs, axis=0)
tprs_upper = np.minimum(mean_tpr + std_tpr, 1)
tprs_lower = np.maximum(mean_tpr - std_tpr, 0)
plt.fill_between(mean_fpr, tprs_lower, tprs_upper, color='grey', alpha=.2,
                 label=r'$\pm$ 1 std. dev.')

plt.xlim([-0.05, 1.05])
plt.ylim([-0.05, 1.05])
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
plt.title('Receiver Operating Curve Random Forest URL Prediction \n with accuracy of ' + average + ' percent')
plt.legend(loc="lower right")
plt.savefig(roc_file)

# Plot the Confusion Matrix
plt.title('Confusion Matrix Random Forest URL Prediction \n with accuracy of ' + average + ' percent')
fig, ax = plot_confusion_matrix(conf_mat=matrix_sum, figsize=(10, 5))
plt.savefig(confusion_matrix_file)


# dump the model for later use

pickle.dump(forest, open(forest_saved_file, 'wb'))

