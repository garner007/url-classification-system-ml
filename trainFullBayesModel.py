"""
Module loads in the CSV of cleaned data, and uses the mask of features from findBestK to train the NaiveBayes
Gaussian model.  This module also runs Cross-Validation on the model and data, to produce ROC curve
Confusion Matrix as well as the accuracy score.
"""

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from scipy import interp
from sklearn.preprocessing import LabelEncoder
from sklearn.naive_bayes import GaussianNB
from sklearn.model_selection import KFold
from sklearn.metrics import confusion_matrix
from mlxtend.plotting import plot_confusion_matrix
from sklearn.metrics import accuracy_score
from sklearn.metrics import roc_curve
from sklearn.metrics import auc
from names import names
import csv
import pickle

naive_saved_file = 'naivePredictor.sav'
feature_mask = 'featuresMask.csv'
selected_features = 'bestFeatures.csv'
classifierErrorsFP = 'classifierErrorsFP.csv'
classifierErrorsFN = 'classifierErrorsFN.csv'
roc_file = 'ROC_plot.png'
confusion_matrix_file = 'confusion_matrix_plot.png'

data_csv = pd.read_csv('dropped.csv', delimiter='|', names=names, header=0)

# test the classifier with the mislabeled data points removed
data_csv = pd.read_csv('dropped.csv', delimiter='|', names=names, header=0)

naive = GaussianNB()

# convert class to binary (0, 1) from benign, malicious
le = LabelEncoder()
data_csv['class'] = le.fit_transform(data_csv['class'].values)

# array containing all original values including the URL
# this will be used to pull the URL that corresponds to the selected features for errors
url_array = data_csv.values
U = url_array[:, 0:]

# drop the URL from the data frame, not needed for training / testing of model
data_csv.drop(columns=['url'], axis=1, inplace=True)


array = data_csv.values

# load Y with the classes, making sure they are of int type
Y = array[:, -1]
Y = Y.astype(int)

# drop the class so we can use the data frame for the SelectKBest
data_csv.drop(columns=['class'], axis=1, inplace=True)
array = data_csv.values

# create a mask from the feature_mask file
mask = np.genfromtxt(feature_mask, delimiter=',', dtype=None)

# load X with the appropriate features from the kbest mask
X = array[:, mask]

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

with open(classifierErrorsFP, 'w', ) as error_fileFP, open(classifierErrorsFN, 'w') as error_fileFN, \
            open(selected_features, 'r') as selected:
    reader = csv.reader(selected)
    for row in reader:
        error_fileFP.write('url' + '|' + '|'.join((map(str, row))) + '\n')
        error_fileFN.write('url' + '|' + '|'.join((map(str, row))) + '\n')
    for train_index, test_index in kf.split(X, Y):
        X_train, X_test = X[train_index], X[test_index]
        Y_train, Y_test, url_data = Y[train_index], Y[test_index], U[test_index]
        naive.fit(X_train, Y_train)
        prediction = naive.predict(X_test)
        matrix = confusion_matrix(Y_test, prediction)
        n = 0
        # write out the FP and FN errors
        while n < len(test_index):
            if Y_test[n] != prediction[n]:
                # find the index for the array to pull the url and the selected feature vectorized data
                uidx = test_index[n]
                if prediction[n] == 1:
                    # these are the FP - benign urls flagged as malicious
                    error_fileFP.write(str(U[uidx, 0]) + '|' + '|'.join(map(str, X[uidx])) + '\n')
                else:
                    # these are the FN - malicious urls flagged as benign
                    error_fileFN.write(str(U[uidx, 0]) + '|' + '|'.join(map(str, X[uidx])) + '\n')
            n += 1

        matrix_sum = matrix_sum + matrix
        summation += accuracy_score(Y_test, prediction)

        # Compute ROC curve
        probability = naive.fit(X[train_index], Y[train_index]).predict_log_proba(X[test_index])
        fpr, tpr, thresholds = roc_curve(Y[test_index], probability[:, 1])
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
plt.title('Receiver Operating Curve GaussianBayes URL Prediction \n with accuracy of ' + average + ' percent')
plt.legend(loc="lower right")
plt.savefig(roc_file)

# Plot the Confusion Matrix
plt.title('Confusion Matrix GaussianBayes URL Prediction \n with accuracy of ' + average + ' percent')
fig, ax = plot_confusion_matrix(conf_mat=matrix_sum, figsize=(10, 5))
plt.savefig(confusion_matrix_file)


# train a model on the full data
naive.fit(X, Y)

# dump the model for later use
pickle.dump(naive, open(naive_saved_file, 'wb'))



