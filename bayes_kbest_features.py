import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from scipy import interp
from sklearn.preprocessing import LabelBinarizer
from sklearn.naive_bayes import GaussianNB
from sklearn.model_selection import KFold
from sklearn.metrics import confusion_matrix
from sklearn.metrics import accuracy_score
from sklearn.metrics import roc_curve
from sklearn.metrics import auc
from sklearn.feature_selection import SelectKBest
from sklearn.feature_selection import chi2


import pickle

naive_saved_file = 'naivePredictor.sav'
selected_features = 'bestFeatures.csv'
feature_mask = 'featuresMask.csv'

names = ['url', 'length_of_url', 'number_of_dots', 'suspicious_words', 'number_of_hyphens_in_domain',
         'length_of_directory', 'number_subdirectories_in_url', 'length_of_domain', 'words_in_domain', 'path_tokens',
         'url_contains_ip', 'has_alexa_rank', 'use_https', 'country_code', 'age', 'words',  'entropy', 'special_chars',
         'length_of_largest_domain_token', 'average_length_of_domain_tokens','length_of_largest_path_token',
         'average_length_of_path_tokens', 'suspicious_tld_name', 'file_name_present', 'len_of_filename',
         'num_dot_in_filename', 'num_delims_in_filename', 'args_present', 'length_of_arguments',
         'number_of_argument_variables', 'length_of_largest_variable', 'maximum_number_of_delims_in_arguments', 'class']

data_csv = pd.read_csv('cleaned_data.csv', delimiter='|', names=names, header=0)

# print(train_data_csv.head(5))

naive = GaussianNB()

print(data_csv.shape)

print(data_csv.describe())


# convert class to binary (0, 1) from benign, malicious
lb = LabelBinarizer()
data_csv['class'] = lb.fit_transform(data_csv['class'].values)
print(data_csv.groupby(['class']).size())

data_csv.drop(columns=['url'], axis=1, inplace=True)
print(data_csv.shape)


array = data_csv.values

# load Y with the classes, making sure they are of int type
Y = array[:, -1]
Y = Y.astype(int)

# drop the class so we can use the data frame for the SelectKBest
data_csv.drop(columns=['class'], axis=1, inplace=True)

# evaluate for the best features to use
selector = SelectKBest(chi2, k=13)
X_new = selector.fit_transform(data_csv, Y)

# pull out the selected column names
col_names = data_csv.columns.values[selector.get_support()]

with open(selected_features, 'w') as features_file, open(feature_mask, 'w') as maskFile:
    col_names.tofile(selected_features, sep=',')
    selector.get_support().tofile(feature_mask, sep=',')


# pull out the score for each column
scores = selector.scores_[selector.get_support()]
# merge the lists
names_scores = list(zip(col_names, scores))

# put the list of col_names , scores into a data frame
ns_df = pd.DataFrame(data=names_scores, columns=['Feat_names', 'Scores'])

# sort the data frame
ns_df_sorted = ns_df.sort_values(['Scores', 'Feat_names'], ascending=[False, True])
print(ns_df_sorted)

# put the reformatted data frame into X
array = data_csv.values
# X = array[:, 0:]
X = X_new

# set up for 10 fold cross validation
splits = 2
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
    naive.fit(X_train, Y_train)
    prediction = naive.predict(X_test)
    # print(classification_report(Y_test, prediction))
    matrix = confusion_matrix(Y_test, prediction)
    matrix_sum = matrix_sum + matrix
    summation += accuracy_score(Y_test, prediction)

    # Compute ROC curve
    probas_ = naive.fit(X[train_index], Y[train_index]).predict_proba(X[test_index])
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
print("False Negative ---" + str(FN))
print("True Negative --- " + str(TN))

# average accuracy of the model
average = (summation / splits) * 100
print(format(average, '.2f'))

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
plt.title('Receiver operating Curve GaussianBayes URL Prediction')
plt.legend(loc="lower right")
plt.show()


# train a model on the full data
naive.fit(X, Y)

# dump the model for later use
pickle.dump(naive, open(naive_saved_file, 'wb'))


