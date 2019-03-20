from sklearn.naive_bayes import GaussianNB
from sklearn.feature_selection import SelectKBest
from sklearn.feature_selection import chi2
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import KFold
from sklearn.metrics import accuracy_score
import pandas as pd
from names import names

selected_features = 'bestFeatures.csv'
feature_mask = 'featuresMask.csv'

data_csv = pd.read_csv('cleaned_data.csv', delimiter='|', names=names, header=0)

# drop the url column , as it's not helpful for modeling
data_csv.drop(columns=['url'], axis=1, inplace=True)


# convert class to binary (0, 1) from benign, malicious
le = LabelEncoder()
data_csv['class'] = le.fit_transform(data_csv['class'].values)

# load the columns into an array
array = data_csv.values

# load Y with the classes, making sure they are of int type
Y = array[:, -1]
Y = Y.astype(int)

# drop the class so we can use the data frame for the SelectKBest
data_csv.drop(columns=['class'], axis=1, inplace=True)

# count the number of features, to determine how many times to run kbest; subtract 2 for the url and class column
countK = (len([i.split('\t')[0] for i in names]) - 2)

naive = GaussianNB()

# lets process through all the possible available values of Kbest for the features, and see what number of them
# provides the best return

kin = 1
# empty dictionary of kbest runs
dict_of_kbest = {}
selected_columns = ['index', 'selected_columns']
mask_columns = ['index', 'mask']

selected_dict = {}
columns_dict = {}

mask_lit = []
while kin <= countK:
    selector = SelectKBest(chi2, k=kin)
    X = selector.fit_transform(data_csv, Y)

    # pull out the selected column names; put into a dict layout ; store the dict to pull from later
    col_names = data_csv.columns.values[selector.get_support()]
    col_d = {kin: col_names}
    columns_dict.update(col_d)

    # make a dictionary of the feature mask (true, false); put to a dict to pull from later
    mask_dict = {kin: selector.get_support()}
    selected_dict.update(mask_dict)

    # set up for 10 fold cross validation
    splits = 10
    kf = KFold(n_splits=splits)
    kf.get_n_splits(X, Y)

    summation = 0

    for train_index, test_index in kf.split(X, Y):
        X_train, X_test = X[train_index], X[test_index]
        Y_train, Y_test = Y[train_index], Y[test_index]
        naive.fit(X_train, Y_train)
        prediction = naive.predict(X_test)
        summation += accuracy_score(Y_test, prediction)

    average = (summation / splits) * 100
    dict_of_kbest[kin] = average
    kin += 1

# which value has the highest prediction value?
selected_key = max(dict_of_kbest, key=lambda key: dict_of_kbest[key])
print('best value for Kbest is : ', selected_key)

# pull the selected features and mask that are used out of the dictionary
mask = list(selected_dict.get(selected_key))
features = list(columns_dict.get(selected_key))

# write them out to files for use later
with open(selected_features, 'w') as features_file, open(feature_mask, 'w') as maskFile:
    features_file.write(','.join(map(str, features)))
    maskFile.write(','.join(map(str, mask)))




