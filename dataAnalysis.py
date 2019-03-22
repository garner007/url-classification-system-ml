"""
This module runs some statistics on the cleaned dataset to show some descriptive information about it.

"""

import pandas as pd
from names import names
from sklearn.preprocessing import LabelEncoder

# Combined list of benign / malicious URLS after encoding an cleaning
cleaned_data = 'cleaned_data.csv'

data_csv = pd.read_csv(cleaned_data, delimiter='|', names=names, header=0)

# drop the url column, no use for analysis here
data_csv.drop(columns=['url'], axis=1, inplace=True)

# print the shape of the dataset

print("Shape of the dataset")
print(data_csv.shape)

# describe the data
print("Description of data in the dataset")
print(data_csv.describe())


le = LabelEncoder()
data_csv['class'] = le.fit_transform(data_csv['class'].values)
print("Distribution of pos / neg classes in the data set")
print(data_csv.groupby(['class']).size())





