"""
This module runs some statistics on the dataset to show some descriptive information about it.

"""

import pandas as pd
from names import names
from sklearn.preprocessing import LabelEncoder

benign_describe = 'benign_describe.csv'
malicious_describe = 'malicious_describe.csv'


# Combined list of benign / malicious URLS after encoding an cleaning
deduped_url = 'cleaned_deduped.csv'
cleaned_url = 'cleaned_data.csv'

deduped_csv = pd.read_csv(deduped_url, delimiter='|', names=names, header=0)
cleaned_csv = pd.read_csv(cleaned_url, delimiter='|', names=names, header=0)

# drop the url column, no use for analysis here
deduped_csv.drop(columns=['url'], axis=1, inplace=True)
cleaned_csv.drop(columns=['url'], axis=1, inplace=True)

# print the shape of the dataset

benign = deduped_csv[deduped_csv['class'] == 'benign']
malicious = deduped_csv[deduped_csv['class'] == 'malicious']

# put the statistical info for the deduped benign and malicious data to files
benign.describe().to_csv(benign_describe)
malicious.describe().to_csv(malicious_describe)


print("Distribution of data")
print('Number of records on original dataset: ' + str(cleaned_csv.shape[0]))
print(cleaned_csv.groupby(['class']).size())

print('Number of records on deduped dataset: ' + str(deduped_csv.shape[0]))
print(deduped_csv.groupby(['class']).size())

