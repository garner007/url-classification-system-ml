import pandas as pd
from names import names
from sklearn.preprocessing import LabelEncoder
import matplotlib.pyplot as plt


cleaned_data = 'cleaned_data.csv'

data_csv = pd.read_csv('cleaned_data.csv', delimiter='|', names=names, header=0)

# print the shape of the dataset
print(data_csv.shape)

# describe the data
print(data_csv.describe())

le = LabelEncoder()
data_csv['class'] = le.fit_transform(data_csv['class'].values)
print(data_csv.groupby(['class']).size())





