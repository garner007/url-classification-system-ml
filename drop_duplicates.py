# This module will read in the cleaned data, and remove duplicate records from it.
# it is then written back out for further processing


import pandas as pd
from names import names

cleaned = 'cleaned_data.csv'
deduped = 'cleaned_deduped.csv'

cleaned_data = pd.read_csv('cleaned_data.csv', delimiter='|', header=0, names=names)

print('Number of original records on combined file: ' + str(cleaned_data.shape[0]))

duplicates_removed = cleaned_data.drop_duplicates()

print('Number of records after duplicated removed: ' + str(duplicates_removed.shape[0]))

duplicates_removed.to_csv(deduped, sep='|', index=None)


