"""
This module reads in the output from the vectorizor; does any clean-up on the data that is needed, and then drops
duplicate records, using Pandas.


"""

from countries import countries
import pandas as pd
from names import names
combined = 'combined_url.csv'
cleaned_data = 'cleaned_data.csv'
deduped = 'cleaned_deduped.csv'
dropped_data = 'invalid.csv'

bm = ('benign', 'malicious')
read_count = 0
write_count = 0
with open(combined, 'r') as combined, open(cleaned_data, 'w') as cleaned, open(dropped_data, 'w') as dropped:

    file_in = combined.readlines()

    for line in file_in:
        read_count += 1
        # some of the fields have a ' in them, so need to get rid of them
        file_out = line.replace("'", '')
        file_out_split = file_out.split("|")

        # writing file header back out
        if file_out_split[0] == 'url':
            cleaned.write(file_out)
            dropped.write(file_out)
            write_count += 1
        # all of the remainder of the records
        # all records should have benign or malicious as the class
        elif any(c in file_out_split[-1] for c in bm):
            # change country code to a integer
            country_code = file_out_split[13]
            country_code = country_code.replace("_", " ")
            try:
                # see if we can find a ranking for the country
                ranking = countries[country_code]
                file_out_split[13] = ranking
            except KeyError:
                # non-standard country name found, so set it to 0
                # and print it out for review and addition if needed
                if country_code != 'not found':
                    print(country_code)
                file_out_split[13] = 0

            output = '|'.join(str(e) for e in file_out_split)
            cleaned.write(output)
            write_count += 1
        else:
            # during the extract process, some records on the Benign / Malicious file had | as delimiters,
            # causing issue with the split; we will just get rid of those now
            # and write to file for possible analysis
            dropped.write(line)

Number_records_dropped = read_count - write_count
print(Number_records_dropped, " records dropped due to bad fields")

# now that we have cleaned the data, lets get rid of any duplicates
cleaned_data = pd.read_csv('cleaned_data.csv', delimiter='|', header=0, names=names)

original_records = cleaned_data.shape[0]
print('Number of original records remaining: ' + str(original_records))

duplicates_removed = cleaned_data.drop_duplicates()

after_dupes_removed = duplicates_removed.shape[0]

print('Number of records after duplicated removed: ' + str(after_dupes_removed))
duplicates_removed.to_csv(deduped, sep='|', index=None)

number_removed = original_records - after_dupes_removed

print('Number of duplicate records removed: ' + str(number_removed))

print("Distribution of data")
print('Original Cleaned data')
print(cleaned_data.groupby(['class']).size())
print('Deduped Cleaned data')
print(duplicates_removed.groupby(['class']).size())
