import Vector_creator as Vc
import random
import csv
import sqlite3
from sqlite3 import Error
import os
from os.path import join


# File from which Malicious URLs are Read
malicious = 'merged_malware.csv'
benign = 'benign.csv'
combined = 'combined_url.csv'
db_name = 'alexa.db'

file_header = 'url| length_of_url| number_of_dots| suspicious_words| number_of_hyphens_in_domain| ' \
              'length_of_directory| number_subdirectories_in_url| length_of_domain| words_in_domain| path_tokens| ' \
              'url_contains_ip| has_alexa_rank| use_https| country_code| age | words|  entropy| special_chars |' \
              'length_of_largest_domain_token| average_length_of_domain_tokens|length_of_largest_path_token| ' \
              'average_length_of_path_tokens| suspicious_tld_name| file_name_present| len_of_filename| ' \
              'num_dot_in_filename| num_delims_in_filename| args_present| length_of_arguments| ' \
              'number_of_argument_variables| length_of_largest_variable| maximum_number_of_delims in arguments| class'

with open(malicious) as malicious, open(benign) as benign, open(combined, 'w') as combined:
    mal_reader = csv.reader(malicious)
    ben_reader = csv.reader(benign)
    mal_count = 0
    ben_count = 0

    # appending all read URLs in a single Python list
    data = []

    for row_ben in ben_reader:
        ben_count += 1
        url = row_ben[0]
        label = 'benign'
        data.append(url + '|' + label)

    for row_mal in mal_reader:
        mal_count += 1
        url = row_mal[0]
        label = 'malicious'
        data.append(url + '|' + label)

    combined.write(file_header + '\n')

    total_records = (len(data))
    temp = []
    count = 0

    random.shuffle(data)

    cwd = os.getcwd()
    db_location = join(cwd, db_name)
    try:
        conn = sqlite3.connect(db_location)
    except Error as e:
        print(e)
        print("Error connecting to database")

    for line in data:
        record = line.split("|")
        url = record[0]
        label = record[1]
        vec = Vc.Construct_Vector(url, conn)
        output = url + '|' + '|'.join(str(e) for e in vec) + '|' + label
        combined.write(output + "\n")
        count += 1

print('Total Items writen are : %d' % count)
