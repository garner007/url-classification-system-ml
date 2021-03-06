"""
This module creates the vectorized file of features from the inputs of the benign and malicious websites.


"""

import vector_creator as vc
import random
import csv
import sqlite3
from sqlite3 import Error
import os
from os.path import join
from fileHeader import file_header


# File from which Malicious URLs are Read
malicious = 'merged_malware.csv'
benign = 'benign.csv'
combined = 'combined_url.csv'
db_name = 'alexa.db'


with open(malicious) as malicious, open(benign) as benign, open(combined, 'w') as combined:
    mal_reader = csv.reader(malicious)
    ben_reader = csv.reader(benign)
    mal_count = 0
    ben_count = 0

    # appending all read URLs in a single Python list
    data = []

    # read in the benign URLs
    for row_ben in ben_reader:
        ben_count += 1
        url = row_ben[0]
        label = 'benign'
        data.append(url + '|' + label)

    # read in the malicious URLs
    for row_mal in mal_reader:
        mal_count += 1
        url = row_mal[0]
        label = 'malicious'
        data.append(url + '|' + label)

    combined.write(file_header + '\n')

    total_records = (len(data))
    temp = []
    count = 0

    # randomly shuffle the data between the benign and malicious URLs
    random.shuffle(data)

    # connect to the Alexa top 1m database
    cwd = os.getcwd()
    db_location = join(cwd, db_name)
    try:
        conn = sqlite3.connect(db_location)
    except Error as e:
        print(e)
        print("Error connecting to database")

    # process the data to create the vectors.
    for line in data:
        record = line.split("|")
        url = record[0]
        label = record[1]
        vec = vc.Construct_Vector(url, conn)
        output = url + '|' + '|'.join(str(e) for e in vec) + '|' + label
        combined.write(output + "\n")
        count += 1

print('Total Items writen are : %d' % count)
