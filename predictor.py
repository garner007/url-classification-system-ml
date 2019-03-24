"""
Load in pickle file of trained Naive Bayes model.
Asks for url; creates vector from URL and makes the prediction.

"""


import pickle
import vector_creator as Vc
from countries import countries
import numpy as np
import sqlite3
from sqlite3 import Error
import os
from os.path import join


saved_naive = 'naivePredictor.sav'
feature_mask = 'featuresMask.csv'
db_name = 'alexa.db'

model = pickle.load(open(saved_naive, 'rb'))

# get a connection to the database
cwd = os.getcwd()
db_location = join(cwd, db_name)
try:
    conn = sqlite3.connect(db_location)
except Error as e:
    print(e)
    print("Error connecting to database")

while True:
    url = input('\nEnter URL:\n')
    if url == '':
        break

    vec = Vc.Construct_Vector(url, conn)

    country = vec[12]
    country = country.replace("_", " ")
    try:
        ranking = countries[country]
        vec[12] = ranking
    except KeyError:
        vec[12] = 0

    # put the vector into a numpy array
    array = np.asarray(vec)

    # create a mask from the feature_mask file
    Mask = np.genfromtxt(feature_mask, delimiter=',', dtype=None)

    # load X with the appropriate features
    X = array[Mask]

    X = X.reshape(1, -1)

    prediction = model.predict(X)

    if prediction[0] == 1:
        url_prediction = 'Malicious'
    else:
        url_prediction = "BENIGN"

    print('This URL is predicted to be ' + url_prediction)
    # probability of being malicious
    prediction_prob = model.predict_proba(X)
    np.set_printoptions(precision=6)
    mal_prob = prediction_prob[0][1]
    mal_prob = mal_prob * 100
    mal_prob = (format(mal_prob, '.3f'))
    print('Probability of URL being malicious is ' + mal_prob + '%')
