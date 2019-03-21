#  This module will download a fresh copy of the alexa top 1-1m CSV file , unzip it and load it to a db for use later

import sqlite3
from sqlite3 import Error
import os
from os.path import join
import pandas as pd
import requests
import zipfile
import io

db_name = 'alexa.db'

ALEXA_URL = 'http://s3.amazonaws.com/alexa-static/top-1m.csv.zip'
csv_file = 'top-1m.csv'
names = ['rank', 'domain']


def get_alexa():

    r = requests.get(ALEXA_URL)
    zipped_alexa = zipfile.ZipFile(io.BytesIO(r.content))
    zipped_alexa.extractall()


def create_connection(db_file):
    """ create a database connection to a SQLite database """
    try:
        conn = sqlite3.connect(db_file)
        return conn
    except Error as e:
        print(e)
#    finally:
#        conn.close()


def create_table(conn, create_table_sql):

    try:
        c = conn.cursor()
        c.execute(create_table_sql)
    except Error as e:
        print(e)


def main():

    get_alexa()

    cwd = os.getcwd()
    db_location = join(cwd, db_name)

    sql_create_alexa_table = """ CREATE TABLE IF NOT EXISTS ALEXA_RANK (
                                        id integer PRIMARY KEY,
                                        rank integer NOT NULL,
                                        domain text
                                    ); """
    drop_table = "DROP TABLE if exists ALEXA_RANK"
    # create a database connection
    conn = create_connection(db_location)
    if conn is not None:
        # we have a connection, so create cursor
        cursor = conn.cursor()
        # if the table is already there, drop it then we will recreate and load it.
        cursor.execute(drop_table)
    else:
        print("Error! cannot create the database connection.")
    # read in the Alexa top 1 Million websites file
    df = pd.read_csv(csv_file, names=names, delimiter=',')
    # let pandas create the table and load it
    df.to_sql('ALEXA_RANK', conn)


if __name__ == '__main__':
    main()

