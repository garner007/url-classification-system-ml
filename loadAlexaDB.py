import sqlite3
from sqlite3 import Error
import os
from os.path import join
import pandas as pd

db_name = 'alexa.db'
csv_file = 'top-1m.csv'
names = ['rank', 'domain']


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
        cursor = conn.cursor()
        cursor.execute(drop_table)
        # create projects table
        # create_table(conn, sql_create_alexa_table)
        # delete any rows in table, in case it already exists
        # cursor.execute(delete_table_rows)
    else:
        print("Error! cannot create the database connection.")

    df = pd.read_csv(csv_file, names=names, delimiter=',')
    df.to_sql('ALEXA_RANK', conn)


if __name__ == '__main__':
    main()

