import mysql.connector
from mysql.connector import Error

def get_db_connection():
    try:
        connection = mysql.connector.connect(
            host='127.0.0.1',
            database='backend',
            user='user',
            password='password'
        )
        return connection
    except Error as e:
        print(f"Error while connecting to MySQL: {e}")
        return None