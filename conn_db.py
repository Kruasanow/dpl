import os
import psycopg2 as ps

def get_db_connection():
    conn = ps.connect(host='localhost',
                      database='flask_db',
                      user=os.environ['DB_USERNAME'],
                      password=os.environ['DB_PASSWORD']
                    )
    return conn