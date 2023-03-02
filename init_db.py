import os
import psycopg2

conn = psycopg2.connect(
        host="localhost",
        database="flask_db",
        user=os.environ['DB_USERNAME'],
        password=os.environ['DB_PASSWORD']
        )

# Open a cursor to perform database operations
cur = conn.cursor()

# Execute a command: this creates a new table
cur.execute('DROP TABLE IF EXISTS dns_flags;')
cur.execute('CREATE TABLE dns_flags (id serial PRIMARY KEY,' ### ОТРЕДАЧИТЬ ТИПЫ ДАННЫХ 
                                 'id_pac varchar (200),' #
                                 'a_return_rec varchar (200),' #
                                 'flags_authenticated varchar (200),'  #
                                 'flags_authoritative varchar (200),'  #
                                 'flags_opcode varchar (200),'  #
                                 'flags_rcode varchar (200),' #
                                 'flags_recavail varchar (200),' #
                                 'flags_recdesired varchar (200),' #
                                 'flags_response varchar (200),'  #
                                 'flags_truncated varchar (200),'  #
                                 'flags_z varchar (200),' #
                                 'qry_class varchar (200),'  #
                                 'qry_name varchar (200),'  #
                                 'qry_type varchar (200),' #
                                 'resp_class varchar (200),' #
                                 'resp_ttl varchar (200),'  #
                                 'resp_type varchar (200),' #
                                 'response_to varchar (200),' #
                                 'time varchar (200),' #
                                 'count_add_rr varchar (200),' #
                                 'count_answers varchar (200),' #
                                 'count_auth_rr varchar (200),' #
                                 'count_labels varchar (200),' # 
                                 'count_queries varchar (200),' #
                                 'date_added date DEFAULT CURRENT_TIMESTAMP);'
                                 )

# Insert data into the table

# cur.execute('INSERT INTO books (title, author, pages_num, review)'
#             'VALUES (%s, %s, %s, %s)',
#             ('Dmitry R',
#              'big dick',
#              13,
#              'A great cock!')
#             )


# cur.execute('INSERT INTO books (title, author, pages_num, review)'
#             'VALUES (%s, %s, %s, %s)',
#             ('Ilya P',
#              'lil dick',
#              9,
#              'Another great cock!')
#             )

conn.commit()

cur.close()
conn.close()

