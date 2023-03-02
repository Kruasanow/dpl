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
cur.execute('DROP TABLE IF EXISTS dns;')
cur.execute('CREATE TABLE dns_flags (id serial PRIMARY KEY,'
                                 'id_pac varchar (20),' #
                                 'a_return_rec varchar (20),'
                                 'flags_authenticated varchar (20),' 
                                 'flags_authoritative varchar (20),' 
                                 'flags_checkdisable varchar (20),' #
                                 'flags_opcode varchar (20),' #
                                 'flags_rcode varchar (20),'
                                 'flags_recavail varchar (20),' 
                                 'flags_recdesired varchar (20),' #
                                 'flags_response varchar (20),' #
                                 'flags_truncated varchar (20),' #
                                 'flags_z varchar (20),' #
                                 'qry_class varchar (20),' #
                                 'qry_name varchar (20),' #
                                 'qry_type varchar (20),' #
                                 'resp_class varchar (20),'
                                 'resp_ttl varchar (20),'
                                 'resp_type varchar (20),'
                                 'response_to varchar (20),'
                                 'time varchar (20),'
                                 'count_add_rr varchar (20),' #
                                 'count_answers varchar (20),' #
                                 'count_auth_rr varchar (20),' #
                                 'count_labels varchar (20),' # 
                                 'count_queries varchar (20),' #
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

