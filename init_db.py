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
                                 'ip_src varchar (64),'
                                 'ip_dst varchar (64),'
                                 'id_pac varchar (64),' #
                                 'a_return_rec varchar (64),' #
                                 'flags_authenticated varchar (10),'  #
                                 'flags_authoritative varchar (10),'  #
                                 'flags_opcode varchar (256),'  #
                                 'flags_rcode varchar (256),' #
                                 'flags_recavail varchar (10),' #
                                 'flags_recdesired varchar (10),' #
                                 'flags_response varchar (10),'  #
                                 'flags_truncated varchar (10),'  #
                                 'flags_z varchar (10),' #
                                 'qry_class varchar (128),'  #
                                 'qry_name varchar (128),'  #
                                 'qry_type varchar (128),' #
                                 'resp_class varchar (128),' #
                                 'resp_ttl varchar (128),'  #
                                 'resp_type varchar (128),' #
                                 'response_to varchar (256),' #
                                 'time varchar (30),'
                                 'soa_expire_limit varchar (128),'
                                 'soa_mininum_ttl varchar (128),'
                                 'soa_mname varchar (128),'
                                 'soa_refresh_interval varchar (128),'
                                 'soa_retry_interval varchar (128),'
                                 'soa_rname varchar (128),'
                                 'soa_serial_number varchar (128),'
                                 'count_add_rr varchar (10),' #
                                 'count_answers varchar (10),' #
                                 'count_auth_rr varchar (10),' #
                                 'count_labels varchar (10),' # 
                                 'count_queries varchar (10),' #
                                 'date_added date DEFAULT CURRENT_TIMESTAMP);'
                                 )

cur.execute('DROP TABLE IF EXISTS dns_srv_profile;')
cur.execute('CREATE TABLE dns_srv_profile (id serial PRIMARY KEY,'
                                 'server varchar (50),'# #
                                 'name varchar (50),'# #
                                 'returned_a varchar (40),'# #
                                 'sum_pac int,'# #
                                 'qtype varchar (100),'# #
                                 'qclass varchar (100),'# #
                                 'rcode varchar (100),'# #
                                 'recursion varchar (10),'# #
                                 'avg_time real,'# #
                                 'avg_ttl real,'# #
                                 'qname varchar (50),'# #
                                 'opcode varchar (100),'#
                                 'ans_pac int,'# #
                                 'req_pac int,'# #
                                 'trunk varchar (256),'# #
                                 'orphan varchar (200),'# #
                                 'rtype varchar (100),'# #
                                 'rclass varchar (100));'# #
                                 ) 


conn.commit()

cur.close()
conn.close()

