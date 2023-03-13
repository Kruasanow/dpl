import osh 
import dns_prepare_fdb as dprep
import dns_codes_list as dcode
import whois
import conn_db as cdb

conn = cdb.get_db_connection() 
cur = conn.cursor()
cur.execute('SELECT server FROM dns_srv_profile;')
table1_test = cur.fetchall() # SAVE DATA IN VARIABLE
good_exec_arr = []
print(table1_test)
# for i in table1_test:
#     t = 

cur.close()
conn.close()


cap = osh.cap
who_dict = {}
# who = whois.whois('visitnorway.com')
# print(who)