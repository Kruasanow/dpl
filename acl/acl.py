from db_do.conn_db import get_db_connection
# ВОТ КАКОГО ХУЯ ОПЯТЬ ОКРУЖЕНИЕ ОТЪЕБНУЛО-ТО СУКА
def insert_ip_to_acl(ip):
    # from db_do.conn_db import get_db_connection
    conn = get_db_connection()

    cur = conn. cursor()
    cur.execute ('INSERT INTO acl (ipaddr) VALUES (%s)', (str(ip),))
    conn.commit 
    cur.close()
    conn.close()
print(insert_ip_to_acl('123'))

def get_ip_f_db():
    # from db_do.conn_db import get_db_connection
    conn = get_db_connection()
    cur = conn. cursor()
    cur.execute ('SELECT  ipaddr FROM acl')

    ips = cur.fetchall()    
    cur.close()
    conn.close()
    print(ips)
# print(get_ip_f_db())