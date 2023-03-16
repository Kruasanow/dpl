from db_do.conn_db import get_db_connection

def get_srv_from_db():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT * FROM dns_srv_profile;')
        case1 = cur.fetchall()
        cur.close()
        conn.close()
        print('[*]db_selector.py: selected by dns_srv_profile')
        print(case1)
    except Exception:
        print('[*]db_selector.py: error exists!')
    return case1