import whois
import conn_db as cdb
import osh

print(osh.get_dname_from_db())

def get_qname_list():
    try:
        conn = cdb.get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT qname FROM dns_srv_profile;')
        case1 = cur.fetchall()
        cur.close()
        conn.close()
    except Exception:
        print('error exists!')

    qname_arr = []
    ldomain = 'localdomain'
    for i in case1:
        if ldomain in str(i):
            continue
        qname_arr.append(str(i).translate({
                                    ord("'"): None, 
                                    ord("("): None,
                                    ord(")"): None,
                                    ord(","): None
                                    }))
    
    return qname_arr

# print(get_qname_list())