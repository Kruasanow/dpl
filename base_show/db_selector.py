from db_do.conn_db import get_db_connection

def get_srv_from_db():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT server, sum_pac, recursion,'
                    'avg_time, avg_ttl, qname,'
                    'trunk, orphan, rcode, date_added '
                    'FROM dns_srv_profile;')
        case1 = cur.fetchall()
        cur.execute('SELECT server, qname, returned_a, id, qtype,'
                    'qclass, rtype, rclass, opcode, ans_pac,'
                    'req_pac, soa_refresh, soa_exp_limit, soa_min_ttl '
                    'FROM dns_srv_profile;'
                    )
        case11 = cur.fetchall()
        cur.close()
        conn.close()
        print('[*]db_selector.py: selected by dns_srv_profile')
        case2 = []
        case22 = []
        for i in case11:
            case22.append(list(i))
        for i in case1:
            case2.append(list(i))
        # print(type(case2))
        # print(case2)
        # print(type(case2[0]))
        # print(case2[0])
        # print(type(case2[0][4]))
        # print(case2[0][4])
        # case1 = case1
    except Exception:
        print('[*]db_selector.py: error exists!')
    return [case2, case22]