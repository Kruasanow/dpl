import whois
import conn_db as cdb

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

good_arr = get_qname_list()
def do_whois(arr):
    res_arr = []
    who_list_json = []
    for i in good_arr:
        who = whois.whois(i)
        who_list_json.append(who)
        print(who)
        print('-----------')
        if who.country != None:
            res_arr.append(who.country)
            continue
        if who.registrant_country != None:
            res_arr.append(who.registrant_country)
            continue
    res_arr_once = [2]*len(res_arr)
    final_dict = dict(zip(res_arr,res_arr_once))
    return final_dict

print(do_whois(good_arr))