import whois
import conn_db as cdb

def get_qname_list():
    try:
        conn = cdb.get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT qname FROM dns_srv_profile;')
        case1 = cur.fetchall()
        print('[*]dns_whois.py: base selected - ' + str(case1[-1]))
        cur.close()
        conn.close()
    except Exception:
        print('[*]dns_whois.py: error exists!')

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

# good_arr = get_qname_list()
def do_whois(good_arr):
    res_arr = []
    who_list_json = []
    for i in good_arr:
        who = whois.whois(i)
        who_list_json.append(who)
        print('[*]dns_whois.py: ')
        print(who)
        print('-----------')
        if who.country != None:
            res_arr.append(who.country)
            continue
        if who.registrant_country != None:
            res_arr.append(who.registrant_country)
            continue
        if who.country == 'UK':
            res_arr.append('GB')
            continue
        if who.registrant_country == 'UK':
            res_arr.append('GB')
            continue
    res_arr_once = [2]*len(res_arr)
    final_dict = dict(zip(res_arr,res_arr_once))
    return [final_dict, who_list_json]

def get_items_from_who(arr):
    country =      []
    state =        []
    city =         []
    address =      []
    org =          []
    emails =       []
    name_servers = []
    creation_date= []
    updated_date = []
    registrar =    []
    domain_name =  []
    for i in arr:
        try:
            country.append(i.country)
        except Exception:
            country.append("")
        try:
            state.append(i.state)
        except Exception:
            state.append("") 
        try:
            city.append(i.city)
        except Exception:
            city.append("") 
        try:
            address.append(i.address)
        except Exception:
            address.append("") 
        try:
            org.append(i.org)
        except Exception:
            org.append("") 
        try:
            emails.append(i.emails)
        except Exception:
            emails.append("") 
        try:
            name_servers.append(i.name_servers)
        except Exception:
            name_servers.append("") 
        try:
            creation_date.append(i.creation_date)
        except Exception:
            creation_date.append("") 
        try:
            updated_date.append(i.updated_date)
        except Exception:
            updated_date.append("") 
        try:
            registrar.append(i.registrar)
        except Exception:
            registrar.append("") 
        try:
            domain_name.append(i.domain_name)
        except Exception:
            domain_name.append("") 
    return [
            country, state, city,
            address, org, emails,
            name_servers, creation_date,
            updated_date, registrar,
            domain_name
            ]

# def delete_none(arr):
#     for i in arr:
#         for j in i:
#             if j == None:
#                 arr[i][j] = ''
#     return arr

def transponate_arr(arr):
    # delete_none(arr)
    zarr = zip(*arr)
    tarr = [list(row) for row in zarr]
    return tarr
