import csv

def is_ip_in_range(ip_address, ip_range):

    ip = [int(x) for x in ip_address.split('.')]
    start, end = ip_range.split('-')
    start = [int(x) for x in start.split('.')]
    end = [int(x) for x in end.split('.')]
    start_int = start[0] * 256 ** 3 + start[1] * 256 ** 2 + start[2] * 256 + start[3]
    end_int = end[0] * 256 ** 3 + end[1] * 256 ** 2 + end[2] * 256 + end[3]
    ip_int = ip[0] * 256 ** 3 + ip[1] * 256 ** 2 + ip[2] * 256 + ip[3]
    return start_int <= ip_int <= end_int


def get_geo_asn(ip,base):
    with open(base, newline='') as csvfile:
        reader = csv.reader(csvfile, delimiter=',', quotechar='"')
        for row in reader:
            range_ip = str(row[0]+'-'+row[1])
            if is_ip_in_range(ip,range_ip):
                res = row[2]
                # print(row[2])
    return res

def get_ip_from_db():
    from db_do.conn_db import get_db_connection
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute('SELECT returned_a FROM dns_srv_profile')
    a_list = cur.fetchall()
    ips = [row[0] for row in a_list if row[0] != '']
    cur.close()
    conn.close()
    return ips

def get_country_list(base):
    co_list = []
    for i in get_ip_from_db():
        co_list.append(get_geo_asn(i,base))
    co_dict = {}
    for j in co_list:
        co_dict[j] = 2
    return co_dict

def show_dir_base():
    import os
    path = 'ip_base'  # путь к папке
    dir_contents = os.listdir(path) 
    return dir_contents
# print(show_dir_base())

def base_to_db(): # не реализовано удаление из базы если убрали файл из директории - да и хуй с ним, я буду дома вовремя
    from db_do.conn_db import get_db_connection
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM geo_base")
    actual_base = cur.fetchall()
    # print(actual_base)
    a_base = []
    for i in actual_base:
        a_base.append(i[1])
    # print(a_base)
    for i in show_dir_base():
        if i in a_base:
            continue
        else:
            cur.execute('INSERT INTO geo_base (base) VALUES (%s)',(i,))
            conn.commit()
    cur.close()
    conn.close()

# base_to_db()
# print(show_dir_base())
# print(get_country_list('ip_base/asn-country-ipv4.csv'))
