from db_do.conn_db import get_db_connection
import socket

def get_ns_list():
    conn = get_db_connection()

    cur = conn.cursor()

    cur.execute('SELECT server FROM dns_srv_profile;')
    get_servers_buff = cur.fetchall()
    get_servers = []
    for i in get_servers_buff:
        get_servers.append(str(list(i)).
                            replace('[','').
                            replace(']','').
                            replace("'",''))
    # print('[*]get_ns_list.py: nameservers - ',get_servers)
    cur.close()
    conn.close()

    return get_servers

# get_ns_list()

def get_ns_ip():
    nslist = get_ns_list()
    ip_list = []
    for i in nslist:
        try:
            ip_list.append(socket.gethostbyname(i))
        except Exception:
            ip_list.append('None')
    return ip_list

# print(get_ns_ip(get_ns_list()))

def do_ns_ip_tuple():
    g_ip_ns = dict(zip(get_ns_list(),get_ns_ip()))
    return g_ip_ns

# print(do_ns_ip_tuple())
