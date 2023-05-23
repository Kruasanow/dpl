from scapy.all import *
import argparse
from db_do.conn_db import get_db_connection

#Check server ability to make flood influence 
def read_servers():
    # with open(data_file) as servers_file:
    # server_list = [row.strip() for row in servers_file]
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM dnsampl;')
    dsave = cur.fetchall()
    cur.close()
    conn.close()
    server_list = []
    for i in dsave:
        server_list.append(list(i))
    print('[*]dns_server_check.py: ' + str(server_list))
    packets = 0
    return [server_list, packets] 

def dns_server_check_main(servers_list = read_servers()[0], timeout=2):
    i = 0
    for param in servers_list:
        status = False
        source_port = random.randint(1025, 65534)
        p = IP(dst = param[1]) / UDP(sport = source_port, dport = 53) / DNS(rd = 1, qd = DNSQR(qname = param[2], qtype = param[3]))
        send(p, inter = 0, verbose = 0, count = 100)
        resp = sr(p, timeout = timeout, verbose = 0)
        stat_arr = []
        for a in resp[0]:
            if a[1].haslayer(DNS):
                ampl_ratio = len(a[1]) / len(p)
                if ampl_ratio >= float(param[4]):
                    stat_var = a[1].src
                    stat_arr.append(stat_var)

                    status = True
        i += 1
    return [status, stat_arr]

print(dns_server_check_main()[1])
