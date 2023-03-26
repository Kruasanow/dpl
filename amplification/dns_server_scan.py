from scapy.all import *
import argparse
from db_do.conn_db import get_db_connection

#do request to dns server and check amplification koef
def dns_scan(ip, qt,  q = '.',timeout=2):
    ampl_ratio = 0
    source_port = random.randint(1025, 65534)
    p = IP(dst = ip) / UDP(sport = source_port, dport = 53) / DNS(rd = 1, qd = DNSQR(qname = q, qtype = qt))
    resp = sr(p, timeout = timeout, verbose = 0)
    
    conn = get_db_connection()
    cur = conn.cursor()
    for a in resp[0]:
        if a[1].haslayer(DNS):
            ampl_ratio = len(a[1]) / len(p)
            cur.execute(
                    'INSERT INTO dnsampl ('
                    'ip, query,'
                    'qtype, koef'
                    ')'
            'VALUES ('
                    '%s, %s, %s, %s'
                    ')',
                    (
                    a[1].src, q, qt, str(ampl_ratio)
                    )
                    )
    conn.commit()
    cur.close()
    conn.close()
    return ampl_ratio
# dns_scan('216.239.34.10', 'NS')

# if __name__ == '__main__':
#     dns_scan()