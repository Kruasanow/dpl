import sys
sys.path.append('/home/ubuntu18/diploma-1/dpl')
from db_do.conn_db import get_db_connection
import ipaddress


def insert_ip_to_acl(ip):

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute ('INSERT INTO acl (ipaddr) VALUES (%s)', (str(ip),))
    conn.commit()
    cur.close()
    conn.close()
# insert_ip_to_acl('123')


def get_ip_f_db():

    conn = get_db_connection()
    cur = conn. cursor()
    cur.execute ('SELECT  ipaddr FROM acl')
    ips = cur.fetchall()    
    cur.close()
    conn.close()
    list_ips = []
    for i in ips:
        list_ips.append(i[0])
    # print(list_ips)
    return list_ips

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def clear_acl():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute ('DELETE FROM acl')
    conn.commit()
    cur.close()
    conn.close()
# clear_acl()

def unique_ip(ip):
    res = True
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute ('SELECT * FROM acl')
    ips = cur.fetchall()
    # print(ips)
    for i in ips:
        print(i[1])
        if i[1] == ip:
            res = False
    cur.close()
    conn.close()
    return res
# print(unique_ip('1.2.1.3'))

def find_acl(proto):
    from osh import read_and_sort_outdump
    list_ip_from_acl = get_ip_f_db()
    file = read_and_sort_outdump(proto)
    out_arr = []
    # print(list_ip_from_acl)
    for i in file:
        a = i.split(" ")
        start_point = a.index('→')
        if a[start_point-1] in list_ip_from_acl or a[start_point+1] in list_ip_from_acl:
            i+=' #ACL#'
        out_arr.append(i)
    return out_arr
# print(find_acl('DNS'))

