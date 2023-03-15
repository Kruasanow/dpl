import pyshark
import subprocess
import os
import db_do.conn_db as cdb

UPLOAD_FOLDER = 'dump_input/'
ALLOWED_EXTENSIONS = set(['pcap','pcapng'])
output_dump = 'out.txt'

def get_dname_from_db():
    good_dname = ''
    try:
        conn = cdb.get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT dname FROM dump_list;')
        case1 = cur.fetchall()
        cur.close()
        conn.close()
        good_dname = str(case1[-1]).translate({
                                    ord("'"): None, 
                                    ord("("): None,
                                    ord(")"): None,
                                    ord(","): None
                                    })
        print('[*]osh.py element choosed - ' + good_dname)
    except Exception:
        print('[*]osh.py: bad get dname!')
        # good_dname = 'qwe.pcapng'
    return good_dname

def get_file(name_of_file=None):
    cap = []
    if name_of_file == None:
        print('[*]osh.py: nothing choosed')
    try:
        # dir_list = os.listdir('dump_input/')
        full_way = 'dump_input/'+str(name_of_file)
        print('[*]osh.py: full way - ' +str(full_way))
        cap = pyshark.FileCapture(full_way)
        print('[*]osh.py: cap for pyshark - ' +str(cap))
    except Exception:
        print('[*]osh.py: get_file - exceptions worked...')
        # cap = pyshark.FileCapture('dump_input/qwe.pcapng')
    return cap

cap = get_file(get_dname_from_db())

def current_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS

def packet_counter(protocolName,cap):
    counter = 0
    for pac in cap:
        if pac.highest_layer == protocolName :
            counter=counter+1
    return counter

def convert_dump(name_before,name_after):
    subprocess.call(["./scripts/scr.sh",name_before,name_after])

def exec_db_init_sh():
    subprocess.call(["./scripts/environment_fix.sh"])

pac_t_list =['DNS','TCP','UDP','SSL','VSSMONITORING','DATA','ICMP']
def analize_table(pac_type_list,cap):
    arr = []
    for i in pac_type_list:
        arr.append(packet_counter(i,cap))
    print('[*]osh.py: packet counter - ' + str(arr))
    return arr


# dns_pack = packet_counter('DNS',cap)
# tcp_pack = packet_counter('TCP',cap)
# udp_pack = packet_counter('UDP',cap)
# ssl_pack = packet_counter('SSL',cap)
# vss_pack = packet_counter('VSSMONITORING',cap)
# data_pack = packet_counter('DATA',cap)
# icmp_pack = packet_counter('ICMP',cap)
