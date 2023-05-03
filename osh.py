import pyshark
import subprocess
import db_do.conn_db as cdb

UPLOAD_FOLDER = 'dump_input/'
ALLOWED_EXTENSIONS = set(['pcap','pcapng'])
output_dump = 'out.txt'

def check_output():
    res = True
    with open('dump_output/out.txt', 'r') as f:
        first_line = next(f).strip()
    bad_line = 'ERF 0 Unknown type 77' #eto kakogo-to hu9 ne rabotaet tvar'
    if bad_line in first_line:
        res = False
    return res

def reload_arr(arr):
    for i in range(0,len(arr)):
        for j in range(0,len(arr[i])):
            arr[i][j] = str(arr[i][j]).translate({
                                ord("'"):None,
                                ord("{"):None,
                                ord("}"):None
                                })
    return arr

def delete_datetime(line):
    badline = 'datetime.datetime' # this does not work too, i do not know when i will fix it
    if badline in str(line):
        new_line = line.replace(badline,'')
    return new_line

def reload_list_by_who(lst):
    lst = str(lst).translate({
                            ord("'"):None,
                            ord("["):None,
                            ord("]"):None,
                            ord(")"):None,
                            ord("("):None
                             })
    return lst

def delete_empty(lst):
    lst = str(lst)
    if lst == '[]':
        lst = ''
    return lst

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
    return good_dname

def get_file(name_of_file=None):
    cap = []
    if name_of_file == None:
        print('[*]osh.py: nothing choosed')
    try:
        full_way = 'dump_input/'+str(name_of_file)
        print('[*]osh.py: full way - ' +str(full_way))
        cap = pyshark.FileCapture(full_way)
        print('[*]osh.py: cap for pyshark - ' +str(cap))
    except Exception:
        print('[*]osh.py: get_file - exceptions worked...')
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

pac_t_list =['DNS','TCP','SSL','VSSMONITORING','DATA','ICMP']

def analize_table(pac_type_list,cap):
    arr = []
    for i in pac_type_list:
        arr.append(packet_counter(i,cap))
    print('[*]osh.py: packet counter - ' + str(arr))
    return arr

def get_par_from_dns_srv(dbase,param1,param2):
    from db_do.conn_db import get_db_connection
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(f"SELECT {param1}, {param2} FROM {dbase}")
    parms = cur.fetchall()
    fpar = []
    spar = []
    for i in range(len(parms)):
        fpar.append(parms[i][0])
        spar.append(parms[i][1])
    cur.close()
    conn.close()
    return [fpar,spar]

# print(get_par_from_dns_srv('dns_srv_profile','server','sum_pac')[1])

def read_and_sort_outdump(proto):
    out_arr = []
    file = 'dump_output/out.txt'
    with open(file, 'r') as f:
      for line in f:
        if proto in line:
            out_arr.append(line.replace('\n',''))
            # print(line)
    return out_arr
print(read_and_sort_outdump('FTP'))