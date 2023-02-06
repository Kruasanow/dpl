import pyshark
import subprocess
import os

UPLOAD_FOLDER = 'dump_input/'
ALLOWED_EXTENSIONS = set(['pcap','pcapng'])
output_dump = 'out.txt'

try:
    dir_list = os.listdir('dump_input/')
    full_way = 'dump_input/'+str(dir_list[0])
    print(full_way)
    cap = pyshark.FileCapture(full_way)
    print(cap)
except:
    cap = pyshark.FileCapture('dump_input/ddd.pcapng')

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
    subprocess.call(["./scr.sh",name_before,name_after])



dns_pack = packet_counter('DNS',cap)
tcp_pack = packet_counter('TCP',cap)
udp_pack = packet_counter('UDP',cap)
ssl_pack = packet_counter('SSL',cap)
vss_pack = packet_counter('VSSMONITORING',cap)
data_pack = packet_counter('DATA',cap)
icmp_pack = packet_counter('ICMP',cap)
