import pyshark
import subprocess

cap = pyshark.FileCapture('dump_input/wsh_dump.pcapng')

def packet_counter(protocolName,cap):
    counter = 0
    for pac in cap:
        if pac.highest_layer == protocolName :
            counter=counter+1
    return counter

def convert_dump(name_before,name_after):
    subprocess.call(["./scr.sh",name_before,name_after])
input_dump = 'wsh_dump.pcapng'
output_dump = 'out.txt'


dns_pack = packet_counter('DNS',cap)
tcp_pack = packet_counter('TCP',cap)
udp_pack = packet_counter('UDP',cap)
ssl_pack = packet_counter('SSL',cap)
vss_pack = packet_counter('VSSMONITORING',cap)
data_pack = packet_counter('DATA',cap)
icmp_pack = packet_counter('ICMP',cap)
