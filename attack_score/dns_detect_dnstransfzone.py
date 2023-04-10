from scapy.all import *

def detect_dns_zone_transfer(cap):
    packets = rdpcap(cap)
    res = []
    for packet in packets:
        if packet.haslayer(DNS):
            dns = packet[DNS]
            if dns.opcode == 6: # if opcode has 6 value it mean transfer may be exist
                res.append(packet[IP].src)
    print(packets)
    return res

# print(detect_dns_zone_transfer('../dump_input/qwe1.pcapng'))