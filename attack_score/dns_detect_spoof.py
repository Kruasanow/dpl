from scapy.all import *

# STILL MUST BE REWORKED !!!
def detect_dns_spoofing(cap):
    packets = rdpcap(cap)
    attacker = []
    for packet in packets:
        if packet.haslayer(DNSRR):
            dnsrr = packet[DNSRR]
            if dnsrr.type == 1: # 1 equals type A
                try:
                    ip_src = packet[IP].src
                except Exception:
                    ip_src = ''
                try:
                    ip_dst = packet[IP].dst
                except Exception:
                    ip_dst = ''
                if ip_dst != dnsrr.rdata: # Check ip add src and ip dst
                    if '127.0.0' in str(ip_src):
                        continue
                    else:
                        attacker.append(ip_src) 
    return attacker

# print(detect_dns_spoofing('test.pcapng'))