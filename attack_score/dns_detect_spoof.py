from scapy.all import *

# STILL MUST BE REWORKED !!!
def detect_dns_spoofing(cap):
    packets = rdpcap(cap)
    attacker = []
    for packet in packets:
        if packet.haslayer(DNSRR):
            dnsrr = packet[DNSRR]
            if dnsrr.type == 1: # Тип A
                ip_src = packet[IP].src
                ip_dst = packet[IP].dst
                if ip_dst != dnsrr.rdata: # Сравнение IP-адресов отправителя и получателя
                    attacker.append(ip_src) 
    return attacker

# print(detect_dns_spoofing('398in190-150323.pcapng'))