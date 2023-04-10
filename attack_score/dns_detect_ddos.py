from scapy.all import *

def detect_dns_ddos(cap, limit):
    packets = rdpcap(cap)

    ip_counts = {}

    for packet in packets:
        if packet.haslayer(DNS) and packet.haslayer(IP):
            dns = packet[DNS]
            if dns.opcode == 0:
                ip_src = packet[IP].src
                if ip_src in ip_counts:
                    ip_counts[ip_src] += 1
                else:
                    ip_counts[ip_src] = 1

    # unique IP-addr with their limit value
    for ip in ip_counts:
        if ip_counts[ip] > limit: # Limit 
            ddos_attacker = ip
        else:
            ddos_attacker = ''
    return ddos_attacker

# print(detect_dns_ddos('../test.pcapng',50))