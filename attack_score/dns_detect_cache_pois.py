from scapy.all import *
def detect_dnscachepois(cap, ur_ip):
    pcap = rdpcap(cap)

    # dns packet filter
    dns_packets = [pkt for pkt in pcap if DNS in pkt]
    detected_dnscp = []

    # test response by dns srv
    for pkt in dns_packets:
        if pkt.haslayer(DNSRR):
            if pkt.haslayer(IP):  # Add a check for the IP layer
                if pkt[DNSRR].rdata != ur_ip:
                    if '127.0.0' in pkt[IP].src:
                        continue
                    else:
                        detected_dnscp.append(pkt[IP].src)
    detected_dnscp = list(set(detected_dnscp))
    return detected_dnscp

# print(detect_dnscachepois('398in190-150323.pcapng','192.168.138.15'))