from scapy.all import *

def detect_dnsampl(cap):
    packets = rdpcap(cap)
    results = []
    for packet in packets:
        if packet.haslayer(IP) and packet.haslayer(DNS):
            dns = packet[DNS]
            if hasattr(dns, 'flags') and dns.flags & 0x2 != 0:
                # flag truncated = 1
                ip_src = packet[IP].src
                ip_dst = packet[IP].dst
                # qname = dns.qd.qname.decode()  
                # gstr = str(ip_src) + ' ' + str(ip_dst) + ' ' + qname
                gstr = str(ip_src) + ' ' + str(ip_dst)

                results.append(gstr)

        # if packet.haslayer(DNSQR) and packet.haslayer(IP):
        #     dnsqr = packet[DNSQR]
        #     if dnsqr.qtype == 255:
        #         ip_src = packet[IP].src
        #         ip_dst = packet[IP].dst
        #         qname = dnsqr.qname.decode()  
        #         gstr = str(ip_src) + ' ' + str(ip_dst)
        #         # gstr = str(ip_src) + ' ' + str(ip_dst) + ' ' + qname

        #         results.append(gstr)
    
    return results

# print(detect_dnsampl('dump_input/398in190-150323.pcapng'))