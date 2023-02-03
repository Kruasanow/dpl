import osh, attack

def level_acl():
    bad_list = attack.checkAcl(osh.cap,attack.acl)[0]
    bad_count = attack.checkAcl(osh.cap,attack.acl)[1]
    bad_koef = bad_count / attack.packet_count()
    if bad_koef >= 0.1:
        pointer = False
    else:
        pointer = True
    return bad_list, pointer

def level_icmp():
    bad_count = attack.icmpFlood(osh.cap)
    bad_koef = bad_count / attack.packet_count()
    if bad_koef >= 0.1:
        pointer = False
    else:
        pointer = True
    return pointer

def level_udp():
    bad_count = attack.udpFlood(osh.cap)
    bad_koef = bad_count / attack.packet_count()
    if bad_koef >= 0.5:
        pointer = False
    else:
        pointer = True
    return pointer

def level_syn():
    bad_count = attack.synFlood(osh.cap)
    bad_koef = bad_count / attack.packet_count()
    if bad_koef >= 0.1:
        pointer = False
    else:
        pointer = True
    return pointer

def level_ttl():
    arr = attack.checkTTL(osh.cap)
    bad_unixwindows = arr[1]/arr[2]
    if bad_unixwindows >= 0.5:
        bad_pointer = False
    if arr[0] != 0 or arr[3] != 0 or arr[4] != 0:
        bad_pointer = True
    else:
        bad_pointer = False
    return bad_pointer

def DNSTZ():
    return attack.DNStransferZone()

def DNSAMPL():
    return attack.DNSAmplification()

def level_ssl():
    if attack.ussltlsDDOS(osh.cap)[2] >= 0.3:
        pointer = False
    else:
        pointer = True
    return pointer
