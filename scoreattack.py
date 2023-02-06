import osh
import attack as at

def level_acl():
    bad_list = at.checkAcl(osh.cap,at.acl)[0]
    bad_count = at.checkAcl(osh.cap,at.acl)[1]
    bad_koef = bad_count / at.packet_count()
    if bad_koef >= 0.1:
        pointer = False
    else:
        pointer = True
    return bad_list, pointer

def level_ttl():
    arr = at.checkTTL(osh.cap)
    bad_unixwindows = arr[1]/arr[2]
    if bad_unixwindows >= 0.5:
        bad_pointer = False
    if arr[0] != 0 or arr[3] != 0 or arr[4] != 0:
        bad_pointer = True
    else:
        bad_pointer = False
    return bad_pointer

def level_icmp():
    return True

def level_udp():
    return True

def level_syn():
    return True

def DNSTZ():
    return at.DNStransferZone()

def DNSAMPL():
    return at.DNSAmplification()

def level_ssl():
    return True
