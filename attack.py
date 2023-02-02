import osh

acl = ['192.168.49.2','192.168.49.139']

def checkAcl(dump,acl):
    badArr = []
    counter = 0
    counterTrue = 0
    for pac in dump:
        try:
            if pac.ip.src != acl[0] and pac.ip.src != acl[1]:
                if pac.ip.src not in badArr:    
                    badArr.append(pac.ip.src)
                    counterTrue = counterTrue + 1
                counter = counter + 1
        except AttributeError:
            continue
    return badArr,counter,counterTrue
print(checkAcl(osh.cap,acl))

def icmpFlood(cap):
    cap = osh.cap
    countIcmp = 0
    for pac in cap:
        if pac.highest_layer == 'ICMP':
            countIcmp = countIcmp + 1
    return countIcmp

def udpFlood(cap):
    cap = osh.cap
    countUdp = 0
    for pac in cap:
        if pac.highest_layer == 'UDP':
            countUdp = countUdp + 1
    return countUdp

def synFlood(cap):
    cap = osh.cap
    countSyn = 0
    for pac in cap:
        if 'RST' in pac:
            countSyn = countSyn + 1
    return countSyn

# print(osh.cap[49].ip.src)
# print(synFlood(osh.cap))