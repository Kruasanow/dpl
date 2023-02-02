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

def checkTTL(dump):
    aclTTL = ['54','64','128','255']
    countWIN = 0
    countUNIX = 0
    countSOLARISorCisco = 0
    countBSD = 0
    countUNDEF = 0

    for pac in dump:
        try:    
            if pac.ip.ttl == aclTTL[0]:
                countBSD = countBSD + 1
            elif pac.ip.ttl == aclTTL[1]:
                countUNIX = countUNIX + 1
            elif pac.ip.ttl == aclTTL[2]:
                countWIN = countWIN + 1
            elif pac.ip.ttl == aclTTL[3]:
                countSOLARISorCisco = countSOLARISorCisco + 1
            else:
                countUNDEF = countUNDEF + 1
        except:
            continue
    return countBSD,countUNIX,countWIN,countSOLARISorCisco,countUNDEF

def ussltlsDDOS(cap):
    cap = osh.cap
    countTLS = 0
    i = 0
    koefAlert = 0
    countAlert = 0
    for pac in cap:
        i = i + 1
        try:
            if pac.highest_layer == 'SSL':
                countTLS = countTLS + 1    
        except AttributeError:
            continue
    koefAlert = countTLS / i
    return countTLS, countAlert, koefAlert

print(ussltlsDDOS(osh.cap))

print(dir(osh.cap[72].ip))
print(osh.cap[72].ip.ttl)