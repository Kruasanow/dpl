import osh

acl = ['192.168.49.2','192.168.49.139']

def packet_count():
    index = 0
    for pac in osh.cap:
        index = index + 1
    return index

def checkAcl(dump,acl): # YES
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

def icmpFlood(cap): # YES
    cap = osh.cap
    countIcmp = 0
    for pac in cap:
        if pac.highest_layer == 'ICMP':
            countIcmp = countIcmp + 1
    return countIcmp

def udpFlood(cap): # NO
    return True

def synFlood(cap): # NO
    return True

def checkTTL(dump): # YES
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
    # cap = osh.cap
    # countTLS = 0
    # i = 0
    # koefAlert = 0
    # countAlert = 0
    # for pac in cap:
    #     i = i + 1
    #     try:
    #         if pac.highest_layer == 'SSL':
    #             countTLS = countTLS + 1    
    #     except AttributeError:
    #         continue
    # koefAlert = countTLS / i
    # return countTLS, countAlert, koefAlert
    return True

def DNStransferZone():
    return True

def DNSAmplification():
    return True
