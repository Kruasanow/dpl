import osh
import attack_score.attack as at

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




############################# ANSWER ########################################
    # packet.append(a[i].dns.a)
    # packet.append(a[i].dns.count_add_rr)
    # packet.append(a[i].dns.count_answers)
    # packet.append(a[i].dns.count_auth_rr)
    # packet.append(a[i].dns.count_labels)
    # packet.append(a[i].dns.count_queries)
    # packet.append(a[i].dns.flags_authenticated)
    # packet.append(a[i].dns.flags_authoritative)
    # packet.append(a[i].dns.flags_opcode)
    # packet.append(a[i].dns.flags_rcode)
    # packet.append(a[i].dns.flags_recavail)
    # packet.append(a[i].dns.flags_recdesired)
    # packet.append(a[i].dns.flags_response)
    # packet.append(a[i].dns.flags_truncated)
    # packet.append(a[i].dns.flags_z)
    # packet.append(a[i].dns.id)
    # packet.append(a[i].dns.qry_class)
    # packet.append(a[i].dns.qry_name)
    # packet.append(a[i].dns.qry_type)
    # packet.append(a[i].dns.resp_class)
    # packet.append(a[i].dns.resp_ttl)
    # packet.append(a[i].dns.resp_type)
    # packet.append(a[i].dns.response_to)
    # packet.append(a[i].dns.time)
##############################################################################

######################### REQUEST ############################################ req = 0; resp = 1
    # packet.append(dns_arr[i].dns.count_add_rr)
    # packet.append(dns_arr[i].dns.count_answers)
    # packet.append(dns_arr[i].dns.count_auth_rr)
    # packet.append(dns_arr[i].dns.count_labels)
    # packet.append(dns_arr[i].dns.count_queries)
    # packet.append(dns_arr[i].dns.flags_opcode)
    # packet.append(dns_arr[i].dns.flags_recdesired)
    # packet.append(dns_arr[i].dns.flags_response)
    # packet.append(dns_arr[i].dns.flags_truncated)
    # packet.append(dns_arr[i].dns.flags_z)
    # packet.append(dns_arr[i].dns.id)
    # packet.append(dns_arr[i].dns.qry_class)
    # packet.append(dns_arr[i].dns.qry_name)
    # packet.append(dns_arr[i].dns.qry_type)
############################################################################# 