import pyshark as ps

a = ps.FileCapture('dump_input/qwe.pcapng')

arr = []
for pac in a:
    if pac.highest_layer == 'DNS':
        arr.append(pac)
print(len(arr))

packet = []

try:

############################# ANSWER ########################################

    # packet.append(a[i].dns.a)
    # packet.append(a[i].dns.count_add_rr)
    # packet.append(a[i].dns.count_answers)
    # packet.append(a[i].dns.count_auth_rr)
    # packet.append(a[i].dns.count_labels)
    # packet.append(a[i].dns.count_queries)
    # packet.append(a[i].dns.flags_authenticated)
    # packet.append(a[i].dns.flags_authoritative)
    # packet.append(a[i].dns.flags_checkdisable)
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


######################### REQUEST ############################################

    packet.append(a[i].dns.count_add_rr)
    packet.append(a[i].dns.count_answers)
    packet.append(a[i].dns.count_auth_rr)
    packet.append(a[i].dns.count_labels)
    packet.append(a[i].dns.count_queries)
    packet.append(a[i].dns.flags_checkdisable)
    packet.append(a[i].dns.flags_opcode)
    packet.append(a[i].dns.flags_recdesired)
    packet.append(a[i].dns.flags_response)
    packet.append(a[i].dns.flags_truncated)
    packet.append(a[i].dns.flags_z)
    packet.append(a[i].dns.id)
    packet.append(a[i].dns.qry_class)
    packet.append(a[i].dns.qry_name)
    packet.append(a[i].dns.qry_type)

#############################################################################
    
except AttributeError:
    pass

for k in packet:
    print(k)