import pyshark as ps

a = ps.FileCapture('dump_input/qwe.pcapng')

# only DNS array
dns_arr = []
for pac in a:
    if pac.highest_layer == 'DNS':
        dns_arr.append(pac)
print(len(dns_arr))

print(dns_arr[3].dns)
print(dir(dns_arr[3].dns))

# for i in dns_arr:
#     if i.dns.flags_response == 0:

#     elif i.dns.flags_response == 1:

#     else:

    















# i = int(input())
# try:
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
    # packet.append(dns_arr[i].dns.flags_checkdisable)
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
# except AttributeError:
#     pass
# for k in packet:
#     print(k)

