import main
import osh

a = osh.cap

# only DNS array
dns_arr = []
for pac in a:
    if pac.highest_layer == 'DNS':
        dns_arr.append(pac)
print(len(dns_arr))

count_error = 0
conn = main.get_db_connection() 
cur = conn.cursor()
bad = []
for i in dns_arr:
    if int(i.dns.flags_response) == 0:
            cur.execute('INSERT INTO dns_flags ('
                        'ip_src, ip_dst, id_pac,'
                        'qry_class, qry_name,' 'qry_type,'
                        'flags_z, flags_truncated, flags_response,'
                        'flags_recdesired, flags_opcode, count_queries,'
                        'count_labels, count_auth_rr, count_answers,'
                        'count_add_rr)'
                'VALUES ('
                        '%s, %s, %s, %s,'
                        '%s, %s, %s, %s,'
                        '%s, %s, %s, %s,'
                        '%s, %s, %s, %s)',
                        (
            str(i.ip.src),
            str(i.ip.dst),
            str(i.dns.id),
            str(i.dns.qry_class),
            str(i.dns.qry_name),
            str(i.dns.qry_type),
            int(i.dns.flags_z),
            int(i.dns.flags_truncated),
            int(i.dns.flags_response),
            int(i.dns.flags_recdesired),
            int(i.dns.flags_opcode),
            str(i.dns.count_queries),
            str(i.dns.count_labels),
            str(i.dns.count_auth_rr),
            str(i.dns.count_answers),
            str(i.dns.count_add_rr)
            )
            )
    elif int(i.dns.flags_response) == 1:
        try:
            cur.execute('INSERT INTO dns_flags ('
                        'id_pac, qry_class, qry_name,'
                        'qry_type, flags_z, flags_truncated,'
                        'flags_response, flags_recdesired, flags_opcode,'
                        'count_queries, count_labels, count_auth_rr,'
                        'count_answers, count_add_rr, flags_authenticated,'
                        'flags_authoritative, flags_rcode, flags_recavail,'
                        'resp_class, resp_ttl, resp_type,'
                        'response_to, a_return_rec)'
                'VALUES (%s, %s, %s, %s,'
                        '%s, %s, %s, %s,'
                        '%s, %s, %s, %s,'
                        '%s, %s, %s, %s,'
                        '%s, %s, %s, %s,'
                        '%s, %s, %s)',
                        (
            str(i.dns.id),
            str(i.dns.qry_class),
            str(i.dns.qry_name),
            str(i.dns.qry_type),
            str(i.dns.flags_z),
            str(i.dns.flags_truncated),
            str(i.dns.flags_response),
            str(i.dns.flags_recdesired),
            str(i.dns.flags_opcode),
            str(i.dns.count_queries),
            str(i.dns.count_labels),
            str(i.dns.count_auth_rr),
            str(i.dns.count_answers),
            str(i.dns.count_add_rr),
            str(i.dns.flags_authenticated),
            str(i.dns.flags_authoritative),
            str(i.dns.flags_rcode),
            str(i.dns.flags_recavail),
            str(i.dns.resp_class),
            str(i.dns.resp_ttl),
            str(i.dns.resp_type),
            str(i.dns.response_to),
            str(i.dns.a)
            )
            )
        except AttributeError:
            print('something WRONG - ' + str(i.dns.id) + " " +str(i.dns.flags_response))
            bad.append(i)
            count_error = count_error + 1
            continue
print(count_error)
print(bad)

conn.commit()
cur.close()
conn.close()

    















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

