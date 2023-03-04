import main
import osh

a = osh.cap

# only DNS array
def to_dns_arr(a):
    dns_arr = []
    for pac in a:
        if pac.highest_layer == 'DNS':
            dns_arr.append(pac)
    print(len(dns_arr))
    return dns_arr

count_error = 0
conn = main.get_db_connection() 
cur = conn.cursor()
bad = []
for i in to_dns_arr(a):
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
                        'ip_src, ip_dst,'
                        'id_pac, qry_class, qry_name,'
                        'qry_type, flags_z, flags_truncated,'
                        'flags_response, flags_recdesired, flags_opcode,'
                        'count_queries, count_labels, count_auth_rr,'
                        'count_answers, count_add_rr, flags_authenticated,'
                        'flags_authoritative, flags_rcode, flags_recavail,'
                        'resp_class, resp_ttl, resp_type,'
                        'response_to, a_return_rec)'
                'VALUES ('
                        '%s, %s, %s, %s,'
                        '%s, %s, %s, %s,'
                        '%s, %s, %s, %s,'
                        '%s, %s, %s, %s,'
                        '%s, %s, %s, %s,'
                        '%s, %s, %s, %s,'
                        '%s)',
                        (
            str(i.ip.src if hasattr(i.ip, "src") else ""),
            str(i.ip.dst if hasattr(i.ip, "dst") else ""),
            str(i.dns.id if hasattr(i.dns, "id") else ""),
            str(i.dns.qry_class if hasattr(i.dns, "qry_class") else ""),
            str(i.dns.qry_name if hasattr(i.dns, "qry_name") else ""),
            str(i.dns.qry_type if hasattr(i.dns, "qry_type") else ""),
            str(i.dns.flags_z if hasattr(i.dns, "flags_z") else ""),
            str(i.dns.flags_truncated if hasattr(i.dns, "flags_truncated") else ""),
            str(i.dns.flags_response if hasattr(i.dns, "flags_response") else ""),
            str(i.dns.flags_recdesired if hasattr(i.dns, "flags_recdesired") else ""),
            str(i.dns.flags_opcode if hasattr(i.dns, "flags_opcode") else ""),
            str(i.dns.count_queries if hasattr(i.dns, "count_queries") else ""),
            str(i.dns.count_labels if hasattr(i.dns, "count_labels") else ""),
            str(i.dns.count_auth_rr if hasattr(i.dns, "count_auth_rr") else ""),
            str(i.dns.count_answers if hasattr(i.dns, "count_answers") else ""),
            str(i.dns.count_add_rr if hasattr(i.dns, "count_add_rr") else ""),
            str(i.dns.flags_authenticated if hasattr(i.dns, "flags_authenticated") else ""),
            str(i.dns.flags_authoritative if hasattr(i.dns, "flags_authoritative") else ""),
            str(i.dns.flags_rcode if hasattr(i.dns, "flags_rcode") else ""),
            str(i.dns.flags_recavail if hasattr(i.dns, "flags_recavail") else ""),
            str(i.dns.resp_class if hasattr(i.dns, "resp_class") else ""),
            str(i.dns.resp_ttl if hasattr(i.dns, "resp_ttl") else ""),
            str(i.dns.resp_type if hasattr(i.dns, "resp_type") else ""),
            str(i.dns.response_to if hasattr(i.dns, "response_to") else ""),
            str(i.dns.a if hasattr(i.dns, "a") else "")
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

def get_unique_dns_srv(arr):
    unique_srv = []
    arr = to_dns_arr(arr)
    for i in arr:
        if i.ip.src in unique_srv:
            continue
        else:
            if int(i.dns.flags_response) == 1:
                unique_srv.append(i.ip.src)
            else:
                continue
    return unique_srv

def is_unique(arr):
    un_var = []
    for i in arr:
        if i in un_var:
            continue
        else:
            un_var.append(i)
    return un_var

def arr_needed_ip(arr,ip):
    needed_arr = []
    for i in arr:
        if int(i.dns.flags_response) == 1 and str(i.ip.src) == ip:
            needed_arr.append(i)
        else:
            continue
    return needed_arr
 

def get_dns_profile(arr):
    array = to_dns_arr(arr)
    dns_srv_list = get_unique_dns_srv(arr)

    for u_ip in dns_srv_list:
        rec_count = 0
        un_var = []
        orphan_pacs = []
        a_rec_arr = []
        for pac in arr_needed_ip(array,str(u_ip)):
            # Считаю количество запросов и ответов
            if int(pac.dns.flags_response) == 1:
                rec_count = rec_count + 1
            else:
                ans_count = ans_count + 1
            sum_pac = rec_count + ans_count
            #----------------------------------

            # Ищу осиротевшие пакеты ----------
            for i in array:
                if i.dns.id in un_var:
                    continue
                else:
                    un_var.append(str(i.dns.id))

            for un_dns_id in array:
                if un_dns_id.dns.id in un_var:
                    continue
                else:
                    orphan_pacs.append(str(un_dns_id.dns.id))
            #----------------------------------

            # IP-addr которые вернул сервер (тип А)
            one_srv_resp = arr_needed_ip(array,str(u_ip))
            for i in one_srv_resp:
                try:
                    if i.dns.a:
                        a_rec_arr.append(i)
                except AttributeError:
                    continue
            #-----------------------------------
        print(str(rec_count) + ' rec_count')
        print(str(ans_count) + ' ans_count')
        print(str(sum_pac) + ' sum_count')
        print(str(orphan_pacs) + ' orphan_pacs')
        print(str(a_rec_arr) + ' a_rec_arr')

print('------------------------------------------------')
get_dns_profile(to_dns_arr(a))







# print(get_unique_dns_srv(a))
















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

