from collections import Counter
import ipaddress
from statistics import mean
import dns_codes_list as dcode
import conn_db as cdb

# a = osh.cap

def swap_dict_values(dict_a,dict_b):
    dict_a = dict(dict_a)
    swaped_dict = {}
    for key_a,value_a in dict_a.items():
        for key_b,value_b in dict_b.items():
            if key_a == key_b:
                swaped_dict[value_b] = value_a
    return swaped_dict

# Convert Main-dump to DNS-array
def to_dns_arr(a):
    dns_arr = []
    print('[*]dns_prepare_fdb.py: arr - ' + str(a))
    print(a)
    for pac in a:
        if pac.highest_layer == 'DNS':
            dns_arr.append(pac)
    return dns_arr

def get_unique_dns_srv(arr):
    unique_srv = []
    arr = to_dns_arr(arr)
    for i in arr:
        try:
            if i.dns.soa_mname in unique_srv:
                continue
            else:
                if int(i.dns.flags_response) == 1:
                    unique_srv.append(i.dns.soa_mname)
                else:
                    continue
        except AttributeError:
            continue
    return unique_srv

def get_unique_dns_domain(arr):
    unique_srv = []
    arr = to_dns_arr(arr)
    for i in arr:
        try:
            if i.dns.qry_name in unique_srv:
                continue
            elif i.dns.qry_name.find("in-addr.arpa") != -1:
                continue 
            else:
                if int(i.dns.flags_response) == 1:
                    unique_srv.append(i.dns.qry_name)
                else:
                    continue
        except AttributeError:
            continue
    return unique_srv

# Select only unique values to list
def is_unique(arr):
    un_var = []
    for i in arr:
        if i in un_var:
            continue
        else:
            un_var.append(i)
    return un_var

# Select packets from array by dns.qry_type
def arr_needed_domain(arr,domain):
    needed_arr_domain = []
    for i in arr:
        if str(i.dns.qry_name) == domain:
            needed_arr_domain.append(i)
        else:
            continue
    return needed_arr_domain

def arr_needed_dns_srv(arr,dns_name):
    needed_arr = []

    for i in arr:
        try:
            if i.dns.soa_mname == dns_name:
                needed_arr.append(i)
            else:
                continue
        except AttributeError:
            continue
    return needed_arr
 
def compare_name_src(cap):
    name_arr = []
    srv_arr = []
    arr_dump = []
    u_dump = []
    for i in cap:
        if hasattr(i.dns, 'soa_mname') == True:
            if 'in-addr.arpa' not in str(i.dns.qry_name):
                arr_dump.append(i)
    for i in  arr_dump:
        if i.dns.soa_mname in u_dump:
            continue
        else:
            u_dump.append(i)
            name_arr.append(i.dns.qry_name)
            srv_arr.append(i.dns.soa_mname)   
    qname_srv_dict = dict(zip(name_arr,srv_arr))
    return(qname_srv_dict)

# Select packets from dump by Query Name and PTR;
def get_dump_by_service(arr, qname):
    arr = to_dns_arr(arr)
    a_req_pac_arr = []
    list_a = []
    list_qname = []
    for a_req_pac in arr:
        if hasattr(a_req_pac.dns,"a") == True and str(a_req_pac.dns.qry_name) == qname:
            list_a.append(a_req_pac.dns.a)
            list_qname.append(a_req_pac.dns.qry_name)
        else:
            list_a.append('')
            list_qname.append('')
    a_req_pac_dict = dict(zip(list_a,list_qname))
    for i in a_req_pac_dict:
        if i == '':
            key = ''
        else:
            key = str(i)
    try:
        key = ipaddress.ip_address(key).reverse_pointer
    except ValueError:
        key = ''
    for i in arr:
        if str(i.dns.qry_name) == qname:
            a_req_pac_arr.append(i)
        if key == str(i.dns.qry_name):
            a_req_pac_arr.append(i)
    return(a_req_pac_arr)
# print(get_dump_by_service(a,'vk.com'))

# Prepare values to create DNS-profile tables
def get_dns_profile(arr):
    conn = cdb.get_db_connection()
    cur = conn.cursor()    
    array = to_dns_arr(arr)
    counter = 0
    # print("Domain names -" + str(list(compare_name_src(array).keys())))
    # print("SRV -" + str(list(compare_name_src(array).values())))

    for srv in compare_name_src(array).keys():
        rec_count =   0
        ans_count =   0
        a_rec =       0
        nameserver =  ''
        soa_refresh = 0
        soa_exp_limit=0
        soa_min_ttl = 0
        un_var =      []
        orphan_pacs = []
        a_rec_arr =   []
        rcode_arr =   []
        qtype_arr =   []
        qclass_arr =  []
        qname_list =  []
        opcode_arr =  []
        trunk_arr =   []
        rclass =      []
        rtype =       []
        recursion_arr=[]
        rttl =        []
        avg_resp_time=[]
        arr = get_dump_by_service(array,str(srv))
        for pac in arr:
            try:
                nameserver = str(pac.dns.soa_mname)
            except AttributeError:
                pass
            try:
                soa_refresh = int(pac.dns.soa_refresh_interval)
            except AttributeError:
                pass
            try:
                soa_exp_limit = int(pac.dns.soa_expire_limit)
            except AttributeError:
                pass
            try:
                soa_min_ttl = int(pac.dns.soa_mininum_ttl)
            except AttributeError:
                pass
            # Counting of request and response packets, their sum
            if int(pac.dns.flags_response) == 1:
                rec_count = rec_count + 1
            sum_pac = len(arr)
            ans_count = sum_pac - rec_count
            # Find orphaned packets ----------
            for i in arr:
                if i.dns.id in un_var:
                    continue
                else:
                    un_var.append(str(i.dns.id))
            for un_dns_id in arr:
                if un_dns_id.dns.id in un_var:
                    continue
                else:
                    orphan_pacs.append(str(un_dns_id.dns.id))                   
            # IP-addr that DNS-server returned (type A)
            for i in arr:
                try:
                    if i.dns.a:
                        a_rec_arr.append(i.dns.a)
                except AttributeError:
                    pass
            a_rec_arr = is_unique(a_rec_arr)
            # Count Errors and their type ------
            try:
                rcode_arr.append(int(pac.dns.flags_rcode))
            except AttributeError:
                pass
            # Count query codes and their types
            qtype_arr.append(int(pac.dns.qry_type))
            # Count query classes and their types
            qclass_arr.append(pac.dns.qry_class)
            # Count query names and their types
            if int(pac.dns.qry_type) == 1 or int(pac.dns.qry_type) == 28:
                qname_list.append(pac.dns.qry_name)
            # Count opcode's
            opcode_arr.append(int(pac.dns.flags_opcode))
            # Count trunkated
            trunk_arr.append(int(pac.dns.flags_truncated))
            # Count response class, type, ttl
            try:
                rclass.append(pac.dns.resp_class)
                rtype.append(int(pac.dns.resp_type))
                rttl.append(float(pac.dns.resp_ttl))
            except AttributeError:
                pass
            # Average response packet time
            try:
                avg_resp_time.append(float(pac.dns.time))
            except AttributeError:
                pass
            # Is available recursion on server
            try:
                recursion_arr.append(int(pac.dns.flags_recavail))
            except AttributeError:
                pass

        try:
            a_rec = str(a_rec_arr[0])
        except IndexError:
            a_rec = ''
        rtype =  str(swap_dict_values(dict(Counter(rtype)),dcode.RR_types_dict))   
        rclass = str(swap_dict_values(dict(Counter(rclass)),dcode.RR_classes_dict))
        rttl = float(mean(rttl))
        atime = float(mean(avg_resp_time))
        qname_list = is_unique(qname_list)[0]
        rcode_arr = str(swap_dict_values(dict(Counter(rcode_arr)),dcode.RCODE_dict))    
        qtype_arr = str(swap_dict_values(dict(Counter(qtype_arr)),dcode.RR_types_dict))    
        qclass_arr = str(swap_dict_values(dict(Counter(qclass_arr)),dcode.RR_classes_dict))   
        opcode_arr = str(swap_dict_values(dict(Counter(opcode_arr)),dcode.OPCODE_dict))
        trunk_arr = str(swap_dict_values(dict(Counter(trunk_arr)),dcode.Trunkated_pac))
        recursion_arr = str(swap_dict_values(dict(Counter(recursion_arr)),dcode.Recursive_pac))
        if orphan_pacs == []:
            orphan_pacs = 'None'
        else:
            orphan_pacs = str(orphan_pacs)
        sum_pac = int(sum_pac)
        rec_count = int(rec_count)
        ans_count = int(ans_count)
        nameserver = str(nameserver)
        soa_refresh = int(soa_refresh)
        soa_exp_limit = int(soa_exp_limit)
        soa_min_ttl = int(soa_min_ttl)
        
        counter = counter + 1

        cur.execute(
                    'INSERT INTO dns_srv_profile ('
                    'server, returned_a,'
                    'sum_pac, qtype, qclass,'
                    'rcode, recursion, avg_time,'
                    'avg_ttl, qname, opcode,'
                    'ans_pac, req_pac, trunk,'
                    'soa_refresh, soa_exp_limit, soa_min_ttl,'
                    'orphan, rtype, rclass)'
            'VALUES ('
                    '%s, %s, %s, %s,'
                    '%s, %s, %s, %s,'
                    '%s, %s, %s, %s,'
                    '%s, %s, %s, %s,'
                    '%s, %s, %s, %s'
                    ')',
                    (
                    nameserver, a_rec, sum_pac,
                    qtype_arr, qclass_arr, rcode_arr,
                    recursion_arr, atime, rttl,
                    qname_list, opcode_arr, ans_count,
                    rec_count, trunk_arr, soa_refresh,
                    soa_exp_limit, soa_min_ttl,
                    orphan_pacs, rtype, rclass,
                    )
                    )
        conn.commit()

        # print("SERVER - " + nameserver)#
        # print("ans_count - " + str(ans_count))
        # print("rec_count - " + str(rec_count))
        # print("sum_pac - " + str(sum_pac))#
        # print("orphan pacs - " + str(orphan_pacs))
        # print("rcode - " + str(rcode_arr))
        # print("qtype - " + str(qtype_arr))#
        # print("qclass - " + str(qclass_arr))
        # print("qname - " + str(qname_list))
        # print('a_record - ' + a_rec)
        # print("opcode - " + str(opcode_arr))
        # print("trunk - " + str(trunk_arr))
        # print("recursion - " + str(recursion_arr))
        # print("rtype - " + str(rtype))
        # print("rclass - " + str(rclass))
        # print("rttl - " + str(rttl))
        # print("average time - " + str(atime))

        # print("#--------------------------------------#")
    # return [nameserver, srv, a_rec, 
    #         sum_pac, qtype_arr, 
    #         qclass_arr, rcode_arr, 
    #         recursion_arr, atime, 
    #         rttl, qname_list, opcode_arr, 
    #         trunk_arr, rtype, rclass, 
    #         orphan_pacs, ans_count, rec_count]; 
    print('[*]dns_prepare_fdb.py: srv counter - '+str(counter))
    cur.close()
    conn.close()
    return counter
            