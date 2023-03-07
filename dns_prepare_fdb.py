import osh
from collections import Counter
import ipaddress
from statistics import mean

a = osh.cap

# Convert Main-dump to DNS-array
def to_dns_arr(a):
    dns_arr = []
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
            continue
    a_req_pac_dict = dict(zip(list_a,list_qname))
    key = list(a_req_pac_dict.keys())[0]
    key = ipaddress.ip_address(key).reverse_pointer
    for i in arr:
        if str(i.dns.qry_name) == qname:
            a_req_pac_arr.append(i)
        if key == str(i.dns.qry_name):
            a_req_pac_arr.append(i)
    return(a_req_pac_arr)
# print(get_dump_by_service(a,'vk.com'))

# Prepare values to create DNS-profile tables
def get_dns_profile(arr):
    array = to_dns_arr(arr)

    print("Domain names -" + str(list(compare_name_src(array).keys())))
    print("SRV -" + str(list(compare_name_src(array).values())))

    for srv in compare_name_src(array).keys():
        print(srv)
        rec_count = 0
        ans_count = 0
        un_var = []
        orphan_pacs = []
        a_rec_arr = []
        arr = get_dump_by_service(array,str(srv))
        rcode_arr = []
        qtype_arr = []
        qclass_arr = []
        qname_list = []
        opcode_arr = []
        trunk_arr = []
        rclass = []
        rtype = []
        recursion_arr = []
        rttl = []
        average_resp_time = []
        for pac in arr:
            # Find nameserver
            try:
                nameserver = pac.dns.soa_mname
            except AttributeError:
                pass

            # Counting of request and response packets, their sum
            if int(pac.dns.flags_response) == 1:
                rec_count = rec_count + 1
            sum_pac = len(arr)
            ans_count = sum_pac - rec_count
            #return ans_count, sum_pac, rec_count
            #----------------------------------

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
            #return orphan_pacs                    
            #----------------------------------

            # IP-addr that DNS-server returned (type A)
            for i in arr:
                try:
                    if i.dns.a:
                        a_rec_arr.append(i)
                except AttributeError:
                    continue
            a_rec_arr = is_unique(a_rec_arr)
            #return a_rec_arr
            #-----------------------------------

            # Count Errors and their type ------
            try:
                rcode_arr.append(pac.dns.flags_rcode)
            except AttributeError:
                pass
            #-----------------------------------

            # Count query codes and their types
            qtype_arr.append(pac.dns.qry_type)
            #-----------------------------------
            
            # Count query classes and their types
            qclass_arr.append(pac.dns.qry_class)
            #------------------------------------

            # Count query names and their types
            if int(pac.dns.qry_type) == 1 or int(pac.dns.qry_type) == 28:
                if 'localdomain' not in pac.dns.qry_name:
                    qname_list.append(pac.dns.qry_name)

            #------------------------------------

            # Count opcode's
            opcode_arr.append(pac.dns.flags_opcode)
            # Count trunkated
            trunk_arr.append(pac.dns.flags_truncated)
            # Count response class, type, ttl
            try:    
                rclass.append(pac.dns.resp_type)
                rtype.append(pac.dns.resp_class)
                rttl.append(float(pac.dns.resp_ttl))
            except AttributeError:
                pass

            # Average response packet time
            try:
                average_resp_time.append(float(pac.dns.time))
            except AttributeError:
                pass
            # Is available recursion on server
            try:
                recursion_arr.append(pac.dns.flags_recavail)
            except AttributeError:
                pass
        
        rtype = Counter(rtype)
        rclass = Counter(rclass)
        rttl = mean(rttl)
        atime = mean(average_resp_time)
        qname_list = is_unique(qname_list)
        rcode_arr = Counter(rcode_arr)
        qtype_arr = Counter(qtype_arr)
        qclass_arr = Counter(qclass_arr)
        opcode_arr = Counter(opcode_arr)
        trunk_arr = Counter(trunk_arr)
        recursion_arr = Counter(recursion_arr)

        print("SERVER - " + nameserver)
        print("ans_count - " + str(ans_count))
        print("rec_count - " + str(rec_count))
        print("sum_pac - " + str(sum_pac))
        print("orphan pacs - " + str(orphan_pacs))
        print("a - " + str(a_rec_arr[0].dns.a))
        print("rcode - " + str(rcode_arr))
        print("qtype - " + str(qtype_arr))
        print("qclass - " + str(qclass_arr))
        print("qname - " + str(qname_list))
        print("opcode - " + str(opcode_arr))
        print("trunk - " + str(trunk_arr))
        print("recursion - " + str(recursion_arr))
        print("rtype - " + str(rtype))
        print("rclass - " + str(rclass))
        print("rttl - " + str(rttl))
        print("average time - " + str(atime))

        print("#--------------------------------------#")

get_dns_profile(a)