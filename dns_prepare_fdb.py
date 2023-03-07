import osh
from collections import Counter
import ipaddress

a = osh.cap

# Conver Main-dump to DNS-array
def to_dns_arr(a):
    dns_arr = []
    for pac in a:
        if pac.highest_layer == 'DNS':
            dns_arr.append(pac)
    return dns_arr

# Select only unique dns server's IP as list
# do not need "to_dns_arr"
# def get_unique_dns_srv(arr):
#     unique_srv = []
#     arr = to_dns_arr(arr)
#     for i in arr:
#         if i.ip.src in unique_srv:
#             continue
#         else:
#             if int(i.dns.flags_response) == 1:
#                 unique_srv.append(i.ip.src)
#             else:
#                 continue
#     return unique_srv

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
    # for name in arr:
    #     if name.dns.qry_name.find("in-addr.arpa") != -1:
    #         arr.remove(name)
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
# print(get_dump_by_service(a,'binance.ae'))

# Prepare values to create DNS-profile tables
def get_dns_profile(arr):
    array = to_dns_arr(arr)
    dns_srv_list = get_unique_dns_srv(array)
    dns_name_list = get_unique_dns_domain(array)

    # print("Domain names -" + str(list(compare_name_src(array).keys())))
    # print("SRC -" + str(list(compare_name_src(array).values())))

    for srv in list(compare_name_src(array).values()):
        rec_count = 0
        ans_count = 0
        un_var = []
        orphan_pacs = []
        a_rec_arr = []
        arr = arr_needed_dns_srv(array,str(srv))
        rcode_arr = []
        qtype_arr = []
        qclass_arr = []
        qname_list = []
        opcode_arr = []
        trunk_arr = []
        recursion_arr = []
        for pac in array:
            # Counting of request and response packets, their sum
            if int(pac.dns.flags_response) == 1:
                rec_count = rec_count + 1
            sum_pac = len(array)
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
            #------------------------------------

            # Count trunkated
            trunk_arr.append(pac.dns.flags_truncated)

            # Is available recursion on server
            try:
                recursion_arr.append(pac.dns.flags_recavail)
            except AttributeError:
                pass
        qname_list = is_unique(qname_list)
        rcode_arr = Counter(rcode_arr)
        qtype_arr = Counter(qtype_arr)
        qclass_arr = Counter(qclass_arr)
        opcode_arr = Counter(opcode_arr)
        trunk_arr = Counter(trunk_arr)
        recursion_arr = Counter(recursion_arr)

        # print("SERVER - " + str(qname))
        # print(ans_count)
        # print(rec_count)
        # print(sum_pac)
        # print(orphan_pacs)
        # print(a_rec_arr)
        # print(rcode_arr)
        # print(qtype_arr)
        # print(qclass_arr)
        # print(qname_list)
        # print(opcode_arr)
        # print(trunk_arr)
        # print(recursion_arr)
        print("#--------------------------------------#")

get_dns_profile(a)