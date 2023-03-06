import osh
from collections import Counter

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

# Select only unique values to list
def is_unique(arr):
    un_var = []
    for i in arr:
        if i in un_var:
            continue
        else:
            un_var.append(i)
    return un_var

# Select packets from array by IP.src
def arr_needed_ip(arr,ip):
    needed_arr = []
    for i in arr:
        if str(i.ip.src) == ip:
            needed_arr.append(i)
        else:
            continue
    return needed_arr
 
# Prepare values to create DNS-profile tables
def get_dns_profile(arr):
    array = to_dns_arr(arr)
    dns_srv_list = get_unique_dns_srv(arr)
    print("SRV -" + str(dns_srv_list))

    for u_ip in dns_srv_list:
        rec_count = 0
        ans_count = 0
        un_var = []
        orphan_pacs = []
        a_rec_arr = []
        arr = arr_needed_ip(array,str(u_ip))
        rcode_arr = []
        qtype_arr = []
        qclass_arr = []
        qname_list = []
        opcode_arr = []
        trunk_arr = []
        recursion_arr = []
        for pac in arr:
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
            rcode_arr.append(pac.dns.flags_rcode)
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

        print(ans_count)
        print(rec_count)
        print(sum_pac)
        print(orphan_pacs)
        print(a_rec_arr)
        print(rcode_arr)
        print(qtype_arr)
        print(qclass_arr)
        print(qname_list)
        print(opcode_arr)
        print(trunk_arr)
        print(recursion_arr)

get_dns_profile(a)