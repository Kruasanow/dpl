import osh

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

    for u_ip in dns_srv_list:
        rec_count = 0
        ans_count = 0
        un_var = []
        orphan_pacs = []
        a_rec_arr = []
        for pac in arr_needed_ip(array,str(u_ip)):
            # Counting of request and response packets, their sum
            if int(pac.dns.flags_response) == 1:
                rec_count = rec_count + 1
            sum_pac = len(array)
            ans_count = sum_pac - rec_count
            #return ans_count, sum_pac, rec_count
            #----------------------------------

            # Find orphaned packets ----------
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
            #return orphan_pacs                    
            #----------------------------------

            # IP-addr that DNS-server returned (type A)
            one_srv_resp = arr_needed_ip(array,str(u_ip))
            for i in one_srv_resp:
                try:
                    if i.dns.a:
                        a_rec_arr.append(i)
                except AttributeError:
                    continue
            a_rec_arr = is_unique(a_rec_arr)
            #return a_rec_arr
            #-----------------------------------

    

get_dns_profile(a)