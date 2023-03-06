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
    RCODE_list= [
                0,1,2,3,4,5,
                6,7,8,9,10,11,
                12,
                16,17,18,19,20,
                21,22,23
                ]
    RCODE_name_list=[
                    'NoError','FormErr','ServFail',
                    'NXDomain','NotImp','Refused',
                    'YXDomain','YXRRSet','NXRRSet',
                    'NotAuth','NotZone',
                    'DSOTYPENI','Unassigned','BADVERS or BADSIG',
                    'BADKEY','BADTIME',
                    'BADMODE','BADNAME','BADALG',
                    'BADTRUNC','BADCOOKIE'
                    ]
    RCODE_dict = dict(zip(RCODE_list,RCODE_name_list))

    for u_ip in dns_srv_list:
        rec_count = 0
        ans_count = 0
        un_var = []
        orphan_pacs = []
        a_rec_arr = []
        arr = arr_needed_ip(array,str(u_ip))
        rcode_arr = []
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
            for i in arr:
                rcode_arr.append(i.dns.flags_rcode)
            




get_dns_profile(a)