import osh 
import dns_prepare_fdb as dprep


cap = osh.cap

# dns_arr = dprep.dns_arr
print('------------')


d = dprep.arr_needed_domain(dprep.to_dns_arr(cap),'vk.com') 
print(d)

cap = dprep.to_dns_arr(cap)

def compare_name_src(cap):
    name_arr = []
    srv_arr = []
    arr_dump = []
    u_dump = []
    for i in cap:
        if hasattr(i.dns, 'soa_mname') == True:
            arr_dump.append(i)
            print(i.dns.soa_mname)
    for i in arr_dump:
        if i.dns.soa_mname in u_dump:
            continue
        else:
            u_dump.append(i.dns.soa_mname)
    return(u_dump)
print(compare_name_src(cap))
    # for i in cap:
    #     try: