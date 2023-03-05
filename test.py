import osh 
import dns_db_addiction as dnsadd

cap = osh.cap

# dns_arr = dnsadd.dns_arr
print('------------')
# print(dnsadd.arr_needed_ip(dnsadd.to_dns_arr(osh.cap),'192.168.212.2'))

# a_rec_arr = []
# for i in dnsadd.arr_needed_ip(dnsadd.to_dns_arr(osh.cap),'192.168.212.2'):
#     try:
#         if i.dns.a:
#             a_rec_arr.append(i)
#     except AttributeError:
#         continue
# print(a_rec_arr)

cap = dnsadd.to_dns_arr(cap)
print(len(cap))

print(dir(cap[24].dns))

# for i in cap:
    