import osh 
import dns_prepare_fdb as dprep


cap = osh.cap

# dns_arr = dprep.dns_arr
print('------------')
# print(dprep.arr_needed_ip(dprep.to_dns_arr(osh.cap),'192.168.212.2'))

# a_rec_arr = []
# for i in dprep.arr_needed_ip(dprep.to_dns_arr(osh.cap),'192.168.212.2'):
#     try:
#         if i.dns.a:
#             a_rec_arr.append(i)
#     except AttributeError:
#         continue
# print(a_rec_arr)

cap = dprep.to_dns_arr(cap)
print(len(cap))

print(dir(cap[24].dns))

# for i in cap: