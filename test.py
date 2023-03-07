import osh 
import dns_prepare_fdb as dprep


cap = osh.cap

# dns_arr = dprep.dns_arr
print('------------')


d = dprep.arr_needed_domain(dprep.to_dns_arr(cap),'vk.com') 
print(d)