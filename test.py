import osh 
import dns_prepare_fdb as dprep
import dns_codes_list as dcode

cap = osh.cap

print(dir(dprep.to_dns_arr(cap)[39].dns))
# dns_arr = dprep.dns_arr
print('------------')


#d = dprep.get_dump_by_service(dprep.to_dns_arr(cap),'vk.com') 
# print(d)

#dict_a = {1: 2, 28: 2, 12: 2}
#dict_a = str(dict_a)
#print(str(dict_a))
#print(dict(dict_a).items())
