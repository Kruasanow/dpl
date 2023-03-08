import osh 
import dns_prepare_fdb as dprep
import dns_codes_list as dcode

cap = osh.cap

# dns_arr = dprep.dns_arr
print('------------')


d = dprep.get_dump_by_service(dprep.to_dns_arr(cap),'vk.com') 
print(d)

cap = dprep.to_dns_arr(cap)

dict_a = {1: 2, 28: 2, 12: 2}
dict_b = dcode.RR_types_dict
# print(dict_a)
print(dict_b)

def swap_dict_values(dict_a,dict_b):
    dict_a = dict(dict_a)
    swaped_dict = {}
    print(dict_a)
    for key_a,value_a in dict_a.items():
        for key_b,value_b in dict_b.items():
            if key_a == key_b:
                swaped_dict[value_b] = value_a
    return swaped_dict
print(swap_dict_values(dict_a,dict_b))