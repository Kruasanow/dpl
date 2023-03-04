import osh 
import dns_db_addiction as dnsadd

cap = osh.cap

# dns_arr = dnsadd.dns_arr
print('------------')
# print(dnsadd.arr_needed_ip(dnsadd.to_dns_arr(osh.cap),'192.168.212.2'))

a_rec_arr = []
for i in dnsadd.arr_needed_ip(dnsadd.to_dns_arr(osh.cap),'192.168.212.2'):
    try:
        if i.dns.a:
            a_rec_arr.append(i)
    except AttributeError:
        continue
print(a_rec_arr[0].dns.a, a_rec_arr[1].dns.a)