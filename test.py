import osh 
import dns_db_addiction as dnsadd

cap = osh.cap

dns_arr = dnsadd.dns_arr

print(dns_arr[0].ip.src)
print(dns_arr[0].ip.dst)