import whois
from dnsf.dns_whois import get_qname_list, do_whois, get_items_from_who, transponate_arr

# w = transponate_arr(get_items_from_who())

a = [
 'fc2.com',
 'livedoor.localdomain',
 'livedoor.com',
 'aajtak.com',
 'home.in.localdomain',
 'home.it',
 'florence.it',
 'florence.it.localdomain',
 'flora.it']

print(do_whois(a))

