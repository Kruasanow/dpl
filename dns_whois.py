import osh 
import dns_prepare_fdb as dprep
import dns_codes_list as dcode
import whois

cap = osh.cap

who = whois.whois('visitnorway.com')
print(who)