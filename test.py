import osh 
import dns_prepare_fdb as dprep
import dns_codes_list as dcode
import whois

cap = osh.cap

# print(dir(dprep.to_dns_arr(cap)[39].dns))
# print('------------')

who = whois.whois('goal.footbal.com')
print(dir(who))
print(who)