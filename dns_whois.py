import whois

who_dict = {}
res_arr = []
good_arr = ['vk.com','lesta.ru','ucoz.com','cars.io']
for i in good_arr:
    who = whois.whois(i)
    print(who)
    if who.country != None:
        res_arr.append(who.country)
        if who.registrant_country != None:
            res_arr.append(who.registrant_country)
    else:
        continue
print(res_arr)

res_arr_once = [3]*len(res_arr)
print(res_arr_once)

final_dict = dict(zip(res_arr,res_arr_once))

print(final_dict)
