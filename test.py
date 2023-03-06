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

# cap = dprep.to_dns_arr(cap)
# print(len(cap))

# print(dir(cap[24].dns))

# for i in cap:

RCODE_list= [
            0,1,2,3,4,5,
            6,7,8,9,10,11,
            12,
            16,17,18,19,20,
            21,22,23
            ]
RCODE_name_list=[
                'NoError','FormErr','ServFail',
                'NXDomain','NotImp','Refused',
                'YXDomain','YXRRSet','NXRRSet',
                'NotAuth','NotZone',
                'DSOTYPENI','Unassigned','BADVERS or BADSIG',
                'BADKEY','BADTIME',
                'BADMODE','BADNAME','BADALG',
                'BADTRUNC','BADCOOKIE'
                ]
RCODE_dict = dict(zip(RCODE_list,RCODE_name_list))
print(list(RCODE_dict.keys()))
