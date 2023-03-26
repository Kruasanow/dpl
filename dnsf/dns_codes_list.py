

RCODE_list =    [
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
RR_types_code = [
                0,1,2,3,4,5,6,10,
                12,13,14,15,16,17,
                24,25,28,29,30,33
                ]
RR_types_name = [
                'Reserved','A','NS','MD',
                'MF','CNAME','SOA','NULL',
                'PTR','HINFO','MINFO','MX',
                'TXT','RP','SIG','KEY',
                'AAAA','LOC','NXT','SRV'
                ]
RR_classes_code=[
                '0x00000000','0x00000001','0x00000002',
                '0x00000003','0x00000004','0x000000FE',
                '0x000000FF'
                ]           
RR_classes_name=[
                'Reserved','IN','Unassigned',
                'CH','HS','QCLASS NONE','QCLASS ANY'
                ]
Opcode_code =   [
                0,1,2,3,4,5,6,7
                ]
Opcode_name =   [
                'Query','IQuery (Inverse Query, OBSOLETE)','Status',
                'Unassigned','Notify','Update',
                'DNS Stateful Operations (DSO)','Unassigned'
                ]
to_remove =     ['Reserved', 'MD', 'MF',
                'NULL', 'HINFO', 'MINFO',
                'RP','SIG','KEY','LOC','NXT'
                ]

def delete_bad_qtype():
    good_list = RR_types_name
    for i in to_remove:
        try:
            good_list.remove(i)
        except ValueError:
            continue 
    return good_list

# print(delete_bad_qtype())

Trunkated_pac = {1:'Trunkated', 0:'Non-Trunkated'}
Recursive_pac = {1:'Recursive', 0:'Autoritative'}
RR_types_dict = dict(zip(RR_types_code,RR_types_name))
RR_classes_dict = dict(zip(RR_classes_code,RR_classes_name))
RCODE_dict = dict(zip(RCODE_list,RCODE_name_list))
OPCODE_dict = dict(zip(Opcode_code,Opcode_name))
