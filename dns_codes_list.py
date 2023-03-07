

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
RR_types_dict = dict(zip(RR_types_code,RR_types_name))

RR_classes_code = [
                '0x0000','0x0001','0x0002',
                '0x0003','0x0004','0x00FE',
                '0x00FF'
                    ]           

RR_classes_name = [
                'IN','Reserved','Unassigned',
                'CH','HS','QCLASS NONE','QCLASS ANY'
                    ]
RR_classes_dict = dict(zip(RR_classes_code,RR_classes_name))