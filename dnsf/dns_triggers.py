#       0                       1           2             3         4        5                                 6               7           8       
# ['ns-1489.awsdns-58.org',     '12', 'Recursive: 6', '0.0989069', '5.0', 'fc2.com',                     'Non-Trunkated: 12', 'None', 'NoError: 6', '2023-05-24']
# ['a.root-servers.net',        '10', 'Recursive: 5', '1.08448',   '5.0', 'livedoor.localdomain',        'Non-Trunkated: 10', 'None', 'NXDomain: 5', '2023-05-24']
# ['ns1.naver.jp',              '25', 'Recursive: 12', '0.343328', '5.0', 'livedoor.com',                'Non-Trunkated: 25', 'None', 'NoError: 12', '2023-05-24']
# ['ns-1634.awsdns-12.co.uk',   '18', 'Recursive: 9', '0.278479',  '5.0', 'aajtak.com',                  'Non-Trunkated: 18', 'None', 'NoError: 9', '2023-05-24']
# ['a.root-servers.net',        '11', 'Recursive: 5', '0.471223',  '5.0', 'home.in.localdomain',         'Non-Trunkated: 11', 'None', 'NXDomain: 5', '2023-05-24']
# ['ns1.register.it',           '12', 'Recursive: 6', '0.193173',  '5.0', 'home.it',                     'Non-Trunkated: 12', 'None', 'NoError: 6', '2023-05-24']
# ['dns.nic.it',                '8',  'Recursive: 4', '0.117535',  '5.0', 'florence.it',                 'Non-Trunkated: 8',  'None', 'NoError: 4', '2023-05-24']
# ['a.root-servers.net',        '11', 'Recursive: 5', '0.251002',  '5.0', 'florence.it.localdomain',     'Non-Trunkated: 11', 'None', 'NXDomain: 5', '2023-05-24']
# ['dns.technorail.com',        '14', 'Recursive: 7', '0.672387',  '5.0', 'flora.it',                    'Non-Trunkated: 14', 'None', 'NoError: 7', '2023-05-24']

#           0                       1                           2                3              4                   5               6                   7         8        9    10    11        12        13
# ['ns-1489.awsdns-58.org',     'fc2.com',                  '52.24.98.229',     '383', 'A: 4, AAAA: 4, PTR: 4', 'IN: 12', 'SOA: 1, A: 2, PTR: 2',   'IN: 5', 'Query: 12', '6', '6', '7200', '1209600', '86400']
# ['a.root-servers.net',        'livedoor.localdomain',     '',                 '384', 'A: 4, AAAA: 6',         'IN: 10', 'SOA: 3',                 'IN: 3', 'Query: 10', '5', '5', '1800', '604800', '86400']
# ['ns1.naver.jp',              'livedoor.com',             '147.92.184.22',    '385', 'A: 13, AAAA: 12',       'IN: 25', 'SOA: 3, A: 6',           'IN: 9', 'Query: 25', '13', '12', '3566', '86400', '3600']
# ['ns-1634.awsdns-12.co.uk',   'aajtak.com',               '13.250.68.118',    '386', 'A: 8, AAAA: 10',        'IN: 18', 'A: 4, SOA: 3',           'IN: 7', 'Query: 18', '9', '9', '7200', '1209600', '86400']
# ['a.root-servers.net',        'home.in.localdomain',      '',                 '387', 'A: 5, AAAA: 6',         'IN: 11', 'SOA: 3',                 'IN: 3', 'Query: 11', '6', '5', '1800', '604800', '86400']
# ['ns1.register.it',           'home.it',                  '195.110.124.133',  '388', 'A: 4, AAAA: 4, PTR: 4', 'IN: 12', 'A: 2, SOA: 1, PTR: 2',   'IN: 5', 'Query: 12', '6', '6', '10800', '604800', '86400']
# ['dns.nic.it',                'florence.it',              '',                 '389', 'A: 4, AAAA: 4',         'IN: 8',  'SOA: 2',                 'IN: 2', 'Query: 8', '4', '4', '10800', '604800', '3600']
# ['a.root-servers.net',        'florence.it.localdomain',  '',                 '390', 'A: 5, AAAA: 6',         'IN: 11', 'SOA: 3',                 'IN: 3', 'Query: 11', '6', '5', '1800', '604800', '86400']
# ['dns.technorail.com',        'flora.it',                 '62.149.128.160',   '391', 'A: 6, AAAA: 4, PTR: 4', 'IN: 14', 'SOA: 1, A: 3, PTR: 2',   'IN: 6', 'Query: 14', '7', '7', '86400', '2592000', '3600']

# import sys
# # PROJECT_PATH = '/home/ubuntu18/diploma-1/dpl' #Для HP
# PROJECT_PATH = '/home/ubuntu18/Desktop/dpl' #Для Aquarius
# if PROJECT_PATH not in sys.path:
#     sys.path.append(PROJECT_PATH)
# from base_show.db_selector import get_srv_from_db
# from osh import reload_arr

# f_table = reload_arr(get_srv_from_db()[0]) 
# s_table = reload_arr(get_srv_from_db()[1])

def detect_bad_dname(dname):
    return True

def mark_value_ftable(table_list):
    alert = ' [!]'
    warn = ' [?]'
    for i in table_list:
        
        if int(i[1]) > 20:
            i[1] += warn
        elif int(i[1]) > 100:
            i[1] += alert
        
        if 'Autoritative' in i[2]:
            i[2] += warn
        
        if float(i[3]) > 1:
            i[3] += warn
        elif float(i[3]) > 2:
            i[3] += alert        
        
        if float(i[4]) != 5:
            i[4] += warn

        if 'Non-Trunkated' in i[6]:
            pass
        else:
            i[6] += warn

        if i[7] != 'None':
            i[7] += warn

        if 'NoError' in i[8]:
            pass
        elif 'ServFail' in i[8] or 'Refused' in i[8] or 'NotAuth' in i[8] or 'NotZone' in i[8]:
            i[8] += alert
        else:
            i[8] += warn

        #  БЛЯТЬ НЕ ЗАБУДЬ ПРОВЕРКУ ДОМЕНА
        # print(i)
    return table_list

def mark_value_stable(table_list):
    alert = ' [!]'
    warn = ' [?]'
    for i in table_list:
        if i[2] == '':
            i[2] += warn
        
        if 'IN' in i[5]:
            pass
        else:
            i[5] += warn

        if 'IN' in i[5]:
            pass
        else:
            i[7] += warn

        if 'Query' in i[8]:
            pass
        else:
            i[8] += warn

        if int(i[9]) - int(i[10]) != 0:
            i[9] += warn
            i[10] += warn
        
        if int(i[11]) < 1000:
            i[11] += warn
        elif int(i[11]) > 1800:
            i[11] += alert

        if int(i[12]) < 500000:
            i[12] += warn
        elif int(i[12]) > 604800:
            i[12] += alert

        if int(i[13]) < 86400:
            i[13] += warn
        elif int(i[13]) > 86400:
            i[13] += alert
    return table_list

