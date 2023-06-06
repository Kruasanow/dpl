import whois
import db_do.conn_db as cdb
from osh import reload_list_by_who

def get_qname_list():
    try:
        conn = cdb.get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT qname FROM dns_srv_profile;')
        case1 = cur.fetchall()
        print('[*]dns_whois.py: base selected - ' + str(case1[-1]))
        cur.close()
        conn.close()
    except Exception:
        print('[*]dns_whois.py: error exists!')

    qname_arr = []
    ldomain = 'localdomain'
    for i in case1:
        if ldomain in str(i):
            continue
        qname_arr.append(str(i).translate({
                                    ord("'"): None, 
                                    ord("("): None,
                                    ord(")"): None,
                                    ord(","): None,
                                    ord("}"): None,
                                    ord("{"): None
                                    }))
    return qname_arr

def do_whois(good_arr):
    res_arr = []
    who_list_json = []

    print(f'[*]dns_whois.py:{good_arr} ')
    for i in good_arr:
        who = whois.whois(i)
        who_list_json.append(who)
        print(who)
        print('-----------')

        if who.country != None:
            res_arr.append(who.country)
            continue
        if who.registrant_country != None:
            res_arr.append(who.registrant_country)
            continue
        if who.country == 'UK':
            res_arr.append('GB')
            continue
        if who.registrant_country == 'UK':
            res_arr.append('GB')
            continue

    res_arr_once = [2]*len(res_arr)
    final_dict = dict(zip(res_arr,res_arr_once))
    return [final_dict, who_list_json]

def get_items_from_who(arr):

    country       = []
    state         = []
    city          = []
    address       = []
    org           = []
    emails        = []
    name_servers  = []
    creation_date = []
    updated_date  = []
    registrar     = []
    domain_name   = []

    for i in arr:

        try:
            country.append(reload_list_by_who( i.country))
        except Exception:
            country.append("")

        try:
            state.append(reload_list_by_who(i.state))
        except Exception:
            state.append("") 

        try:
            city.append(reload_list_by_who(i.city))
        except Exception:
            city.append("")

        try:
            address.append(reload_list_by_who(i.address))
        except Exception:
            address.append("") 

        try:
            org.append(reload_list_by_who(i.org))
        except Exception:
            org.append("") 

        try:
            emails.append(reload_list_by_who(i.emails))
        except Exception:
            emails.append("") 

        try:
            name_servers.append(reload_list_by_who(i.name_servers))
        except Exception:
            name_servers.append("") 

        try:
            creation_date.append(reload_list_by_who(i.creation_date))
        except Exception:
            creation_date.append("") 

        try:
            updated_date.append(reload_list_by_who(i.updated_date))
        except Exception:
            updated_date.append("") 

        try:
            registrar.append(reload_list_by_who(i.registrar))
        except Exception:
            registrar.append("") 

        try:
            domain_name.append(reload_list_by_who(i.domain_name))
        except Exception:
            domain_name.append("") 

    return [
            country, state, city,
            address, org, emails,
            name_servers, creation_date,
            updated_date, registrar,
            domain_name
            ]
# print(do_whois(['vk.com','ya.ru']))

def transponate_arr(arr):
    zarr = zip(*arr)
    tarr = [list(row) for row in zarr]
    return tarr


import datetime
kostil = [{'CA': 2, 'JP': 2, 'IN': 2}, 
            [{'domain_name': 'FC2.COM', 
            'registrar': 'TUCOWS, INC.', 
            'whois_server': 'whois.tucows.com', 
            'referral_url': None, 
            'updated_date': [datetime.datetime(2019, 1, 23, 10, 2, 30), datetime.datetime(2020, 5, 27, 18, 4, 50)], 
            'creation_date': datetime.datetime(1999, 5, 20, 3, 6), 
            'expiration_date': datetime.datetime(2028, 5, 20, 3, 6, 36), 
            'name_servers': 
                    ['NS-1489.AWSDNS-58.ORG', 
                    'NS-1834.AWSDNS-37.CO.UK', 
                    'NS-214.AWSDNS-26.COM', 
                    'NS-616.AWSDNS-13.NET', 
                    'ns-214.awsdns-26.com', 
                    'ns-616.awsdns-13.net', 
                    'ns-1834.awsdns-37.co.uk', 
                    'ns-1489.awsdns-58.org'], 
            'status': 
                    ['clientTransferProhibited https://icann.org/epp#clientTransferProhibited', 
                    'clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited'], 
            'emails': 
                    ['domainabuse@tucows.com', 
                    'fc2.com@contactprivacy.com'], 
            'dnssec': 'unsigned', 
            'name': 'Contact Privacy Inc. Customer 014173950', 
            'org': 'Contact Privacy Inc. Customer 014173950', 
            'address': '96 Mowat Ave', 
            'city': 'Toronto', 
            'state': 'ON', 
            'registrant_postal_code': 
            'M6K 3M1', 'country': 'CA'}, 
            
            {'domain_name': None, 
            'registrar': None, 
            'whois_server': None, 
            'referral_url': None, 
            'updated_date': None, 
            'creation_date': None, 
            'expiration_date': None, 
            'name_servers': None, 
            'status': None, 
            'emails': None, 
            'dnssec': None, 
            'name': None, 
            'org': None, 
            'address': None, 
            'city': None, 
            'state': None, 
            'registrant_postal_code': None, 
            'country': None}, 
            
            {'domain_name': 'LIVEDOOR.COM', 
            'registrar': 'Japan Registry Services Co.,Ltd.(JPRS)', 
            'whois_server': 'whois.jprs.jp', 
            'referral_url': None, 
            'updated_date': datetime.datetime(2023, 1, 24, 5, 23, 16), 
            'creation_date': datetime.datetime(1999, 10, 1, 3, 15, 42), 
            'expiration_date': datetime.datetime(2024, 12, 22, 21, 16, 17), 
            'name_servers': 
                    ['ADNS1.NAVER.COM', 
                    'ADNS2.NAVER.COM', 
                    'NS1.NAVER.JP', 
                    'NS2.NAVER.JP'], 
            'status': 
                    ['clientTransferProhibited https://icann.org/epp#clientTransferProhibited', 
                    'clientTransferProhibited  https://icann.org/epp#clientTransferProhibited'], 
            'emails': 
                    ['gtld-abuse@jprs.jp', 
                    'dl_livedoor_domain@livedoor.co.jp'], 
            'dnssec': 'unsigned', 
            'name': 'livedoor Co., Ltd.', 
            'org': None, 
            'address': 'Kudan-kita-1-8-10', 
            'city': 'Chiyoda-ku', 
            'state': 'Tokyo', 
            'registrant_postal_code': '102-0073', 
            'country': 'JP'}, 
            
            
            {'domain_name': 'AAJTAK.COM', 
            'registrar': 'Mps Infotecnics Limited', 
            'whois_server': 'whois.signdomains.com', 
            'referral_url': None, 
            'updated_date': 
                    [datetime.datetime(2018, 7, 25, 8, 59, 14), 
                    datetime.datetime(2023, 5, 31, 19, 45, 38)], 
            'creation_date': datetime.datetime(1996, 8, 8, 4, 0), 
            'expiration_date': datetime.datetime(2027, 8, 7, 4, 0), 
            'name_servers': 
                    ['NS-1071.AWSDNS-05.ORG', 
                    'NS-1634.AWSDNS-12.CO.UK', 
                    'NS-314.AWSDNS-39.COM', 
                    'NS-836.AWSDNS-40.NET', 
                    'ns-1071.awsdns-05.org', 
                    'ns-1634.awsdns-12.co.uk', 
                    'ns-314.awsdns-39.com', 
                    'ns-836.awsdns-40.net'], 
            'status': 'clientTransferProhibited https://icann.org/epp#clientTransferProhibited', 
            'emails': 
                    ['tech.support@intoday.com', 
                    'registration@signdomains.com'], 
            'dnssec': 
                    ['unsigned', 'Unsigned'], 
            'name': 'Dinesh Bhatia', 
            'org': 'TV TODAY NETWORK LIMITED', 
            'address': 'K-9 Connaught Circus Connaught place', 
            'city': 'New Delhi', 
            'state': 'Delhi', 
            'registrant_postal_code': '110001', 
            'country': 'IN'}, 
            
            {'domain_name': None, 
            'registrar': None, 
            'whois_server': None, 
            'referral_url': None, 
            'updated_date': None, 
            'creation_date': None, 
            'expiration_date': None, 
            'name_servers': None, 'status': None, 'emails': None, 'dnssec': None, 'name': None, 'org': None, 'address': None, 'city': None, 'state': None, 'registrant_postal_code': None, 'country': None}, {'domain_name': 'home.it', 'creation_date': datetime.datetime(2006, 1, 23, 0, 0), 'updated_date': datetime.datetime(2022, 7, 16, 1, 19, 53), 'expiration_date': datetime.datetime(2023, 7, 16, 0, 0), 'status': 'ok', 'name_servers': 'ns1.register.it\n  ns2.register.it', 'registrant_organization': 'hidden', 'registrant_address': 'Via Zanchi 22', 'admin_address': 'Via Zanchi 22', 'admin_organization': 'hidden', 'admin_name': 'hidden', 'tech_address': 'Via Zanchi 22', 'tech_organization': 'Register SpA', 'tech_name': 'Technical Support', 'registrar_address': None, 'registrar': 'Register S.p.a.', 'registrar_name': 'REGISTER-REG'}, {'domain_name': 'florence.it', 'creation_date': None, 'updated_date': None, 'expiration_date': None, 'status': 'UNASSIGNABLE', 'name_servers': None, 'registrant_organization': None, 'registrant_address': None, 'admin_address': None, 'admin_organization': None, 'admin_name': None, 'tech_address': None, 'tech_organization': None, 'tech_name': None, 'registrar_address': None, 'registrar': None, 'registrar_name': None}, {'domain_name': None, 'registrar': None, 'whois_server': None, 'referral_url': None, 'updated_date': None, 'creation_date': None, 'expiration_date': None, 'name_servers': None, 'status': None, 'emails': None, 'dnssec': None, 'name': None, 'org': None, 'address': None, 'city': None, 'state': None, 'registrant_postal_code': None, 'country': None}, {'domain_name': 'flora.it', 'creation_date': datetime.datetime(2000, 2, 1, 0, 0), 'updated_date': datetime.datetime(2023, 4, 2, 0, 57, 41), 'expiration_date': datetime.datetime(2024, 3, 17, 0, 0), 'status': 'ok', 'name_servers': 'dns.technorail.com\n  dns2.technorail.com\n  dns3.arubadns.net\n  dns4.arubadns.cz', 'registrant_organization': 'FAEDA SPA', 'registrant_address': 'VIA ROGGIA DI MEZZO, 53', 'admin_address': "VIA DUCA D'AOSTA, 22", 'admin_organization': 'FAEDA SPA', 'admin_name': 'ALBERTO CANEVA', 'tech_address': "VIA DUCA D'AOSTA, 22", 'tech_organization': 'FAEDA SPA', 'tech_name': 'ALBERTO CANEVA', 'registrar_address': None, 'registrar': 'Aruba s.p.a.', 'registrar_name': 'ARUBA-REG'}]]
