import db_do.conn_db as cdb
import osh
from dnsf.dns_prepare_fdb import to_dns_arr

a = osh.cap

def add_dump(dname):
    print('[*]dns_db_addiction.py: dump name - '+str(dname))
    conn = cdb.get_db_connection()
    cur = conn.cursor()
    cur.execute('INSERT INTO dump_list (dname) VALUES (%s)',[dname])
    conn.commit()
    cur.close()
    conn.close()

def init_db():
    count_error = 0
    conn = cdb.get_db_connection() 
    cur = conn.cursor()
    bad = []
    for i in to_dns_arr(osh.cap):
        if int(i.dns.flags_response) == 0:
                cur.execute('INSERT INTO dns_flags ('
                            'ip_src, ip_dst, id_pac,'
                            'qry_class, qry_name,' 'qry_type,'
                            'flags_z, flags_truncated, flags_response,'
                            'flags_recdesired, flags_opcode, count_queries,'
                            'count_labels, count_auth_rr, count_answers,'
                            'count_add_rr)'
                    'VALUES ('
                            '%s, %s, %s, %s,'
                            '%s, %s, %s, %s,'
                            '%s, %s, %s, %s,'
                            '%s, %s, %s, %s)',
                            (
                str(i.ip.src),
                str(i.ip.dst),
                str(i.dns.id),
                str(i.dns.qry_class),
                str(i.dns.qry_name),
                str(i.dns.qry_type),
                int(i.dns.flags_z),
                int(i.dns.flags_truncated),
                int(i.dns.flags_response),
                int(i.dns.flags_recdesired),
                int(i.dns.flags_opcode),
                str(i.dns.count_queries),
                str(i.dns.count_labels),
                str(i.dns.count_auth_rr),
                str(i.dns.count_answers),
                str(i.dns.count_add_rr),
                )
                )
        elif int(i.dns.flags_response) == 1:
            try:
                cur.execute('INSERT INTO dns_flags ('
                            'ip_src, ip_dst,'
                            'id_pac, qry_class, qry_name,'
                            'qry_type, flags_z, flags_truncated,'
                            'flags_response, flags_recdesired, flags_opcode,'
                            'count_queries, count_labels, count_auth_rr,'
                            'count_answers, count_add_rr, flags_authenticated,'
                            'flags_authoritative, flags_rcode, flags_recavail,'
                            'resp_class, resp_ttl, resp_type,'
                            'response_to, a_return_rec, time,'
                            'soa_expire_limit, soa_mininum_ttl, soa_mname,'
                            'soa_refresh_interval, soa_retry_interval, soa_rname,'
                            'soa_serial_number)'
                    'VALUES ('
                            '%s, %s, %s, %s,'
                            '%s, %s, %s, %s,'
                            '%s, %s, %s, %s,'
                            '%s, %s, %s, %s,'
                            '%s, %s, %s, %s,'
                            '%s, %s, %s, %s,'
                            '%s, %s, %s, %s,'
                            '%s, %s, %s, %s,'
                            '%s)',
                            (
                str(i.ip.src if hasattr(i.ip, "src") else ""),
                str(i.ip.dst if hasattr(i.ip, "dst") else ""),
                str(i.dns.id if hasattr(i.dns, "id") else ""),
                str(i.dns.qry_class if hasattr(i.dns, "qry_class") else ""),
                str(i.dns.qry_name if hasattr(i.dns, "qry_name") else ""),
                str(i.dns.qry_type if hasattr(i.dns, "qry_type") else ""),
                str(i.dns.flags_z if hasattr(i.dns, "flags_z") else ""),
                str(i.dns.flags_truncated if hasattr(i.dns, "flags_truncated") else ""),
                str(i.dns.flags_response if hasattr(i.dns, "flags_response") else ""),
                str(i.dns.flags_recdesired if hasattr(i.dns, "flags_recdesired") else ""),
                str(i.dns.flags_opcode if hasattr(i.dns, "flags_opcode") else ""),
                str(i.dns.count_queries if hasattr(i.dns, "count_queries") else ""),
                str(i.dns.count_labels if hasattr(i.dns, "count_labels") else ""),
                str(i.dns.count_auth_rr if hasattr(i.dns, "count_auth_rr") else ""),
                str(i.dns.count_answers if hasattr(i.dns, "count_answers") else ""),
                str(i.dns.count_add_rr if hasattr(i.dns, "count_add_rr") else ""),
                str(i.dns.flags_authenticated if hasattr(i.dns, "flags_authenticated") else ""),
                str(i.dns.flags_authoritative if hasattr(i.dns, "flags_authoritative") else ""),
                str(i.dns.flags_rcode if hasattr(i.dns, "flags_rcode") else ""),
                str(i.dns.flags_recavail if hasattr(i.dns, "flags_recavail") else ""),
                str(i.dns.resp_class if hasattr(i.dns, "resp_class") else ""),
                str(i.dns.resp_ttl if hasattr(i.dns, "resp_ttl") else ""),
                str(i.dns.resp_type if hasattr(i.dns, "resp_type") else ""),
                str(i.dns.response_to if hasattr(i.dns, "response_to") else ""),
                str(i.dns.a if hasattr(i.dns, "a") else ""),
                str(i.dns.time if hasattr(i.dns, "time") else ""),
                str(i.dns.soa_expire_limit if hasattr(i.dns, "soa_expire_limit") else ""),                                
                str(i.dns.soa_mininum_ttl if hasattr(i.dns, "soa_mininum_ttl") else ""),
                str(i.dns.soa_mname if hasattr(i.dns, "soa_mname") else ""),
                str(i.dns.soa_refresh_interval if hasattr(i.dns, "soa_refresh_interval") else ""),
                str(i.dns.soa_retry_interval if hasattr(i.dns, "soa_retry_interval") else ""),  
                str(i.dns.soa_rname if hasattr(i.dns, "soa_rname") else ""), 
                str(i.dns.soa_serial_number if hasattr(i.dns, "soa_serial_number") else ""),
                )
                )
                # print('[*]dns_db_addiction.py: data inserted')
            except AttributeError:
                print('[*]dns_db_addiction.py: something WRONG - ' + str(i.dns.id) + " " +str(i.dns.flags_response))
                bad.append(i)
                count_error = count_error + 1
                continue
    print('[*]dns_db_addiction.py: bad array - '+str(bad))

    conn.commit()
    cur.close()
    conn.close()