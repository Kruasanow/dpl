import dns.query
import dns.zone

def test_dns_trans_zone(dnsserver, domain):
    # ask zone for domain
    try:
        zone = dns.zone.from_xfr(dns.query.xfr(dnsserver, domain))
        # get all records in zone
        for name in zone.nodes.keys():
            good_influence = zone[name].to_text(name)
            # print(type(zone[name].to_text(name)))
    except Exception as e:
        good_influence = 'zone transfer is not available'
    return good_influence

# print(test_dns_trans_zone('ns1.vkontakte.com','vk.com'))
