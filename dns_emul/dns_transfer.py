import dns.query
import dns.zone
import subprocess

def test_dns_trans_zone(dnsserver, domain):
    good_influence = ''
    # ask zone for domain
    # try:
    #     zone = dns.zone.from_xfr(dns.query.xfr(dnsserver, domain))
    #     # get all records in zone
    #     for name in zone.nodes.keys():
    #         good_influence = zone[name].to_text(name)
    #         # print(type(zone[name].to_text(name)))
    #         status = True
    # except Exception as e:
    #     good_influence = 'zone transfer is not available'
    #     status = False
    # return [good_influence, status]
    status = False
    subprocess.call(['./scripts/ztrans.sh',domain,dnsserver])
    with open('dns_emul/transfer_zone.txt','r') as r:
        good_influence = r.read()
        status = True
    return [good_influence,status]
# test_dns_trans_zone('nsztm1.digi.ninja.','zonetransfer.me')
