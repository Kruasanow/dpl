import csv

def is_ip_in_range(ip_address, ip_range):

    ip = [int(x) for x in ip_address.split('.')]
    start, end = ip_range.split('-')
    start = [int(x) for x in start.split('.')]
    end = [int(x) for x in end.split('.')]
    start_int = start[0] * 256 ** 3 + start[1] * 256 ** 2 + start[2] * 256 + start[3]
    end_int = end[0] * 256 ** 3 + end[1] * 256 ** 2 + end[2] * 256 + end[3]
    ip_int = ip[0] * 256 ** 3 + ip[1] * 256 ** 2 + ip[2] * 256 + ip[3]
    return start_int <= ip_int <= end_int


def get_geo_asn(ip):
    with open('ip_base/geo-asn-country-ipv4.csv', newline='') as csvfile:
        reader = csv.reader(csvfile, delimiter=',', quotechar='"')
        for row in reader:
            range_ip = str(row[0]+'-'+row[1])
            if is_ip_in_range(ip,range_ip):
                res = row[2]
                # print(row[2])
    return res

# print(get_geo_asn('4.4.4.4'))
# print(is_ip_in_range('192.168.3.32','192.168.1.1-192.168.4.255'))