import dns.resolver
import dns.query
import dns.zone
import argparse
import re
import sys
import json
    
def verify():
    subs = []
    # Check that domain is in correct format; otherwise, produce error:
    # Thank https://stackoverflow.com/questions/8467647/python-domain-name-check-using-regex
    if re.search("^[a-zA-Z\d-]{,63}(\.[a-zA-Z\d-]{,63})*$", args.domain) == None:
        print("[-] Domain is not valid... quitting")
        sys.exit(1)
    else:
        print("[+] Domain is valid")
    # Attempt reading wordlist
    try:
        with open(args.wordlist, "r") as f:
            subs = f.read().split()
    except FileNotFoundError:
        print("[-] Wordlist not found... quitting")
        sys.exit(1)
    print("[+] Found wordlist")
    return subs

def enum(subdomains):
    scanned_subs = []
    # Remove duplicate items from records list
    args.records = list(dict.fromkeys(args.records))
    for sub in subdomains:
        results = {"Hostname": "{}.{}".format(sub, args.domain)} # Used to collect all records for subdomain
        for rcd in args.records:
            print("[*] Querying {}.{} for {} records".format(sub, args.domain, rcd))
            # Make the query and initialize the record list
            try:
                answer = dns.resolver.resolve("{}.{}".format(sub, args.domain), rcd)
            except dns.resolver.NXDOMAIN:
                print("\t[-] ERROR: Received NXDOMAIN")
            except dns.resolver.NoAnswer:
                print("\t[-] ERROR: Received NoAnswer")
            except dns.resolver.Timeout:
                print("\t[-] ERROR: Received Timeout")
            else:
                record_list = []
                # Take the answer from the query and add the addresses to the record list
                # https://www.programcreek.com/python/example/97695/dns.resolver.NXDOMAIN - referenced for the next couple lines
                for item in answer:
                    print("\t[+] Found {} record: {}".format(rcd, item.to_text()))
                    record_list.append(item.to_text())
                # Add records to results list for subdomain
                results[rcd] = record_list
        # Check for Zone Transfer if requested
        if args.transfer: # Make sure zone transfer is requested and nameservers exist in the results dictionary
            answer = zone_transfer("{}.{}".format(sub, args.domain))
            #answer = zone_transfer("zonetransfer.me") - for testing purposes
            if answer != None: # Ensuring that it does not get added to the results if it was not successful
                results["Zone Transfer"] = answer
        # Append all record query results to the scanned_subs list if there are any results gathered
        if len(results) > 1:
            scanned_subs.append(results)
    return scanned_subs
            
def zone_transfer(hostname):
    nameservers = []
    try:
        answer = dns.resolver.resolve(hostname, "NS")
    except:
        print("\t[-] An error ocurred while grabbing nameservers, likely unavailable")
    else:
        for item in answer:
            nameservers.append(item.to_text()) # Append each result to nameservers list, not entirely necessary but makes everything neater
            
        for ns in nameservers:
            print("\t[+] Attempting zone transfer at: {} with nameserver: {}".format(hostname, ns))
            try:
                z = dns.zone.from_xfr(dns.query.xfr(ns, hostname))
                names = z.nodes.keys()
                #names.sort()
                for n in names:
                    print(z[n].to_text(n))
                print("\t[+] Zone Transfer successful")
                return z.to_text()
            except dns.query.TransferError:
                print("\t[-] Zone Transfer failed")
            except ConnectionResetError:
                print("\t[-] Connection forcibly closed by remote host, zone transfer failed")

# Print results and write to file at the end
def print_results(scanned_subs):
    print("[+] Printing scanned subdomain results:")
    for res in scanned_subs:
        print(res)
    if args.output: # 
        if args.json:
            with open(args.output, "w") as f:
                json.dump(scanned_subs, f)
        else:
            with open(args.output, "w") as f:
                for result in scanned_subs:
                    for key in result.keys():
                        f.write("{}: {}\n".format(key, result[key]))
        
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="DNS enumeration tool designed for pentesting reconnaissance",
        usage="%(prog)s domain [options]",
        add_help=False)
    
    # Little control with argparse; optget may be better
    parser.add_argument("-h", "--help", action="help", help="Display this helpful bit and exit")
    
    parser.add_argument("-w", "--wordlist", required=True, dest="wordlist", help="Specify wordlist file")
    parser.add_argument("--records", required=True, dest="records", help="Query for DNS records; Options are NS, A, CNAME, and MX", choices=["NS", "A", "CNAME", "MX"], nargs="+")
    
    parser.add_argument("-z", "--zone-transfer", dest="transfer", action="store_true", help="Attempt a zone transfer on domain (Note: this may be illegal depending on your area, make sure you are authorized to perform a zone transfer on your target assets)")
    parser.add_argument("-o", "--output", dest="output", help="Specify output file")
    parser.add_argument("--json", dest="json", action="store_true", help="Output results in JSON format")
    parser.add_argument("domain", help="Hostname to run enumeration on")
    args = parser.parse_args()
    
    
# Grab subs and verify domain
subs = verify()
# Enumerate and print results
scanned_subs = enum(subs)
print_results(scanned_subs)