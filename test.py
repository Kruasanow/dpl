import pyshark

cap = pyshark.FileCapture('dump_input/imap.pcap')
# 'response', 'response_status', 'response_tag'
# 'request', 'request_command', 'request_tag'
for pac in cap:
    try:
        print(pac['imap'].request_command)
        print('---------')
        # print(pkt['smtp'].response_code)
        # print(pkt['smtp'].req_command)
    except Exception:
        pass


    
