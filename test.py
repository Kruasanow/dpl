import pyshark

cap = pyshark.FileCapture('dump_input/imap.pcap')
# 'response_description', 'response_indicator', 'response_data''
# ' 'request_command' 'request_parameter'
for pac in cap:
    try:
        if hasattr(pac,'imap'):
            print(pac.imap.response_tag)
            print(pac.frame_info.number)
            print('---------')
    except Exception:
        pass


    
