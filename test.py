import pyshark

cap = pyshark.FileCapture('dump_input/smtp.pcap')
# 'response', 'response_code', 'rsp', 'rsp_parameter'
for pkt in cap:
    # try:
    #     # print(pkt['smtp'].rsp_parameter)
    #     # print(pkt['smtp'].response_code)
    #     # print(pkt['smtp'].req_command)
    # except Exception:
    #     pass
    try:
        if 'UGFzc3dvcmQ6' in pkt['smtp'].rsp_parameter:
            # print('Authentication failed in packet %s' % pkt.number)
            print('xc90.websitewelcome.com closing connection %s' % pkt.number)
    except Exception:
        pass

    
