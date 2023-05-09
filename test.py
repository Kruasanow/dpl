import pyshark

cap = pyshark.FileCapture('dump_input/pop-normal.pcapng')
# 'response_description', 'response_indicator', 'response_data''
# ' 'request_command' 'request_parameter'
for pac in cap:
    try:
        if hasattr(pac,'pop'):
            print(pac.pop.request_parameter)
            # print(pac.frame_info.number)
            print('---------')
    except Exception:
        pass


    
