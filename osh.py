import pyshark

cap = pyshark.FileCapture('dump_input/wsh_dump.pcapng')

def packet_counter(protocolName,cap):
    counter = 0
    for pac in cap:
        if pac.highest_layer == protocolName :
            counter=counter+1
    return counter

