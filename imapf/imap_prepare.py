
import sys
PROJECT_PATH = '/home/ubuntu18/diploma-1/dpl' #Для HP
# PROJECT_PATH = '/home/ubuntu18/Desktop/dpl' #Для Aquarius
if PROJECT_PATH not in sys.path:
    sys.path.append(PROJECT_PATH)

def to_imap_arr(a):
    imap_arr = []
    for pac in a:
        if hasattr(pac,'imap'):
            imap_arr.append(pac)
    return imap_arr

# from osh import get_file, get_dname_from_db
# cap = get_file(get_dname_from_db())

def get_imap_info(cap): 
    cap = to_imap_arr(cap)

    response = [[],[]]
    response_status = [[],[]]
    response_tag = [[],[]]
    request = [[],[]]
    request_command = [[],[]]
    request_tag = [[],[]]

    for pac in cap:
        if hasattr(pac,'imap'):
            if hasattr(pac.imap,'response_arg'):
                response[0].append(pac.frame_info.number)
                response[1].append(pac.imap.response)
            if hasattr(pac.imap,'response_status'):
                response_status[0].append(pac.frame_info.number)
                response_status[1].append(pac.imap.response_status)
            if hasattr(pac.imap,'response_tag'):
                response_tag[0].append(pac.frame_info.number)
                response_tag[1].append(pac.imap.response_tag)
            if hasattr(pac.imap,'request'):
                request[0].append(pac.frame_info.number)
                request[1].append(pac.imap.request)
            if hasattr(pac.imap,'request_command'):
                request_command[0].append(pac.frame_info.number)
                request_command[1].append(pac.imap.request_command)
            if hasattr(pac.imap,'request_tag'):
                request_tag[0].append(pac.frame_info.number)
                request_tag[1].append(pac.imap.request_tag)

    return [response,response_status,response_tag,request,request_command,request_tag]
from pyshark import FileCapture
print(get_imap_info(FileCapture('dump_input/imap.pcap')))

def compare_code_imap(arr):
    out_arr = []
    from imapf.imap_codes_list import code_imap_dict
    for i in arr:
        for j in code_imap_dict:
            if i == j:
                out_arr.append(code_imap_dict[j])
    return out_arr
# print(get_imap_info(cap))
# print(compare_code_imap(get_imap_info(cap)[4]))