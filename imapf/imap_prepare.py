
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

from osh import get_file, get_dname_from_db
cap = get_file(get_dname_from_db())

def get_imap_info(cap): 
    cap = to_imap_arr(cap)

    response = []
    response_status = []
    response_tag = []
    request = []
    request_command = []
    request_tag = []

    for pac in cap:
        # print(pac)
        try:
            response.append(pac['imap'].response)
        except Exception:
            pass
        try:
            response_status.append(pac['imap'].response_status)
        except Exception:
            pass
        try:
            response_tag.append(pac['imap'].response_tag)
        except Exception:
            pass
        try:
            request.append(pac['imap'].request)
        except Exception:
            pass
        try:
            request_command.append(pac['imap'].request_command)
        except Exception:
            pass
        try:
            request_tag.append(pac['imap'].request_tag)
        except Exception:
            pass
    return [response,response_status,response_tag,request,request_command,request_tag]

# print(get_imap_info(cap))

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