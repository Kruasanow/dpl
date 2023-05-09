from pyshark import FileCapture

import sys
PROJECT_PATH = '/home/ubuntu18/diploma-1/dpl' #Для HP
# PROJECT_PATH = '/home/ubuntu18/Desktop/dpl' #Для Aquarius
if PROJECT_PATH not in sys.path:
    sys.path.append(PROJECT_PATH)

def to_pop_arr(a):
    pop_arr = []
    for pac in a:
        if hasattr(pac,'pop'):
            pop_arr.append(pac)
        
    return pop_arr
# print(to_pop_arr(FileCapture('dump_input/pop-normal.pcapng')))
# 'response_description', 'response_indicator', 'response_data''
# ' 'request_command' 'request_parameter'

def get_pop_info(cap): 
    cap = to_pop_arr(cap)

    request_command = [[],[]]
    request_parameter = [[],[]]
    response_indicator = [[],[]]
    response_description = [[],[]]
    response_data = [[],[]]

    for pac in cap:
        if hasattr(pac,'pop'):
            if hasattr(pac.pop,'request_command'):
                request_command[0].append(pac.frame_info.number)
                request_command[1].append(pac.pop.request_command)
            if hasattr(pac.pop,'request_parameter'):
                request_parameter[0].append(pac.frame_info.number)
                request_parameter[1].append(pac.pop.request_parameter)
            if hasattr(pac.pop,'response_indicator'):
                response_indicator[0].append(pac.frame_info.number)
                response_indicator[1].append(pac.pop.response_indicator)
            if hasattr(pac.pop,'response_description'):
                response_description[0].append(pac.frame_info.number)
                response_description[1].append(pac.pop.response_description)
            if hasattr(pac.pop,'response_data'):
                response_data[0].append(pac.frame_info.number)
                response_data[1].append(pac.pop.response_data)
            # except Exception:
                # print(f"[*]pop_prepare.py: exception works at {pac.frame_info.number}")

    return [request_command,request_parameter,response_description,response_indicator,response_data]

print(get_pop_info(FileCapture('dump_input/pop-normal.pcapng')))

def compare_code_pop(arr):
    out_arr = []
    from popf.pop_codes_list import code_pop_dict
    for i in arr:
        for j in code_pop_dict:
            if i == j:
                out_arr.append(code_pop_dict[j])
    return out_arr
# print(get_pop_info(cap))
# print(compare_code_pop(get_pop_info(cap)[4]))