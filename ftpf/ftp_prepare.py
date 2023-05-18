

def code_list_compare(arr):
    from ftpf.ftp_codes import code_dict
    good_list = []
    for i in arr:
        for j in code_dict:
            if i == j:
                good_list.append(code_dict[j])
    return good_list

def code_list_compare2(arr): # блять я знаю что 2 раза одна и та же функция но ебаный рот если я ее сейчас поменяю может отъебнуть в любой точке проги
    from ftpf.ftp_codes import code_ans_dict
    good_list = []
    for i in arr:
        for j in code_ans_dict:
            if i == j:
                good_list.append(code_ans_dict[j])
    return good_list
# print(code_list_compare(arr))

def select_ftp_get_arg(cap):
    
    ftp_arr          = []
    response_arg_arr = [[],[]]
    request_arg_arr  = [[],[]]
    command_arr      = [[],[]]
    response_code    = [[],[]]

    for pac in cap:
        if hasattr(pac,'ftp'):
            ftp_arr.append(pac)

            if hasattr(pac.ftp,'response_arg'):
                response_arg_arr[0].append(pac.frame_info.number)
                response_arg_arr[1].append(pac.ftp.response_arg)
            if hasattr(pac.ftp,'request_arg'):
                request_arg_arr[0].append(pac.frame_info.number)
                request_arg_arr[1].append(pac.ftp.request_arg)
            if hasattr(pac.ftp,'request_command'):
                command_arr[0].append(pac.frame_info.number)
                command_arr[1].append(pac.ftp.request_command)
            if hasattr(pac.ftp,'response_code'):
                response_code[0].append(pac.frame_info.number)
                response_code[1].append(pac.ftp.response_code)
            else:
                pass
    description_list = code_list_compare(command_arr[1])
    description_list2 = code_list_compare2(response_code[1])

    return [ftp_arr, response_arg_arr, request_arg_arr, command_arr,description_list,response_code,description_list2]
import subprocess 
from pyshark import FileCapture


def to_ftp_arr(a):
    ftp_arr = []
    for pac in a:
        if hasattr(pac,'ftp'):
            ftp_arr.append(pac)
    return ftp_arr

# subprocess.call('scripts/sftp_decript.sh')

import sys
# PROJECT_PATH = '/home/ubuntu18/diploma-1/dpl' #Для HP
PROJECT_PATH = '/home/ubuntu18/Desktop/dpl' #Для Aquarius
if PROJECT_PATH not in sys.path:
    sys.path.append(PROJECT_PATH)
# print(select_ftp_get_arg(FileCapture('dump_input/ftp.pcapng'))[6])
from osh import get_file, get_dname_from_db

def detect_ftp_anomaly(cap):
    from collections import Counter
    
    window_sizes = set()
    command_counter = []

    cap = to_ftp_arr(cap)
    # print(len(cap))
    general_out = {
                'detector_brute':[False,''],
                'detector_secureport':[False,''],
                'detect_duplicate_acknowledgment':[False,[]],
                'detect_retransmission':[False,[]],
                'detect_encrypted_connection':[False,[]],
                'detect_conf_troubles':[False,[]],
                'detect_window_size':[False,[]]
                }

    for pac in cap:
        # print(str(pac))
        try:
            command_counter.append(pac.ftp.request_command)
        except Exception:
            pass
        counter = Counter(command_counter)
        count_user = counter['USER']
        count_pass = counter['PASS']
        # count_port = counter['PORT']
        count_pasv = counter['PASV']
        if count_pasv > 2:
            general_out['detector_secureport'][0] = True
            general_out['detector_secureport'][1] = f'Команды FTP поиска порта: активные - {count_pass}, пассивные - {count_pasv}'
        if count_user > 3 or count_pass > 3:
            general_out['detector_brute'][0] = True
            general_out['detector_brute'][1] = f'Попыток авторизации: login - {count_user}, password - {count_pass}'
        if 'tcp.analysis.retransmission' in str(cap):
            general_out['detect_retransmission'][0] = True
            general_out['detect_retransmission'][1].append(str(pac))

        if 'tcp.analysis.duplicate_acknowledgment' in str(cap):
            general_out['detect_duplicate_acknowledgment'][0] = True  
            general_out['detect_duplicate_acknowledgment'][1].append(str(pac))
        try:
            if 'STOR' in pac.ftp.command or 'RETR' in pac.ftp.command: #НАДО ПРОВЕРИТЬ - КАКАЯ-ТО ХУЙНЯ
                if pac.ftp_data and 'USER' not in pac.ftp.command and 'PASS' not in pac.ftp.command:
                    if 'TLS' not in pac:
                        general_out['detect_encrypted_connection'][0] = True
                        general_out['detect_encrypted_connection'][1].append(str(pac)) 
        except Exception:
            pass

        if '530 Login incorrect' in str(pac):
            general_out['detect_conf_troubles'][0] = True
            general_out['detect_conf_troubles'][1].append(str(pac))
        
        if 'FTP-DATA' in str(pac):
            window_size = int(pac['tcp.window_size'])
            window_sizes.add(window_size)
        if len(window_sizes) > 1:
            general_out['detect_window_size'][0] = True 
            general_out['detect_window_size'][1].append(window_sizes)    
    return general_out
    # return [detector_brute, detector_secureport,detect_duplicate_acknowledgment,detect_retransmission,detect_encrypted_connection,detect_conf_troubles]
# print(detect_ftp_anomaly(get_file('ftp.pcapng'))) 
x = detect_ftp_anomaly(get_file('ftp.pcapng')).values()
for i in x:
    print(i)