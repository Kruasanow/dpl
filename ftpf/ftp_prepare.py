# from pyshark import FileCapture
def select_ftp_get_arg(cap):
    
    ftp_arr          = []
    response_arg_arr = []
    request_arg_arr  = []
    command_arr      = []

    for pac in cap:
        if 'FTP' in pac:
            ftp_arr.append(pac)

            if hasattr(pac.ftp,'response_arg'):
                # print('---------------response')
                # print(pac.ftp.response_arg)
                response_arg_arr.append(pac.ftp.response_arg)

            elif hasattr(pac.ftp,'request_arg'):
                # print('---------------request')
                # print(pac.ftp.request_arg)
                request_arg_arr.append(pac.ftp.request_arg)

            elif hasattr(pac.ftp,'request_command'):
                # print('---------------no-exception')
                # print(pac.ftp.request_command)
                command_arr.append(pac.ftp.request_command)
            else:
                print('[*]ftp_prepare.py: else arg validator works')

    return [ftp_arr, response_arg_arr, request_arg_arr, command_arr]
# import subprocess 

def to_ftp_arr(a):
    ftp_arr = []
    for pac in a:
        if hasattr(pac,'ftp'):
            ftp_arr.append(pac)
    return ftp_arr

# subprocess.call('scripts/sftp_decript.sh')
# print(select_ftp_get_arg(FileCapture('dump_input/ftp.pcapng')))
import sys
PROJECT_PATH = '/home/ubuntu18/diploma-1/dpl' #Для HP
# PROJECT_PATH = '/home/ubuntu18/Desktop/dpl' #Для Aquarius
if PROJECT_PATH not in sys.path:
    sys.path.append(PROJECT_PATH)

from osh import get_file, get_dname_from_db
def detect_ftp_anomaly(cap):
    cap = to_ftp_arr(cap)
    print(len(cap))
    detector_brute = False #брутят
    detector_secureport = False #админ еблан не сменил порт
    detect_duplicate_acknowledgment = False #двойное подтверждение
    detect_retransmission = False # проблема с передачей
    detect_encrypted_connection = False #работа без TLS
    detect_conf_troubles = False 
    from collections import Counter
    command_counter = []
    window_sizes = set()
    for pac in cap:
        # print(str(pac))
        try:
            command_counter.append(pac.ftp.request_command)
        except Exception:
            pass
        counter = Counter(command_counter)
        count_user = counter['USER']
        count_pass = counter['PASS']
        count_port = counter['PORT']
        count_pasv = counter['PASV']
        if count_port < 2 and count_pasv > 2:
            detector_secureport = True
        if count_user > 3 or count_pass > 3:
            detector_brute = True

        if 'tcp.analysis.retransmission' in str(cap):
            detect_retransmission = True

        if 'tcp.analysis.duplicate_acknowledgment' in str(cap):
            detect_duplicate_acknowledgment = True  

        try:
            if 'STOR' in pac.ftp.command or 'RETR' in pac.ftp.command:
                if pac.ftp_data and 'USER' not in pac.ftp.command and 'PASS' not in pac.ftp.command:
                    if 'TLS' not in pac:
                        detect_encrypted_connection = True 
        except Exception:
            pass

        if '530 Login incorrect' in str(pac):
            detect_conf_troubles = True
        
        if 'FTP-DATA' in str(pac):
            window_size = int(pac['tcp.window_size'])
            window_sizes.add(window_size)
        if len(window_sizes) > 1:
            print('FTP traffic contains different window sizes: {}'.format(window_sizes)) #!!!!!!

    return [detector_brute, detector_secureport,detect_duplicate_acknowledgment,detect_retransmission,detect_encrypted_connection,detect_conf_troubles]
print(detect_ftp_anomaly(get_file('ftp_brute.pcapng')))