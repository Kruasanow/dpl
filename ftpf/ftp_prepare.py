from pyshark import FileCapture
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

            else:
                # print('---------------no-exception')
                # print(pac.ftp.request_command)
                command_arr.append(pac.ftp.request_command)

    return [ftp_arr, response_arg_arr, request_arg_arr, command_arr]
import subprocess 

# subprocess.call('scripts/sftp_decript.sh')
# print(select_ftp_get_arg(FileCapture('dump_input/ftp.pcapng')))