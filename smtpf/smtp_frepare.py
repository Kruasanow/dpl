# 'response_code', 'rsp_parameter', 'req_command'

def to_smtp_arr(a):
    smtp_arr = []
    for pac in a:
        if hasattr(pac,'smtp'):
            smtp_arr.append(pac)
    return smtp_arr

def get_smtp_info(cap): 
    cap = to_smtp_arr(cap)   
    out_rsp_param = [[],[]]
    out_resp_code = [[],[]]
    out_req_command = [[],[]]
    out_command_line = [[],[]]
    out_user = [[],[]]
    out_passw = [[],[]]
    for pac in cap:
        if hasattr(pac,'smtp'):
            if hasattr(pac.smtp,'rsp_parameter'):
                out_rsp_param[0].append(pac.frame_info.number)
                out_rsp_param[1].append(pac.smtp.rsp_parameter)
            if hasattr(pac.smtp,'response_code'):
                out_resp_code[0].append(pac.frame_info.number)
                out_resp_code[1].append(pac.smtp.response_code)
            if hasattr(pac.smtp,'req_command'):
                out_req_command[0].append(pac.frame_info.number)
                out_req_command[1].append(pac.smtp.req_command)
            if hasattr(pac.smtp,'command_line'):
                out_command_line[0].append(pac.frame_info.number)
                out_command_line[1].append(pac.smtp.command_line)
            if hasattr(pac.smtp,'auth_username'):
                out_user[0].append(pac.frame_info.number)
                out_user[1].append(pac.smtp.auth_username)
            if hasattr(pac.smtp,'auth_password'):
                out_passw[0].append(pac.frame_info.number)
                out_passw[1].append(pac.smtp.auth_password)
            else:
                pass
    return [out_rsp_param, out_resp_code, out_req_command,out_command_line,out_user,out_passw]
# from pyshark import FileCapture
# print(get_smtp_info(FileCapture('dump_input/smtp.pcap')))

def compare_code_smtp(arr):
    out_arr = []
    from smtpf.smtp_codes import code_smtp_dict
    for i in arr:
        for j in code_smtp_dict:
            if i == j:
                out_arr.append(code_smtp_dict[j])
    return out_arr

# print(get_smtp_info(cap))