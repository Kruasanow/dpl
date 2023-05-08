# 'response_code', 'rsp_parameter', 'req_command'

def to_smtp_arr(a):
    smtp_arr = []
    for pac in a:
        if hasattr(pac,'smtp'):
            smtp_arr.append(pac)
    return smtp_arr

def get_smtp_info(cap): 
    cap = to_smtp_arr(cap)   
    out_rsp_param = []
    out_resp_code = []
    out_req_command = []
    for pac in cap:
        try:
            out_rsp_param.append(pac['smtp'].rsp_parameter)
        except Exception:
            pass
        try:
            out_resp_code.append(pac['smtp'].response_code)
        except Exception:
            pass
        try:
            out_req_command.append(pac['smtp'].req_command)
        except Exception:
            pass
    return [out_rsp_param, out_resp_code, out_req_command]

# print(get_smtp_info(cap))

def compare_code_smtp(arr):
    out_arr = []
    from smtpf.smtp_codes import code_smtp_dict
    for i in arr:
        for j in code_smtp_dict:
            if i == j:
                out_arr.append(code_smtp_dict[j])
    return out_arr

# print(get_smtp_info(cap))