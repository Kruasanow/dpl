import pyshark
cap = pyshark.FileCapture('dump_input/http.pcap')

field_names = [
'date', 'user_agent', 'server', 'request_uri', 'time', 
'accept_encoding', 'request_uri_query_parameter', 
'response_phrase', 'request_version', 'request_method', 
'response_for_uri', 'request_uri_query', 'request_full_uri', 
'chat', 'host', 'response_line', 'connection', 
'response_version', 'accept_language', 'response_code_desc', 
'response_code', 'request_line', 'accept', 'request_uri_path']

def to_http_arr(a):
    smtp_arr = []
    for pac in a:
        if hasattr(pac,'http'):
            smtp_arr.append(pac)
    return smtp_arr

def get_http_info(cap): 
    cap = to_http_arr(cap)  
    date                        = [[],[]]
    user_agent                  = [[],[]] 
    server                      = [[],[]]
    #request                     = [[],[]]
    request_uri                 = [[],[]]
    time                        = [[],[]]
    accept_encoding             = [[],[]]
    #request_number              = [[],[]]
    request_uri_query_parameter = [[],[]]
    response_phrase             = [[],[]]
    request_version             = [[],[]]
    request_method              = [[],[]]
    #response                    = [[],[]]
    #response_number             = [[],[]]
    #request_in                  = [[],[]]
    response_for_uri            = [[],[]]
    request_uri_query           = [[],[]]
    request_full_uri            = [[],[]]
    chat                        = [[],[]]
    host                        = [[],[]]
    response_line               = [[],[]]
    #location                    = [[],[]]
    connection                  = [[],[]]
    response_version            = [[],[]]
    accept_language             = [[],[]]
    response_code_desc          = [[],[]]
    response_code               = [[],[]]
    request_line                = [[],[]]
    accept                      = [[],[]]
    request_uri_path            = [[],[]]
    for pac in cap:
        if hasattr(pac,'http'):
            # print(pac['http'])
            if hasattr(pac.http,'date'):
                date[0].append(pac.frame_info.number)
                date[1].append(pac.http.date)
            if hasattr(pac.http,'user_agent'):
                user_agent[0].append(pac.frame_info.number)
                user_agent[1].append(pac.http.user_agent)
            if hasattr(pac.http,'server'):
                server[0].append(pac.frame_info.number)
                server[1].append(pac.http.server)
            #if hasattr(pac.http,'request'):
            #    request[0].append(pac.frame_info.number)
            #    request[1].append(pac.http.request)
            if hasattr(pac.http,'request_uri'):
                request_uri[0].append(pac.frame_info.number)
                request_uri[1].append(pac.http.request_uri)
            if hasattr(pac.http,'time'):
                time[0].append(pac.frame_info.number)
                time[1].append(pac.http.time)
            if hasattr(pac.http,'accept_encoding'):
                accept_encoding[0].append(pac.frame_info.number)
                accept_encoding[1].append(pac.http.accept_encoding)
            #if hasattr(pac.http,'request_number'):
            #    request_number[0].append(pac.frame_info.number)
            #    request_number[1].append(pac.http.request_number)
            if hasattr(pac.http,'request_uri_query_parameter'):
                request_uri_query_parameter[0].append(pac.frame_info.number)
                request_uri_query_parameter[1].append(pac.http.request_uri_query_parameter)
            if hasattr(pac.http,'response_phrase'):
                response_phrase[0].append(pac.frame_info.number)
                response_phrase[1].append(pac.http.response_phrase)
            if hasattr(pac.http,'request_version'):
                request_version[0].append(pac.frame_info.number)
                request_version[1].append(pac.http.request_version)
            if hasattr(pac.http,'request_method'):
                request_method[0].append(pac.frame_info.number)
                request_method[1].append(pac.http.request_method)
            #if hasattr(pac.http,'response'):
            #    response[0].append(pac.frame_info.number)
            #    response[1].append(pac.http.response)
            #if hasattr(pac.http,'response_number'):
            #    response_number[0].append(pac.frame_info.number)
            #    response_number[1].append(pac.http.response_number)
            #if hasattr(pac.http,'request_in'):
            #    request_in[0].append(pac.frame_info.number)
            #    request_in[1].append(pac.http.request_in)
            if hasattr(pac.http,'response_for_uri'):
                response_for_uri[0].append(pac.frame_info.number)
                response_for_uri[1].append(pac.http.response_for_uri)
            if hasattr(pac.http,'request_uri_query'):
                request_uri_query[0].append(pac.frame_info.number)
                request_uri_query[1].append(pac.http.request_uri_query)
            if hasattr(pac.http,'request_full_uri'):
                request_full_uri[0].append(pac.frame_info.number)
                request_full_uri[1].append(pac.http.request_full_uri)
            if hasattr(pac.http,'chat'):
                chat[0].append(pac.frame_info.number)
                chat[1].append(pac.http.chat)
            if hasattr(pac.http,'host'):
                host[0].append(pac.frame_info.number)
                host[1].append(pac.http.host)
            if hasattr(pac.http,'response_line'):
                response_line[0].append(pac.frame_info.number)
                response_line[1].append(pac.http.response_line)
            #if hasattr(pac.http,'location'):
            #    location[0].append(pac.frame_info.number)
            #    location[1].append(pac.http.location)
            if hasattr(pac.http,'connection'):
                connection[0].append(pac.frame_info.number)
                connection[1].append(pac.http.connection)
            if hasattr(pac.http,'response_version'):
                response_version[0].append(pac.frame_info.number)
                response_version[1].append(pac.http.response_version)
            if hasattr(pac.http,'accept_language'):
                accept_language[0].append(pac.frame_info.number)
                accept_language[1].append(pac.http.accept_language)
            if hasattr(pac.http,'response_code_desc'):
                response_code_desc[0].append(pac.frame_info.number)
                response_code_desc[1].append(pac.http.response_code_desc)
            if hasattr(pac.http,'response_code'):
                response_code[0].append(pac.frame_info.number)
                response_code[1].append(pac.http.response_code)
            if hasattr(pac.http,'request_line'):
                request_line[0].append(pac.frame_info.number)
                request_line[1].append(pac.http.request_line)
            if hasattr(pac.http,'accept'):
                accept[0].append(pac.frame_info.number)
                accept[1].append(pac.http.accept)
            if hasattr(pac.http,'request_uri_path'):
                request_uri_path[0].append(pac.frame_info.number)
                request_uri_path[1].append(pac.http.request_uri_path)
            else:
                pass
    return [date,  #'Wed, 28 Mar 2018 02:37:41 GMT', 'Wed, 28 Mar 2018 02:37:51 GMT'
            user_agent, #'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:59.0) Gecko/20100101 Firefox/59.0', 'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.6) Gecko/20040113'
            server, #'SimpleHTTP/0.6 Python/2.7.14', 'CAFE/1.0', 'Apache'
            #request, # 1
            request_uri, #'/', '/?path=foo', '/foo', '/download.html', '/pagead/ads?client=ca-pub-2309191948673629&random=1084443430285&
            time, #'0.000407565', '0.000491123'
            accept_encoding, #'gzip, deflate'
            #request_number, #'1'
            request_uri_query_parameter, #'path=foo', 'path=foobar', 'client=ca-pub-2309191948673629'
            response_phrase, #'OK', 'Found', 'Found', 'OK'
            request_version, #'HTTP/1.1', 'HTTP/1.1'
            request_method, #'GET', 'GET'
            #response, #'1', '1'
            #response_number, #'1', '1'
            #request_in, #'1', '6', '12'
            response_for_uri, #'http://127.0.0.1/', 'http://127.0.0.1/?path=foo' 'http://pagead2.googlesyndication.com/pagead/ads?client=ca-pub-2309191948673629&random
            request_uri_query, #'path=foo', 'path=foobar' 'client=ca-pub-2309191948673629&random=1084443430285
            request_full_uri, #'http://127.0.0.1/', 'http://www.ethereal.com/download.html'
            chat, #'GET / HTTP/1.1\\r\\n', 'HTTP/1.0 200 OK\\r\\n' 'GET /download.html HTTP/1.1\\r\\n'
            host, #'127.0.0.1', 'www.ethereal.com', 'pagead2.googlesyndication.com'
            response_line, #Server: SimpleHTTP/0.6 Python/2.7.14\\xd\\xa 'P3P: policyref="http://www.googleadservices.com/pagead/p3p.xml
            #location, #'foo', '/', 'foobar'
            connection, #'keep-alive', 'keep-alive'
            response_version, #'HTTP/1.0', 'HTTP/1.0'
            accept_language, #'en-US,en;q=0.5'
            response_code_desc, #'OK', 'Found'
            response_code, #'200', '302', '302'
            request_line, #'Host: 127.0.0.1\\xd\\xa' 'Host: www.ethereal.com\\xd\\xa', 'Host: pagead2.googlesyndication.com\\xd\\xa'
            accept, #'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' 'text/xml,application/xml,application/xhtml+xml
            request_uri_path] #'/', '/my/path', '/my/path', '/', '/b/c/d;p', '/pagead/ads'

def compare_code_http(arr,clist):
    out_arr = []
    # from httpf.http_codes import code_http_dict
    for i in arr:
        for j in clist:
            if i == j:
                out_arr.append(clist[j])
    return out_arr

# import sys
# # PROJECT_PATH = '/home/ubuntu18/diploma-1/dpl' #Для HP
# PROJECT_PATH = '/home/ubuntu18/Desktop/dpl' #Для Aquarius
# if PROJECT_PATH not in sys.path:
#     sys.path.append(PROJECT_PATH)
# print(get_http_info(cap)[20])
# from httpf.http_codes import code_http_dict
# print(compare_code_http(get_http_info(cap)[20][1],code_http_dict))