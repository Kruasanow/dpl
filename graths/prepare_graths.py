

from graths.graths import do_grath

def do_same_shape(arr):
    eb_arr = []
    for i in arr:
        eb_arr.append(len(i))
    biggest_len = max(eb_arr)
    for i in arr:
        while len(i) < biggest_len:
            i.append(0) 
    return [arr, biggest_len]

def list_w_grath():
    from dnsf.dns_prepare_fdb import TIME, TTL, SERVERS
    time = do_same_shape(TIME)[0] 
    # print(time)
    ttl = TTL
    servers = SERVERS 
    outlen = list(range(1, do_same_shape(TIME)[1]+1 ))
    # print('outlen' + str(outlen))
    out = []
    # for s,tm in zip(servers, time):
    i = 0
    for i in range(len(servers)):
        out.append(do_grath(outlen, time[i], 'Пакеты', 'Время', servers[i]))
    return out