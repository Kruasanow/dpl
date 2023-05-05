from flask import Flask, render_template, url_for, request, redirect, session
from osh import  reload_arr, output_dump, current_file, UPLOAD_FOLDER, convert_dump, get_dname_from_db, analize_table, pac_t_list, exec_db_init_sh, get_file
from graths.prepare_graths import list_w_grath
from dnsf.dns_whois import get_qname_list, do_whois, get_items_from_who, transponate_arr
from dnsf.dns_db_addiction import init_db, add_dump
from dnsf.dns_prepare_fdb import get_dns_profile
from dnsf.dns_codes_list import delete_bad_qtype
from werkzeug.utils import secure_filename
from base_show.db_selector import get_srv_from_db
from base_show.get_ns_list import get_ns_list, do_ns_ip_tuple
# import amplification.dns_amplification
import attack_score.scoreattack as sa
import logging
import sys
import os

PROJECT_PATH = '/home/ubuntu18/diploma-1/dpl' #Для HP
# PROJECT_PATH = '/home/ubuntu18/Desktop/dpl' #Для Aquarius
if PROJECT_PATH not in sys.path:
    sys.path.append(PROJECT_PATH)

app = Flask(__name__)    
log = logging.getLogger('werkzeug')
log.disabled = True
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = 'krugloenesemkvadratnoekatim'


@app.template_test("jinja_is_prime")
def jinja_is_prime(n):
    if n % 2 == 0:
        return True
    else:
        return False

@app.route('/', methods = ['get','post'])
def index():
    print(url_for('index'))
    
    exec_db_init_sh()
    arr_dump = []
    output_way = 'dump_output/' + output_dump
    # print(output_way)

    try:
        button_status = session['button_activate']
    except Exception:
        button_status = False

    try:
        with open(output_way) as file:
            for line in file:
                arr_dump.append(line.rstrip())  
    except Exception:
        arr_dump = ['Дамп не выбран...']

    # fname = session['filename']
    fname = get_dname_from_db()

    # if '(' in str(fname):
    #     fname = ''
    try:
        cpackets = analize_table(pac_t_list,c)
    except Exception:
        try:
            cpackets = session['counted_packets']
        except Exception:
            cpackets = ""

    if request.method == "POST":
        file = request.files['file']

        if file and current_file(file.filename):
            session['button_activate'] = True
            button_status = session['button_activate']
            filename = secure_filename(file.filename)
            session['filename'] = filename
            print('[*]main.py: filename - ' + str(filename))

            add_dump(str(filename)) # add dump name to database

            c = get_file(get_dname_from_db())

            print('[*]main.py: osh.cap after choose - ' +str(c))
            print('[*]main.py: file - ' + str(file))

            # init_db()
            # get_dns_profile(c)

            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            convert_dump(filename,output_dump)
            output_way = 'dump_output/' + output_dump
            arr_dump = []
            with open(output_way) as file:
                for line in file:
                    arr_dump.append(line.rstrip())
            counted_packets = analize_table(pac_t_list,c)
            session['counted_packets'] = counted_packets
            return render_template(
                            'index.html', 
                            sd = arr_dump,
                            filename = get_dname_from_db(),
                            counted_packets = counted_packets,
                            bstatus = button_status,
                            )
    return render_template(
                           'index.html', 
                           sd = arr_dump,
                           filename = fname,
                           counted_packets = cpackets,
                           bstatus = button_status,
                          )

@app.route('/restart')
def restart_flask():
    args = [sys.executable] + sys.argv[:]
    os.execv(sys.executable, args)
    return ""

@app.route('/about', methods = ['get','post'])
def about():
    print(url_for('about'))

    name = get_dname_from_db()
    prename = 'dump_input/'
    fullname = prename + name
    print('[*]main.py: fullname for save module ' + fullname)
    from attack_score.dns_detect_ddos import detect_dns_ddos
    from attack_score.dns_detect_dnsampl import detect_dnsampl
    from attack_score.dns_detect_dnstransfzone import detect_dns_zone_transfer
    from attack_score.dns_detect_spoof import detect_dns_spoofing
    from attack_score.dns_detect_cache_pois import detect_dnscachepois

    if 'ur_ip' in request.form:
        ur_ip = request.form['ur_ip']
        limit = request.form['limit']

        from osh import delete_empty
        from dnsf.dns_prepare_fdb import is_unique

        ddos = delete_empty(detect_dns_ddos(fullname, int(limit)))
        dnsampl = delete_empty(is_unique(detect_dnsampl(fullname)))
        ztrans = delete_empty(is_unique(detect_dns_zone_transfer(fullname)))
        spoof = delete_empty(is_unique(detect_dns_spoofing(fullname)))
        pois = delete_empty(is_unique(detect_dnscachepois(fullname, ur_ip)))



        # from osh import reload_list_by_who
        return render_template(
                                'about.html',
                                a = ddos,
                                b = dnsampl,
                                c = ztrans,
                                d = spoof,
                                e = pois,
                                # acl = sa.level_acl()[1],
                                # icmp = sa.level_icmp(),
                                # udp = sa.level_udp(),
                                # syn = sa.level_syn(),
                                # ttl = sa.level_ttl(),
                                # dnsTZ = sa.DNSTZ(),
                                # dnsAP = sa.DNSAMPL(),
                                # ssl = sa.level_ssl(),
                                # insaiders = sa.level_acl()[0],
                            )
    return render_template(
                                'about.html',
                                a = '',
                                b = '',
                                c = '',
                                d = '',
                                e = '',
                            )

@app.route('/report', methods = ['get','post'])
def report():
    print(url_for('report'))
    
    from wr_acl.acl import clear_acl
    clear_acl('dns_srv_profile')
    clear_acl('dns_flags')
    init_db()
    get_dns_profile(get_file(get_dname_from_db()))
    # import subprocess
    # subprocess.call(["./scripts/rm_png_static.sh"])

    from graths.graths import build_circle
    from osh import get_par_from_dns_srv
    pars = get_par_from_dns_srv('dns_srv_profile','server','sum_pac')
    try:
        f_table = reload_arr(get_srv_from_db()[0])   
    except Exception:  
        f_table = ''
    try:
        s_table = reload_arr(get_srv_from_db()[1])
    except Exception:
        s_table = ''
    try:
        gr = list_w_grath()
    except Exception:
        gr = ''
    try:
        circle = build_circle(pars[0],pars[1])
    except Exception:
        circle = ''

    # from osh import cap
    from dnsf.dns_prepare_fdb import to_dns_arr
    
    a = to_dns_arr(get_file(get_dname_from_db()))

    len_cap = len(list(get_file(get_dname_from_db())))
    len_a = len(list(a))
    cap_ga_a = len_cap - len_a
    pacs = [cap_ga_a,len_a]
    leb_pacs = ['Другие протоколы','DNS']

    from graths.graths import build_circle
    circ = build_circle(leb_pacs,pacs)
    from wr_acl.acl import find_acl
    try:
        arr_dump = find_acl('DNS')
        show_content = True
        if arr_dump == []:
            arr_dump = ['Нет пакетов DNS']
            show_content = False
    except Exception:
        show_content = False
        arr_dump = ['Исходный дамп не выбран...']

    return render_template(
                            'report.html',
                            case = f_table,
                            case2 = s_table,
                            graph=gr,
                            cir = circle,
                            cir1 = circ,
                            sd = arr_dump,
                            show = show_content,
                          )

@app.route('/ftp', methods = ['get','post'])
def ftp():
    print(url_for('ftp'))

    from ftpf.ftp_prepare import select_ftp_get_arg
    # from osh import cap
    # asyncio.get_child_watcher().attach_loop(cap.eventloop)
    a = select_ftp_get_arg(get_file(get_dname_from_db()))
    # cap.close()
    # print(cap)
    # print(get_file(get_dname_from_db()))
    len_cap = len(list(get_file(get_dname_from_db())))
    len_a = len(list(a[0]))
    cap_ga_a = len_cap - len_a
    pacs = [cap_ga_a,len_a]
    leb_pacs = ['Другие протоколы','FTP']

    from graths.graths import build_circle
    circ = build_circle(leb_pacs,pacs)
    from wr_acl.acl import find_acl
    try:
        arr_dump = find_acl('FTP')
        show_content = True
        if arr_dump == []:
            arr_dump = ['Нет пакетов FTP']
            show_content = False
    except Exception:
        show_content = False
        arr_dump = ['Исходный дамп не выбран...']

    return render_template(
                            'ftp.html',
                            sd = arr_dump,
                            circle = circ,
                            headftp =  ['Аргумент ответа','Аргумент запроса','Команда запроса'],
                            ftp1 =  a[1],
                            ftp2 =  a[2],
                            ftp3 =  a[3],
                            show = show_content,
                          )

@app.route('/acl', methods = ['get','post'])
def acl():
    print(url_for('acl'))
    from wr_acl.acl import insert_ip_to_acl, get_ip_f_db, is_valid_ip, unique_ip
    acl_list = get_ip_f_db()
    bad_ip = 'Формат [1-255].[1-255].[1-255].[1-255]'
    if request.method == "POST":
        if 'octet1' in request.form:
            compare_ip = request.form['octet1']+ '.' +request.form['octet2'] + '.' + request.form['octet3'] + '.' + request.form['octet4']
            if is_valid_ip(compare_ip) == True:
                if unique_ip(compare_ip) == False:
                    bad_ip = 'IP уже существует'
                else:
                    bad_ip = 'IP внесен в ACL'
                    print("[*]main.py: added ip -"+ str(compare_ip))
                    insert_ip_to_acl(compare_ip)
            else:
                bad_ip = 'Неверный формат IP'
    
    return render_template(
                            'acl.html',
                            acl = acl_list,
                            ip_message = bad_ip,
                          )

@app.route('/smtp', methods = ['get','post'])
def smtp():
    print(url_for('smtp'))
    import subprocess
    from dnsf.geo_ident import show_dir_base
    decode_list = ['Декодировать','Оставить']

    full_way = PROJECT_PATH + "/scripts/traf_decrypt.sh"
    key_list = show_dir_base('dump_input/keys')
    if request.method == "POST":
        # button_action = request.form['button']
        # print(button_action)
        if 'key' in request.form:
            dump = get_dname_from_db()
            key = request.form['key']
            print(key)
            subprocess.run([full_way, dump, key])
            # return render_template(
            #                 'smtp.html',
            #                 dir = key_list,
            # )
        return render_template(
                            'smtp.html',
                            dir = key_list,
            )
    
    return render_template(
                            'smtp.html',
                            dir = key_list,
                          )

@app.route('/emulation', methods = ['get','post'])
def emulation():
    print(url_for('emulation'))
    ns = get_ns_list()
    qtype = delete_bad_qtype()

    if request.method == "POST":
        if 'ns' in request.form:
            selected_ns = request.form.get("ns")
            selected_type = request.form.get("qtype")
            current_ip = do_ns_ip_tuple()[selected_ns]

            from amplification.dns_server_scan import dns_scan
            
            ampl_koef = dns_scan(current_ip,selected_type)
            session['ampl_koef'] = ampl_koef
            return render_template(
                                'emulation.html',
                                ns=ns,
                                qtype=qtype,
                                ampl = ampl_koef,
                            )
        if 'scheck' in request.form:
            from amplification.dns_server_check import dns_server_check_main
            good_ampl = dns_server_check_main()[1]
            from base_show.get_ns_list import get_ns_ip
            select_by_gni = []
            for i  in get_ns_ip():
                if i in good_ampl:
                    select_by_gni.append(i)
            return render_template(
                                'emulation.html',
                                ns=ns,
                                qtype=qtype,
                                ampl = session['ampl_koef'],
                                good_ip = good_ampl,
                                good_ns = select_by_gni,
                            )
        if 'doampl' in request.form:
            ip = request.form["doampl"]
            
            from amplification.dns_amplification import maintain
            
            count_packets_receved = maintain(ip)
            return render_template(
                                'emulation.html',
                                ns=ns,
                                qtype=qtype,
                                ampl = session['ampl_koef'],
                                pac = count_packets_receved,
                                )
        if 'tzone' in request.form:

            from dns_emul.dns_transfer import test_dns_trans_zone
            
            ip_ns = request.form['ip_ns']
            ip_domain = request.form['ip_domain']
            a = test_dns_trans_zone(ip_ns,ip_domain)
            status = a[1]
            transfered_zone = a[0]

            return render_template(
                                    'emulation.html',
                                    status = status,
                                    tzone = transfered_zone,
            )

    return render_template(
                                'emulation.html',
                                ns=ns,
                                qtype=qtype,
                            )

@app.route('/dnsmap', methods = ['get','post'])
def dnsmap():

    from dnsf.geo_ident import base_to_db, show_dir_base,get_country_list
    base_to_db()

    base_list = show_dir_base('ip_base')

    # try:
    #     whois_status = session['whois_show']
    # except Exception:
    whois_status = False

    if 'option' in request.form:
        select = request.form['option']
        if select == 'whois':
            session['whois_show'] = True
            whois_status = session['whois_show']
            rc = []
            print(url_for('dnsmap'))
            for i in do_whois(get_qname_list()):
                rc.append(i)

            who_json = get_items_from_who(rc[1])
            who_json = transponate_arr(who_json)
            return render_template(
                            'example.html',
                            base = base_list,
                            data = rc[0],
                            who = who_json,
                            w_show = whois_status,
                            )
        prefix_path = 'ip_base/'
        fill_path_to_base = prefix_path + str(select)
        # print(get_country_list(fill_path_to_base))
        return render_template(
                            'example.html',
                            data = get_country_list(fill_path_to_base),
                            base = base_list,
                            w_show = whois_status,

        )
    
    return render_template(
                            'example.html',
                            data = {},
                            base = base_list,
                            w_show = whois_status,
    #                         # data = get_country_list('ip_base/asn-country-ipv4.csv'),
    #                         base = base_list,
    #                         data = rc[0],
    #                         who = who_json,
                            )

@app.route('/wireshark', methods = ['get','post'])
def wireshark():
    print(url_for('wireshark'))
    return render_template(
                            'wireshark.html',
                          )

@app.route('/tshark', methods = ['get','post'])
def tshark():
    print(url_for('tshark'))
    return render_template(
                            'tshark.html',
                          )

@app.route('/tcpdump', methods = ['get','post'])
def tcpdump():
    print(url_for('tcpdump'))
    return render_template(
                            'tcpdump.html',
                          )

#-----LOAD------------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=False)
