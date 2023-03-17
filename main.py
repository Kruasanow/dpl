from flask import Flask, render_template, url_for, request
from osh import  reload_arr, cap, output_dump, current_file, UPLOAD_FOLDER, convert_dump, get_dname_from_db, analize_table, pac_t_list, exec_db_init_sh, get_file
import os
import scoreattack as sa
from werkzeug.utils import secure_filename
import psycopg2 as ps
from dns.dns_whois import get_qname_list, do_whois, get_items_from_who, transponate_arr
import db_do.conn_db as cdb
from dns.dns_db_addiction import init_db, add_dump
from dns.dns_prepare_fdb import get_dns_profile
import logging
from base_show.db_selector import get_srv_from_db
import sys

app = Flask(__name__)    
log = logging.getLogger('werkzeug')
log.disabled = True
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.template_test("jinja_is_prime")
def jinja_is_prime(n):
    if n % 2 == 0:
        return True
    else:
        return False


@app.route('/', methods = ['get','post'])
def index():
    print(url_for('index'))
    # print('[*]main.py: osh.cap - ' +str(cap))
    exec_db_init_sh()
    # output_way = 'dump_output/' + output_dump
    # arr_dump = []
    # with open(output_way) as file:
    #     for line in file:
    #         arr_dump.append(line.rstrip())

    if request.method == "POST":
        file = request.files['file']

        if file and current_file(file.filename):
            filename = secure_filename(file.filename)
            print('[*]main.py: filename - ' + str(filename))

            add_dump(str(filename)) # add dump name to database

            c = get_file(get_dname_from_db())
            print(c)
            print('[*]main.py: osh.cap after choose - ' +str(c))
            print('[*]main.py: file - ' + str(file))

            init_db(c)
            get_dns_profile(c) # TUT VSE IDET PO PIZDE

            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            convert_dump(filename,output_dump)
            output_way = 'dump_output/' + output_dump
            arr_dump = []
            with open(output_way) as file:
                for line in file:
                    arr_dump.append(line.rstrip())
            return render_template(
                            'index.html', 
                            sd = arr_dump,
                            filename = get_dname_from_db(),
                            counted_packets = analize_table(pac_t_list,c),
                            )
    return render_template(
                           'index.html',
                           
                          )

@app.route('/restart')
def restart_flask():
    args = [sys.executable] + sys.argv[:]
    os.execv(sys.executable, args)
    return("")

@app.route('/about', methods = ['get','post'])
def about():
    print(url_for('about'))

    return render_template(
                            'about.html',
                            acl = sa.level_acl()[1],
                            icmp = sa.level_icmp(),
                            udp = sa.level_udp(),
                            syn = sa.level_syn(),
                            ttl = sa.level_ttl(),
                            dnsTZ = sa.DNSTZ(),
                            dnsAP = sa.DNSAMPL(),
                            ssl = sa.level_ssl(),
                            insaiders = sa.level_acl()[0]
                            # table = table1_test
                          )

@app.route('/report', methods = ['get','post'])
def report():
    print(url_for('report'))

    return render_template(
                            'report.html',
                            case = reload_arr(get_srv_from_db()[0]),
                            case2 = reload_arr(get_srv_from_db()[1]),
                          )

@app.route('/dnsmap', methods = ['get','post'])
def dnsmap():
    rc = []
    print(url_for('dnsmap'))
    for i in do_whois(get_qname_list()): #NO INET
        rc.append(i)
    who_json = get_items_from_who(rc[1])
    who_json = transponate_arr(who_json)

    return render_template(
                            'example.html',
                            data = rc[0], # KOSTIL'
                            who = who_json
                            )

#-----LOAD------------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=False)
