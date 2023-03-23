from flask import Flask, render_template, url_for, request, redirect
from osh import  reload_arr, output_dump, current_file, UPLOAD_FOLDER, convert_dump, get_dname_from_db, analize_table, pac_t_list, exec_db_init_sh, get_file
from graths.prepare_graths import list_w_grath
from dnsf.dns_whois import get_qname_list, do_whois, get_items_from_who, transponate_arr
from dnsf.dns_db_addiction import init_db, add_dump
from dnsf.dns_prepare_fdb import get_dns_profile
from werkzeug.utils import secure_filename
from base_show.db_selector import get_srv_from_db
import attack_score.scoreattack as sa
import logging
import sys
import os

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
            get_dns_profile(c)

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
    return redirect(url_for('/'), 301)

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
                            insaiders = sa.level_acl()[0],
                          )

@app.route('/report', methods = ['get','post'])
def report():
    print(url_for('report'))

    try:
        f_table = reload_arr(get_srv_from_db()[0])
        s_table = reload_arr(get_srv_from_db()[1])
        gr = list_w_grath()
    except Exception:
        f_table = '.....'
        s_table = '.....'
        gr = 'Для построения графика выберите дамп ...'
    return render_template(
                            'report.html',
                            case = f_table,
                            case2 = s_table,
                            graph=gr,
                          )

@app.route('/dnsmap', methods = ['get','post'])
def dnsmap():
    rc = []
    print(url_for('dnsmap'))
    for i in do_whois(get_qname_list()):
        rc.append(i)
    who_json = get_items_from_who(rc[1])
    who_json = transponate_arr(who_json)

    return render_template(
                            'example.html',
                            data = rc[0],
                            who = who_json
                            )

#-----LOAD------------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=False)
