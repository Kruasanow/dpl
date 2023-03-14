from flask import Flask, render_template, url_for, request
from osh import cap, output_dump, current_file, UPLOAD_FOLDER, convert_dump, get_dname_from_db, analize_table, pac_t_list
import os
import scoreattack as sa
from werkzeug.utils import secure_filename
import psycopg2 as ps
from dns_whois import get_qname_list, do_whois, get_items_from_who
import conn_db as cdb
import dns_db_addiction as dnsadd
import dns_prepare_fdb as dprep

app = Flask(__name__)    
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# def get_db_connection():
#     conn = ps.connect(host='localhost',
#                       database='flask_db',
#                       user=os.environ['DB_USERNAME'],
#                       password=os.environ['DB_PASSWORD']
#                     )
#     return conn

@app.template_test("jinja_is_prime")
def jinja_is_prime(n):
    if n % 2 == 0:
        return True
    else:
        return False


@app.route('/', methods = ['get','post'])
def index():
    print(url_for('index'))
    print('main.py: osh.cap - ' +str(cap))
    dnsadd.init_db(cap)
    dprep.get_dns_profile(cap)

    output_way = 'dump_output/' + output_dump
    arr_dump = []
    with open(output_way) as file:
        for line in file:
            arr_dump.append(line.rstrip())

    if request.method == "POST":
        file = request.files['file']
        print('main.py: file - ' + str(file))
        if file and current_file(file.filename):
            filename = secure_filename(file.filename)
            print('main.py: filename - ' + str(filename))

            dnsadd.add_dump(str(filename)) # add dump name to database

            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            convert_dump(filename,output_dump)
        return render_template(
                            'index.html', 
                            sd = arr_dump,
                            filename = get_dname_from_db(),
                            counted_packets = analize_table(pac_t_list,cap),
                            )
        
    return render_template(
                           'index.html'
                          )

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

@app.route('/dnsmap', methods = ['get','post'])
def dnsmap():
    rc = []
    print(url_for('dnsmap'))
    # for i in do_whois(get_qname_list()): #NO INET
    #     rc.append(i)
    return render_template(
                            'example.html',
                            data = {'BY':2, 'JP':2, 'IS':2} # KOSTIL'
                            # items = get_items
                            )

#-----LOAD------------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
