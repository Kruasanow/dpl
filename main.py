from flask import Flask, render_template, url_for, request
import osh
import os
import scoreattack as sa
from werkzeug.utils import secure_filename
import psycopg2 as ps

app = Flask(__name__)    
app.config['UPLOAD_FOLDER'] = osh.UPLOAD_FOLDER

def get_db_connection():
    conn = ps.connect(host='localhost',
                      database='flask_db',
                      user=os.environ['DB_USERNAME'],
                      password=os.environ['DB_PASSWORD']
                    )
    return conn

@app.template_test("jinja_is_prime")
def jinja_is_prime(n):
    if n % 2 == 0:
        return True
    else:
        return False


@app.route('/', methods = ['get','post'])
def index():
    print(url_for('index'))
    
    # CREATE DATABASE #
    # conn = get_db_connection() 
    # cur = conn.cursor()
    # cur.execute('SELECT * FROM books;')
    # table1_test = cur.fetchall() # СОХРАНЕНИЕ ДАННЫХ В ПЕРЕМЕННОЙ
    # cur.close()
    # conn.close()
    # # # # # # # # # # 

    output_way = 'dump_output/' + osh.output_dump
    arr_dump = []
    with open(output_way) as file:
        for line in file:
            arr_dump.append(line.rstrip())

    if request.method == "POST":
        file = request.files['file']
        if file and osh.current_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            osh.convert_dump(filename,osh.output_dump)
        return render_template(
                            'index.html', 
                            sd = arr_dump,
                            filename = filename,
                            dns_pack = osh.dns_pack,
                            tcp_pack = osh.tcp_pack,
                            udp_pack = osh.udp_pack,
                            ssl_pack = osh.ssl_pack,
                            vss_pack = osh.vss_pack,
                            data_pack = osh.data_pack,
                            icmp_pack = osh.icmp_pack,
                            )
        
    return render_template(
                           'index.html'
                          )

@app.route('/about', methods = ['get','post'])
def about():
    print(url_for('about'))

    conn = get_db_connection() 
    cur = conn.cursor()
    cur.execute('SELECT * FROM books;')
    table1_test = cur.fetchall() # SAVE DATA IN VARIABLE
    cur.close()
    conn.close()

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
                            table = table1_test
                          )

#-----LOAD------------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
