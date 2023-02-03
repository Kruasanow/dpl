from flask import Flask, render_template, url_for, request, flash, session, redirect, g, send_from_directory
from flask_sqlalchemy import SQLAlchemy
import sqlalchemy.orm
import subprocess
import osh
import attack
import os
import scoreattack
from werkzeug.utils import secure_filename
#import sqlite3

UPLOAD_FOLDER = 'dump_input/'
ALLOWED_EXTENSIONS = set(['pcap','pcapng'])
DEBUG = True 

app = Flask(__name__)    
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///dbname.db' #31.25
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
##app.config.update(SECRET_KEY=os.urandom(24))
app.secret_key = 'hasgj214nfsn12213nrnm,5o12'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

db = SQLAlchemy(app)

# >>> from main import db 
# >>> db.create_all()

def current_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS

@app.template_test("jinja_is_prime")
def jinja_is_prime(n):
    if n % 2 == 0:
        return True
    else:
        return False


# class rest(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     rest_name = db.Column(db.String(25), nullable=False, unique=True)
#     img = db.Column(db.String(255), nullable=False)
#     number = db.Column(db.String(11), nullable=False)
#     contact1 = db.Column(db.String(255), nullable=False)

@app.route('/', methods = ['get','post'])
def index():
    print(url_for('index'))

    output_way = 'dump_output/' + osh.output_dump
    arr_dump = []
    with open(output_way) as file:
        for line in file:
            arr_dump.append(line.rstrip())

    if request.method == "POST":
        file = request.files['file']
        if file and current_file(file.filename):
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
                            icmp_pack = osh.icmp_pack
                            )
        
    return render_template(
                           'index.html'
                          )

@app.route('/about', methods = ['get','post'])
def about():
    print(url_for('about'))

    

    return render_template(
                            'about.html',
                            acl = scoreattack.level_acl()[1],
                            icmp = scoreattack.level_icmp(),
                            udp = scoreattack.level_udp(),
                            syn = scoreattack.level_syn(),
                            ttl = scoreattack.level_ttl(),
                            dnsTZ = scoreattack.DNSTZ(),
                            dnsAP = scoreattack.DNSAMPL(),
                            ssl = scoreattack.level_ssl(),
                            insaiders = scoreattack.level_acl()[0]
                          )

#-----LOAD------------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
