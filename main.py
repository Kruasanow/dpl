from jinja2 import Environment
from flask import Flask, current_app, make_response, render_template, sessions, url_for, request, flash, session, redirect, abort, g
#import sqlite3
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, backref
import subprocess
import osh

UPLOAD_FOLDER = 'dump_input/'
UPLOAD_EXTENSIONS = set(['pcap','pcapng'])
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

# def jinja_is_prime(n): ## Потенциально пиздатый тест но какого то хуя не работает
#     if n % 2 == 0:
#         return True
#     else:
#         return False
# environment = Environment()
# environment.tests['jinja_is_prime'] = jinja_is_prime

@app.template_test("jinja_is_prime")
def jinja_is_prime(n):
    if n % 2 == 0:
        return True
    else:
        return False

def convert_dump(name_before,name_after):
    subprocess.call(["./scr.sh",name_before,name_after])
input_dump = 'wsh_dump.pcapng'
output_dump = 'out.txt'
convert_dump(input_dump,output_dump)

# class rest(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     rest_name = db.Column(db.String(25), nullable=False, unique=True)
#     img = db.Column(db.String(255), nullable=False)
#     number = db.Column(db.String(11), nullable=False)
#     contact1 = db.Column(db.String(255), nullable=False)

@app.route('/', methods = ['get','post'])
def index():
    print(url_for('index'))

    output_way = 'dump_output/' + output_dump
    arr_dump = []
    with open(output_way) as file:
        for line in file:
            arr_dump.append(line.rstrip())
    
    dns_pack = osh.packet_counter('DNS',osh.cap)
    tcp_pack = osh.packet_counter('TCP',osh.cap)

    if request.method == "POST":
        return render_template(
                            'index.html', 
                            Title = 'Добро Пожаловать!'
                            )
    return render_template(
                           'index.html',
                           Title = 'Добро Пожаловать!',
                           sd = arr_dump,
                           dns_pack = dns_pack,
                           tcp_pack = tcp_pack,
                           )

#-----LOAD------------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
