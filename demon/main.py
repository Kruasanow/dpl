
from flask import Flask, current_app, make_response, render_template, sessions, url_for, request, flash, session, redirect, abort, g
#import sqlite3
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, backref

DEBUG = True 

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///dbname.db' #31.25
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
#app.config.update(SECRET_KEY=os.urandom(24))
app.secret_key = 'hasgj214nfsn12213nrnm,5o12'

db = SQLAlchemy(app)

# >>> from main import db 
# >>> db.create_all()

class rest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rest_name = db.Column(db.String(25), nullable=False, unique=True)
    img = db.Column(db.String(255), nullable=False)
    number = db.Column(db.String(11), nullable=False)
    contact1 = db.Column(db.String(255), nullable=False)

@app.route('/', methods = ['get','post'])
def index():
    print(url_for('index'))

    if request.method == "POST":
        return render_template('index.html', Title = 'Добро Пожаловать!')
    return render_template('index.html', Title = 'Добро Пожаловать!')

#-----LOAD------------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
