from flask import Flask, render_template, request, flash, redirect, url_for, session, logging, flash
from wtforms import StringField, PasswordField, validators, Form
from flask_mysqldb import MySQL
from passlib.hash import sha256_crypt
from functools import wraps
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
import datetime

app=Flask(__name__)
#mysql config
app.config['MYSQL_HOST'] ='localhost'
app.config['MYSQL_USER'] ='root'
app.config['MYSQL_PASSWORD'] ='1111'
app.config['MYSQL_DB'] ='myflaskapp'
app.config['MYSQL_CURSORCLASS'] ='DictCursor'

mysql=MySQL(app)


#mail server config
app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = ''
app.config['MAIL_PASSWORD'] = ''
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)

s= URLSafeTimedSerializer('secret123')


@app.route("/")
def index():
    return render_template('index.html')

class RegisterForm(Form):
    name=StringField('Name', [validators.DataRequired(), validators.Length(min=1, max=50)])
    username= StringField('username', [validators.DataRequired(), validators.Length(min=4, max=50)])
    email=StringField('Email', [validators.DataRequired(), validators.Length(min=6, max=100)])
    password= PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')

    ])
    confirm=PasswordField('Confirm password', [validators.DataRequired()])


@app.route('/register', methods=['GET', 'POST'])
def register():
    
    form=RegisterForm(request.form)
    if request.method=='POST' and form.validate():
        name=form.name.data
        email=form.email.data
        username=form.username.data
        password=sha256_crypt.encrypt(str(form.password.data))
        confirm_email='0'

        cur= mysql.connection.cursor()
        cur.execute("INSERT INTO users(name, email, username, password, confirm_email) VALUES(%s, %s, %s, %s, %s)", (name, email, username, password, confirm_email))
        
        mysql.connection.commit()

        cur.close()

        token= s.dumps(email, salt='email-confirm')
        msg=Message('Confirm Email', sender='dhirajbaruah412@gmail.com', recipients=[email])
        link=url_for('confirm_email', token=token, _external=True)
        msg.body='your link is {}'.format(link)
        mail.send(msg)
        
        flash('Please confirm your email', 'success')
        return redirect(url_for('register'))

        
    return render_template('register.html', form=form)
    
@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        email=s.loads(token, salt='email-confirm', max_age=3600)
    except SignatureExpired:
        return 'Token Expired'
    cur=mysql.connection.cursor()
    result=cur.execute("SELECT * FROM users where confirm_email= %s", [confirm_email])
    if result==1:
        return 'already confirmed'
    else:
        cur.execute("UPDATE users SET confirm_email='1' where email=%s", [email])
    return redirect(url_for('login'))
    
if __name__ == "__main__":
    app.secret_key='secret123'
    app.run(debug=True)

    