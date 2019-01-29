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
app.config['MAIL_USERNAME'] = 'xx'
app.config['MAIL_PASSWORD'] = 'xx'
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
        
        cur.execute("SELECT * FROM users WHERE email = %s", [email])

        if cur.fetchone() is not None:
            flash("Email Already registered :D, Login to continue", 'danger')
            return redirect(url_for('login'))
        
        
    
        cur.execute("SELECT * FROM users WHERE username = %s", [username])

        if cur.fetchone() is not None:
            flash("Username already taken", 'danger')
            

        else:
            cur.execute("INSERT INTO users(name, email, username, password, confirm_email) VALUES(%s, %s, %s, %s, %s)", (name, email, username, password, confirm_email))
        
            mysql.connection.commit()
            token= s.dumps(email, salt='email-confirm')
            msg=Message('Confirm Email', sender='dhirajbaruah412@gmail.com', recipients=[email])
            link=url_for('confirm_email', token=token, _external=True)
            msg.body='your link is {}'.format(link)
            mail.send(msg)
        
            flash('Please confirm your email', 'success')
            return redirect(url_for('login'))
        

        cur.close()

        

        
    return render_template('register.html', form=form)
    
@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        email=s.loads(token, salt='email-confirm', max_age=3600)
    except SignatureExpired:
        return 'Token Expired'
    cur=mysql.connection.cursor()
    result=cur.execute("SELECT * FROM users where confirm_email= %s", [confirm_email])
    
    cur.close()
    if result>0:
        return 'confirmed'
    else:
        cur=mysql.connection.cursor()
        cur.execute("UPDATE users SET confirm_email='1' where email=%s", [email])
        mysql.connection.commit()
        cur.close()
    return 'thank you'

class LoginForm(Form):
    usernamelogin=StringField('Username', [validators.Length(min=1, max=50)])
    passwordlogin=PasswordField('Password', [validators.DataRequired(), validators.Length(min=3, max=100)])


@app.route('/login', methods=['GET', 'POST'])
def login():
    formlogin=LoginForm(request.form)
    if request.method=='POST' and formlogin.validate():
        usernamelogin=formlogin.usernamelogin.data
        passwordlogin=formlogin.passwordlogin.data

        cur=mysql.connection.cursor()
        result=cur.execute("SELECT * FROM users where username= %s", [usernamelogin])
        #result2=cur.execute("SELECT * FROM users where email=%s", [usernamelogin])
        if result>0:
            data = cur.fetchone()
            password= data['password']

            if sha256_crypt.verify(passwordlogin, password):
                session['logged_in']= True
                session['username']= usernamelogin
                flash('you are now logged in', 'success')
                return redirect(url_for('register'))
        elif (cur.execute("SELECT * FROM users where email=%s", [usernamelogin]))>0:
        
            data = cur.fetchone()
            password= data['password']

            if sha256_crypt.verify(passwordlogin, password):
                session['logged_in']= True
                session['username']= usernamelogin
                flash('you are now logged in', 'success')
                return redirect(url_for('register'))
        

            else:
                flash("Password didnot match", 'danger')
                return redirect(url_for('login'))
        else:
            flash('Username not found', 'danger')
            return redirect(url_for('login'))
        

        cur.close()
    else:
        #flash('Username not found', 'danger')
        return render_template('login.html', formlogin=formlogin)

        


    #return render_template('login.html', formlogin=formlogin)
    
if __name__ == "__main__":
    app.secret_key='secret123'
    app.run(debug=True)

    