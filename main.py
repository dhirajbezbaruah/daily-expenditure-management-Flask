from flask import Flask, render_template, request, flash, redirect, url_for, session, logging, flash
from wtforms import StringField, PasswordField, validators, Form, DateField, ValidationError, SelectField, TextAreaField
from flask_mysqldb import MySQL
from passlib.hash import sha256_crypt
from functools import wraps
from flask_mail import Mail, Message
from flask_wtf.file import FileAllowed, FileField
#import secrets
import os
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, TimedJSONWebSignatureSerializer
#import safe
from werkzeug.utils import secure_filename
from PIL import Image
from flask_bootstrap import Bootstrap
from flask_datepicker import datepicker
from datetime import date, datetime, timedelta

app = Flask(__name__)
Bootstrap(app)
datepicker(app)


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
app.config['MAIL_USERNAME'] = '******@gmail.com'
app.config['MAIL_PASSWORD'] = '*****'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)

s= URLSafeTimedSerializer('secret123')


#users
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            flash('You Must Login First!', 'danger')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function
#admins
def admin_login(g):
    @wraps(g)
    def decorated_function(*args, **kwargs):
        if 'adminlogin' not in session:
            flash('Oops! Looks like You are not an admin.', 'danger')
            return redirect(url_for('login', next=request.url))
        return g(*args, **kwargs)
    return decorated_function

#Home
@app.route("/")
def index():
    return render_template('home.html')

@login_required
@app.route("/index")
def home():
    return render_template('index.html')

def validates(RegisterForm, password):
    p=password.data
    #spec= "!@#$%&_="
    if not any(i.isdigit() for i in p):
        raise ValidationError('Password must contain numbers and letters')
    elif len(p)<6:
        raise ValidationError('Minimum length of password should be 6')

#def valid(RegisterForm, password):
    #sp_cha=('!', '@', '#', '$', '%')
    #for i in password.data:
        #if i not in sp_cha:
            
            #raise ValidationError('sp')


class RegisterForm(Form):    
    name=StringField('Name', [validators.DataRequired(), validators.Length(min=1, max=50)])
    username= StringField('username', [validators.DataRequired(), validators.Length(min=4, max=50)])
    email=StringField('Email', [validators.DataRequired(), validators.Length(min=6, max=100)])
    password= PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match!'),
        validates
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
        budget='1000'
        price=0
        date='2019-05-01'

        cur= mysql.connection.cursor()        
        cur.execute("SELECT * FROM users WHERE email = %s", [email])

        if cur.fetchone() is not None:
            flash("Email Already registered :D, Login to continue", 'danger')
            return redirect(url_for('login'))

        cur.execute("SELECT * FROM users WHERE username = %s", [username])

        if cur.fetchone() is not None:
            flash("Username already taken", 'danger')
        else:
            cur.execute("INSERT INTO users(name, email, username, password, confirm_email, budget) VALUES(%s, %s, %s, %s, %s, %s)", (name, email, username, password, confirm_email, budget))
            cur.execute("insert into record(username, price, date) values(%s, %s, %s)", (username, price, date))
            mysql.connection.commit()
            
            token= s.dumps(email, salt='email-confirm')
            msg=Message('Confirm Email', sender='dbezbaruah412@gmail.com', recipients=[email])
            link=url_for('confirm_email', token=token, _external=True)
            msg.body='Thanks For siging up. Please click on the link to activate your account. The link will be expired in 1 hour. {}'.format(link)
            mail.send(msg)
        
            flash('Thank you for signing up. Please check your email inbox to activate your account', 'success')
            return redirect(url_for('login'))
        cur.close()        
    return render_template('register.html', form=form)


@app.route('/confirm_email/<token>')

def confirm_email(token):
    try:
        email=s.loads(token, salt='email-confirm', max_age=3600)
    except SignatureExpired:
        return 'Your Link is Expired'
    cur=mysql.connection.cursor()
    result=cur.execute("SELECT * FROM users where confirm_email= %s", [confirm_email])
    
    #cur.close()
    if result>0:
        return 'confirmed'
    else:
        cur=mysql.connection.cursor()
        cur.execute("UPDATE users SET confirm_email='1' where email=%s", [email])
        mysql.connection.commit()
        cur.close()
        flash('Email confirmed! You can now login.', 'success')
    return redirect(url_for('login'))

####LOGINNNN

class LoginForm(Form):
    usernamelogin=StringField('Username/Email', [validators.Length(min=1, max=50)])
    passwordlogin=PasswordField('Password', [validators.DataRequired(), validators.Length(min=3, max=100)])


@app.route('/login', methods=['GET', 'POST'])

def login():

    


    formlogin=LoginForm(request.form)
    if request.method=='POST' and formlogin.validate():
        usernamelogin=formlogin.usernamelogin.data
        emaillogin=formlogin.usernamelogin.data
        passwordlogin=formlogin.passwordlogin.data

        cur=mysql.connection.cursor()
        result=cur.execute("SELECT * FROM users where username= %s", [usernamelogin])
        #result2=cur.execute("SELECT * FROM users where email=%s", [usernamelogin])
        if result>0:
            data = cur.fetchone()
            password= data['password']

            if sha256_crypt.verify(passwordlogin, password) and  (cur.execute("SELECT * FROM users where confirm_email='1' and password=%s", [password])):
                session['logged_in']= True
                session['username']= usernamelogin
                cur.execute("SELECT email FROM users where username= %s",[session['username']] )
                res=cur.fetchone()
                email=res['email']
                session['email']= email
                
                flash('you are now logged in', 'success')
                return redirect(url_for('dashboard'))
            elif sha256_crypt.verify(passwordlogin, password) and  (cur.execute("SELECT * FROM users where confirm_email='0'  and password=%s", [password])):
                session['logged_in']= False
                session.clear()
                return redirect(url_for('unconfirmed'))

            else:
                flash("Password didnot match", 'danger')
                return redirect(url_for('login'))
            return redirect(url_for('login'))
        elif (cur.execute("SELECT * FROM users where email=%s", [emaillogin]))>0:
        
            data = cur.fetchone()
            password= data['password']

            if sha256_crypt.verify(passwordlogin, password) and  (cur.execute("SELECT * FROM users where confirm_email='1' and password=%s", [password])):
                session['logged_in']= True
                #session['username']= usernamelogin
                session['email'] = emaillogin

                cur.execute("SELECT username FROM users where email= %s",[session['email']] )
                res=cur.fetchone()
                username=res['username']
                session['username']= username

                


                flash('you are now logged in', 'success')
                return redirect(url_for('dashboard'))
            elif sha256_crypt.verify(passwordlogin, password) and  (cur.execute("SELECT * FROM users where confirm_email='0'  and password=%s", [password])):
                #flash("confirm email first")
                session['logged_in']= False
                session.clear()
                return redirect(url_for('unconfirmed'))

            else:
                flash("Password didnot match", 'danger')
                return redirect(url_for('login'))
        #a="admin"
        #b="password"
        elif usernamelogin=='admin' and passwordlogin=='password':
            session['adminlogin']= True
            return redirect(url_for('admin'))



        else:
            flash('Username not found', 'danger')
            return redirect(url_for('login'))

        
        

        cur.close()
    else:
        #flash('Username not found', 'danger')
        return render_template('login.html', formlogin=formlogin)

        


    #return render_template('login.html', formlogin=formlogin)

@app.route("/logout")
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))

@app.route('/unconfirmed')
def unconfirmed():
    return render_template('unconfirmed.html')

##Forget_Password

class forget_form(Form):
    email=StringField('',[validators.DataRequired(), validators.Length(min=4, max=30)])

@app.route("/forget_password", methods=['GET', 'POST'])
def forget_password():
    formforget=forget_form(request.form)
    if request.method=='POST' and formforget.validate():
        emailforget=formforget.email.data
        cur= mysql.connection.cursor()
        
        cur.execute("SELECT * FROM users WHERE email = %s", [emailforget])
        if cur.fetchone() is not None:
            tokenforget= s.dumps(emailforget, salt='forget_pass')
            msg1=Message('Reset Password', sender='dbezbaruah412@gmail.com', recipients=[emailforget])
            link1=url_for('reset_password', tokenforget=tokenforget, _external=True)
            msg1.body='Please click in the link below to reset your password {}'.format(link1)
            mail.send(msg1)
        flash('Password reset link has been sent to your registered email', 'success')
        return redirect(url_for('forget_password'))

    return render_template('forget_password.html', formforget=formforget)


class resetform(Form):
    password=PasswordField('New password', [validators.DataRequired(), validators.Length(min=4, max=44)])


@app.route("/reset_password/<tokenforget>", methods=['GET', 'POST'])
def reset_password(tokenforget):
    formreset=resetform(request.form)
    if request.method=='POST' and formreset.validate():
        password= sha256_crypt.encrypt(str(formreset.password.data))
        try:
            email=s.loads(tokenforget, salt='forget_pass', max_age=3600)
            cur=mysql.connection.cursor()
            cur.execute("SELECT * FROM users WHERE email=%s", [email])
            if cur.fetchone() is not None:
                cur.execute("UPDATE users SET password=%s where email=%s", [password, email])
                mysql.connection.commit()
                flash('password updated', 'success')
            return redirect(url_for('login'))
        
        except SignatureExpired:
            return 'Token Expired'


    #password= formreset.newpassword.data
    
    return render_template('reset_password.html', formreset=formreset)

#Dashboard
class DateForm(Form):
    dt = DateField('date', format='%Y-%m-%d')

@app.route('/dashboard', methods=['POST','GET'])
@login_required
def dashboard():
    today = (datetime.now() - timedelta(0)).strftime('%Y-%m-%d')
    yesterday= (datetime.now() - timedelta(1)).strftime('%Y-%m-%d')
    yesterday1= (datetime.now() - timedelta(2)).strftime('%Y-%m-%d')
    yesterday2= (datetime.now() - timedelta(3)).strftime('%Y-%m-%d')
    yesterday3= (datetime.now() - timedelta(4)).strftime('%Y-%m-%d')
    yesterday4= (datetime.now() - timedelta(5)).strftime('%Y-%m-%d')
    yesterday5= (datetime.now() - timedelta(6)).strftime('%Y-%m-%d')
    yesterday6= (datetime.now() - timedelta(7)).strftime('%Y-%m-%d')
    yesterday7= (datetime.now() - timedelta(8)).strftime('%Y-%m-%d')
    yesterday8= (datetime.now() - timedelta(9)).strftime('%Y-%m-%d')

    cur=mysql.connection.cursor()
    cur.execute("select daily from record where date = CURDATE() and username=%s", [session['username']] )
    res1=cur.fetchone()
    if res1 is not None:
        res1=res1['daily']
    else:
        res1='0'

    cur.execute("select daily from record WHERE DATE(date) = SUBDATE(CURRENT_DATE(), INTERVAL 1 DAY) and username=%s", [session['username']] )
    res2=cur.fetchone()
    if res2 is not None:
        res2=res2['daily']
    else:
        res2='0'

    cur.execute("select daily from record WHERE DATE(date) = SUBDATE(CURRENT_DATE(), INTERVAL 2 DAY) and username=%s", [session['username']] )
    res3=cur.fetchone()
    if res3 is not None:
        res3=res3['daily']
    else:
        res3='0'

    cur.execute("select daily from record WHERE DATE(date) = SUBDATE(CURRENT_DATE(), INTERVAL 3 DAY) and username=%s", [session['username']] )
    res4=cur.fetchone()
    if res4 is not None:
        res4=res4['daily']
    else:
        res4='0'

    cur.execute("select daily from record WHERE DATE(date) = SUBDATE(CURRENT_DATE(), INTERVAL 4 DAY) and username=%s", [session['username']] )
    res5=cur.fetchone()
    if res5 is not None:
        res5=res5['daily']
    else:
        res5="0"

    cur.execute("select daily from record WHERE DATE(date) = SUBDATE(CURRENT_DATE(), INTERVAL 5 DAY) and username=%s", [session['username']] )
    res6=cur.fetchone()
    if res6 is not None:
        res6=res6['daily']
    else:
        res6="0"

    cur.execute("select daily from record WHERE DATE(date) = SUBDATE(CURRENT_DATE(), INTERVAL 6 DAY) and username=%s", [session['username']] )
    res7=cur.fetchone()
    if res7 is not None:
        res7=res7['daily']
    else:
        res7="0"

    cur.execute("select daily from record WHERE DATE(date) = SUBDATE(CURRENT_DATE(), INTERVAL 7 DAY) and username=%s", [session['username']] )
    res8=cur.fetchone()
    if res8 is not None:
        res8=res8['daily']
    else:
        res8='0'

    cur.execute("select daily from record WHERE DATE(date) = SUBDATE(CURRENT_DATE(), INTERVAL 8 DAY) and username=%s", [session['username']] )
    res9=cur.fetchone()
    if res9 is not None:
        res9=res9['daily']
    else:
        res9='0'

    cur.execute("select daily from record WHERE DATE(date) = SUBDATE(CURRENT_DATE(), INTERVAL 9 DAY) and username=%s", [session['username']] )
    res10=cur.fetchone()
    if res10 is not None:
        res10=res10['daily']
    else:
        res10="0"


    labels = [
        yesterday8, yesterday7,
        yesterday6, yesterday5, yesterday4, yesterday3,
        yesterday2, yesterday1, yesterday, today
    ]

    values = [
        res10, res9,
        res8, res7, res6, res5,
        res4, res3, res2, res1
    ]

    colors = [
        "#F7464A", "#46BFBD", "#FDB45C", "#FEDCBA",
        "#ABCDEF", "#DDDDDD", "#ABCABC", "#4169E1",
        "#C71585", "#FF4500", "#FEDCBA", "#46BFBD"]



    line_labels=labels
    line_values=values

    formdate=DateForm(request.form)
    cur=mysql.connection.cursor()
    cur.execute("SELECT budget FROM users where username= %s",[session['username']])
    res=cur.fetchone()
    if res is not None:
        budget=res['budget']
        session['budget']= budget
    else:
        session['budget']=0
    #cur.execute("SELECT spent FROM users where username= %s order by id asc limit 1",[session['username']])
    #res1=cur.fetchone()
    #if res1 is not None:
    #    spent= res1['spent']
    #    session['spent']= spent
    #else:
    #    session['spent']='0'
    
    #Need more work
    cur.execute("SELECT sum(price) AS total FROM record WHERE MONTH(date)=MONTH(CURDATE()) and username=%s", [session['username']])
    res=cur.fetchone()
    if res is not None:
        result1=res['total']
    else:
        result1=0


    mesg_warn=" "
    

    cur.execute("SELECT item, COUNT(item) AS popularity FROM record WHERE date >= NOW() + INTERVAL -7 DAY AND date <  NOW() + INTERVAL  0 DAY and username=%s GROUP BY item ORDER BY popularity DESC limit 1", [session['username']])
    resitem=cur.fetchone()
    if resitem is not None:
        session['item']=resitem['item']
    else:
        session['item']='None'

    cur.execute("select item, COUNT(item) AS popularity from record where username=%s GROUP BY item ORDER BY popularity DESC limit 1", [session['username']])
    resall=cur.fetchone()
    if resall is not None:
        session['allitem']=resall['item']
    else:
        session['item']='None'

    session['money_left']=int(session['budget'])-int(result1)
    if session['money_left']<500:
        mesg_warn="Your Budget is getting exhausted. Please spend accordingly"
        #flash("Your Budget is ver low")
    
    cur = mysql.connection.cursor()
    resultValue = cur.execute("SELECT * FROM record WHERE date = CURDATE() and username=%s", [session['username']])
    if resultValue > -1:
        datas = cur.fetchall()
    
    
#today's total
    
    

    

    
    #session['today']=cur.fetchone()

    if request.method=='POST':
        
        
        date=request.form['pick']
        place=request.form['location']

        name=request.form['itemname']
        
        quant=request.form['quant']
        total=request.form['total']
        oneprice=request.form['price']
        comment=request.form['comment']

        
        #then = dt.strftime('%Y-%m-%d %H-%M-%S')
        #then=str(dt)
        #formatted_date = dt.strftime('%Y-%m-%d')

        cur=mysql.connection.cursor()
        cur.execute("INSERT INTO record (date, username, item, quantity, oneprice, price, place, comment) VALUES(%s, %s, %s, %s, %s, %s, %s, %s)", (date, session['username'], name, quant, oneprice, total, place, comment))
        mysql.connection.commit()

        cur=mysql.connection.cursor()
        cur.execute("select price from record where username=%s ORDER BY id DESC LIMIT 1", [session['username']])
        res=cur.fetchone()
        if res is not None:
            res1=res['price']
            res12=int(res1)
        else:
            res12=0
        #res1=int(res)
        cur.execute("select spent from record where username=%s", [session['username']])
        res2=cur.fetchone()
        if res2 is not None:
            res3=res2['spent']
            res32=int(res3)
        else:
            res32=0
        #res3=int(res2)
        resfinal=(res12+res32)

        cur.execute("select daily from record where username=%s and date= CURDATE()", [session['username']])
        restoday=cur.fetchone()
        if restoday is not None:
            restoday1=restoday['daily']
            restoday12=int(restoday1)
        else:
            restoday12=0

        todayfinal=(restoday12+res12)
        
        cur.execute("UPDATE record SET daily=%s where date = CURDATE() and username=%s", [todayfinal, session['username']])
        mysql.connection.commit()

        cur.execute("UPDATE record SET spent=%s where username=%s", [resfinal, session['username']])
        mysql.connection.commit()
        flash('Record updated!', 'success')

        return redirect(url_for('dashboard'))

        #cur.close()
    
    #return render_template('analysis.html', max=3000, colors=colors, labels=line_labels, values=line_values)
         

    return render_template('dashboard.html', res1=res1, max=3000, colors=colors, labels=line_labels, values=line_values, formdate=formdate, mesg_warn=mesg_warn, datas=datas, result1=result1)


##Record Detail

class inputform(Form):
    myChoices =[('today', 'Today'), ('lastweek', 'Last 7 days'), ('month', 'Last 30 days')]
    myField = SelectField(u'Field name', choices = myChoices)

@app.route("/record", methods=['GET', 'POST'])
@login_required
def record():
    
    #flash("Record Has Been Deleted Successfully")
    date_select=inputform(request.form)
    cur = mysql.connection.cursor()
    cur.execute("SELECT sum(price) AS totalsum FROM record WHERE date = CURDATE() and username=%s", [session['username']])
    res=cur.fetchone()
    result=res['totalsum']


    resultValue = cur.execute("SELECT * FROM record WHERE date = CURDATE() and username=%s", [session['username']])
    if resultValue > -1:
        datas = cur.fetchall()
    return render_template('records.html', datas=datas, date_select=date_select, result=result)

@app.route("/week_record", methods=['GET', 'POST'])
@login_required
def week_record():
    #flash("Record Has Been Deleted Successfully")
    date_select=inputform(request.form)
    cur = mysql.connection.cursor()
    cur.execute("SELECT sum(price) AS totalsum FROM record WHERE date >= NOW() + INTERVAL -7 DAY AND date <  NOW() + INTERVAL  0 DAY and username=%s", [session['username']])
    res=cur.fetchone()
    result=res['totalsum']


    resultValue = cur.execute("SELECT * FROM record WHERE date >= NOW() + INTERVAL -7 DAY AND date <  NOW() + INTERVAL  0 DAY and username=%s", [session['username']])
    if resultValue > -1:
        datas = cur.fetchall()
    return render_template('week_records.html', datas=datas, date_select=date_select, result=result)


@app.route("/month_record", methods=['GET', 'POST'])
@login_required
def month_record():
    #flash("Record Has Been Deleted Successfully")
    date_select=inputform(request.form)
    cur = mysql.connection.cursor()
    cur.execute("SELECT sum(price) AS totalsum FROM record WHERE date >= NOW() + INTERVAL -30 DAY AND date <  NOW() + INTERVAL  0 DAY and username=%s", [session['username']])
    res=cur.fetchone()
    result=res['totalsum']

    resultValue = cur.execute("SELECT * FROM record WHERE date >= NOW() + INTERVAL -30 DAY AND date <  NOW() + INTERVAL  0 DAY and username=%s", [session['username']])
    if resultValue > -1:
        datas = cur.fetchall()
    return render_template('month_records.html', datas=datas, date_select=date_select, result=result)


@app.route("/all_record", methods=['GET', 'POST'])
@login_required
def all_record():
    
    


    
    cur = mysql.connection.cursor()
    cur.execute("SELECT sum(price) AS totalsum FROM record WHERE username=%s", [session['username']])
    res=cur.fetchone()
    result=res['totalsum']
    
    #result=row['price']
    #result= res.values()

    #result=sum(result)
    
    
    #result=result[0]
    #flash("Record Has Been Deleted Successfully")
    date_select=inputform(request.form)
    
    resultValue = cur.execute("SELECT * FROM record where username=%s", [session['username']])
    if resultValue > -1:
        datas = cur.fetchall()
    return render_template('all_records.html', datas=datas, date_select=date_select, result=result)

@app.route('/delete/<string:id>', methods = ['GET'])
@login_required
def delete(id):
    
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM record WHERE id=%s", (id,))
    mysql.connection.commit()
    flash("Record Has Been Deleted Successfully")
    return redirect(url_for('record'))

#User Profile
def validates_budget():
    p=budget.data
    #spec= "!@#$%&_="
    if not any(i.isdigit() for i in p):
        raise ValidationError('Password must contain numbers and letters')


class userprofile(Form):
    name=StringField('Name', [validators.DataRequired(), validators.Length(min=1, max=50)])
    username= StringField('username', [validators.DataRequired(), validators.Length(min=4, max=50)])
    email=StringField('Email', [validators.DataRequired(), validators.Length(min=6, max=100)])

class profile_pic(Form):
    picture = FileField('Update Profile Picture', validators=[FileAllowed(['jpg', 'png'])])
    #submit = SubmitField('Update')
class sidebar_form(Form):
    budget=StringField('', [validators.DataRequired()], render_kw={"placeholder": "eg. 5,000"})


UPLOAD_FOLDER = 'static\\profile_pic'
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS



@app.route('/profile', methods=['POST','GET'])
@login_required
def profile():
   
    cur=mysql.connection.cursor()
    

    

    cur.execute("SELECT name FROM users where email= %s",[session['email']] )
    res=cur.fetchone()
    name=res['name']
    

    uprofile=userprofile(request.form)
    dpform=profile_pic(request.form)
    sidebar=sidebar_form(request.form)

    uprofile.email.data = session['email']
    uprofile.username.data = session['username']
    uprofile.name.data = name
    mysql.connection.commit()
    cur.execute("SELECT dp FROM users where username= %s",[session['username']] )
    res=cur.fetchone()
    dp=res['dp']
    session['dp']= dp

    if request.method=='POST':
        
        
        uprofile.email.data = session['email']
        uprofile.username.data = session['username']
        uprofile.name.data = name
        
        if "btn1" in request.form:
            # check if the post request has the file part
            if 'file' not in request.files:
                flash('No file ')
                return redirect(request.url)
            file = request.files['file']
            # if user does not select file, browser also
            # submit a empty part without filename
            if file.filename == '':
                flash('No selected file')
                return redirect(request.url)
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                cur=mysql.connection.cursor()
                cur.execute("UPDATE users SET dp=%s where username=%s", [filename, session['username']])
                mysql.connection.commit()
                cur.execute("SELECT dp FROM users where username= %s",[session['username']] )
                res=cur.fetchone()
                dp=res['dp']
                session['dp']= dp
            if file and not allowed_file(file.filename):
                flash('invalid image file')
        session['dp']= dp
        if request.method=='POST':

            if "btn" in request.form:
                uprofile.email.data = session['email']
                uprofile.username.data = session['username']
                uprofile.name.data = name
                
                budget=sidebar.budget.data
                #budget=str(budget)
                cur=mysql.connection.cursor()
                cur.execute("UPDATE users SET budget=%s where username=%s", [budget, session['username']])
                mysql.connection.commit()
                cur.execute("SELECT budget FROM users where username= %s",[session['username']])
                res=cur.fetchone()
                if res is not None:
                    budget=res['budget']
                    session['budget']= budget
                else:
                    session['budget']=0
            return redirect(url_for('profile'))

            #return redirect(url_for('uploaded_file',
                                    #filename=filename))
        if request.method=='GET':
            uprofile.email.data = session['email']
            uprofile.username.data = session['username']
            uprofile.name.data = name
            cur.execute("SELECT dp FROM users where username= %s",[session['username']] )
            res=cur.fetchone()
            dp=res['dp']
            session['dp']= dp
            dpform.picture.data=session['dp']
        

    
        

       
        
    #profile_image = url_for('static', filename='profile_pic/'+ str(cur.execute("SELECT dp FROM users WHERE email=%s", [session['username']])))
    return render_template('userprofile.html', uprofile=uprofile, dpform=dpform, sidebar=sidebar)

##ANALYSIS

@app.route('/line')
def line():
    
    today = str(date.today())
    yesterday= (datetime.now() - timedelta(1)).strftime('%Y-%m-%d')
    yesterday1= (datetime.now() - timedelta(2)).strftime('%Y-%m-%d')
    yesterday2= (datetime.now() - timedelta(3)).strftime('%Y-%m-%d')
    yesterday3= (datetime.now() - timedelta(4)).strftime('%Y-%m-%d')
    yesterday4= (datetime.now() - timedelta(5)).strftime('%Y-%m-%d')
    yesterday5= (datetime.now() - timedelta(6)).strftime('%Y-%m-%d')
    yesterday6= (datetime.now() - timedelta(7)).strftime('%Y-%m-%d')
    yesterday7= (datetime.now() - timedelta(8)).strftime('%Y-%m-%d')
    yesterday8= (datetime.now() - timedelta(9)).strftime('%Y-%m-%d')

    cur=mysql.connection.cursor()
    cur.execute("select daily from record where date = CURDATE() and username=%s", [session['username']] )
    res1=cur.fetchone()
    if res1 is not None:
        res1=res1['daily']
    else:
        res1='0'

    cur.execute("select daily from record WHERE DATE(date) = SUBDATE(CURRENT_DATE(), INTERVAL 1 DAY) and username=%s", [session['username']] )
    res2=cur.fetchone()
    if res2 is not None:
        res2=res2['daily']
    else:
        res2='0'

    cur.execute("select daily from record WHERE DATE(date) = SUBDATE(CURRENT_DATE(), INTERVAL 2 DAY) and username=%s", [session['username']] )
    res3=cur.fetchone()
    if res3 is not None:
        res3=res3['daily']
    else:
        res3='0'

    cur.execute("select daily from record WHERE DATE(date) = SUBDATE(CURRENT_DATE(), INTERVAL 3 DAY) and username=%s", [session['username']] )
    res4=cur.fetchone()
    if res4 is not None:
        res4=res4['daily']
    else:
        res4='0'

    cur.execute("select daily from record WHERE DATE(date) = SUBDATE(CURRENT_DATE(), INTERVAL 4 DAY) and username=%s", [session['username']] )
    res5=cur.fetchone()
    if res5 is not None:
        res5=res5['daily']
    else:
        res5="0"

    cur.execute("select daily from record WHERE DATE(date) = SUBDATE(CURRENT_DATE(), INTERVAL 5 DAY) and username=%s", [session['username']] )
    res6=cur.fetchone()
    if res6 is not None:
        res6=res6['daily']
    else:
        res6="0"

    cur.execute("select daily from record WHERE DATE(date) = SUBDATE(CURRENT_DATE(), INTERVAL 6 DAY) and username=%s", [session['username']] )
    res7=cur.fetchone()
    if res7 is not None:
        res7=res7['daily']
    else:
        res7="0"

    cur.execute("select daily from record WHERE DATE(date) = SUBDATE(CURRENT_DATE(), INTERVAL 7 DAY) and username=%s", [session['username']] )
    res8=cur.fetchone()
    if res8 is not None:
        res8=res8['daily']
    else:
        res8='0'

    cur.execute("select daily from record WHERE DATE(date) = SUBDATE(CURRENT_DATE(), INTERVAL 8 DAY) and username=%s", [session['username']] )
    res9=cur.fetchone()
    if res9 is not None:
        res9=res9['daily']
    else:
        res9='0'

    cur.execute("select daily from record WHERE DATE(date) = SUBDATE(CURRENT_DATE(), INTERVAL 9 DAY) and username=%s", [session['username']] )
    res10=cur.fetchone()
    if res10 is not None:
        res10=res10['daily']
    else:
        res10="0"


    labels = [
        yesterday8, yesterday7,
        yesterday6, yesterday5, yesterday4, yesterday3,
        yesterday2, yesterday1, yesterday, today
    ]

    values = [
        res10, res9,
        res8, res7, res6, res5,
        res4, res3, res2, res1
    ]

    colors = [
        "#F7464A", "#46BFBD", "#FDB45C", "#FEDCBA",
        "#ABCDEF", "#DDDDDD", "#ABCABC", "#4169E1",
        "#C71585", "#FF4500", "#FEDCBA", "#46BFBD"]



    line_labels=labels
    line_values=values
    return render_template('analysis.html', max=3000, set=zip(values, labels, colors))
     
@app.route("/admin", methods=['GET', 'POST'])
@admin_login
def admin():
    return render_template('admin.html')

@app.route("/feedback", methods=['GET', 'POST'])
@login_required
def feedback():
    
    if request.method=='POST':
        
        message=request.form['message']
        name=request.form['fname']
        cur= mysql.connection.cursor()
        cur.execute("INSERT INTO feedback(username, message, name) VALUES(%s, %s, %s)", (session['username'], message, name))
        mysql.connection.commit()
        flash('Feedback Sent. Will get back to you soon!', 'success')
        
        cur.close()
        

        email=session['email']

        msg=Message('Help Desk @DEMS', sender='dbezbaruah412@gmail.com', recipients=[email])
        #link=url_for('confirm_email', token=token, _external=True)
        msg.body="Hi, Thank you for contacting us. We will get back to you within 2 working days.          This is an automaticially generated email. Please don't reply."
        mail.send(msg)
        return redirect(url_for('feedback'))
    
            
           
        
    return render_template('feedback.html')

@app.route("/fb_details", methods=['GET', 'POST'])
@admin_login
def fb_details():
    
    cur = mysql.connection.cursor()
    resultValue = cur.execute("SELECT * FROM feedback")
    if resultValue > -1:
        datas = cur.fetchall()
        
        
        
    
    return render_template('fb_details.html', datas=datas)


class ReplyForm(Form):
    username=StringField('Username', [validators.Length(min=1, max=50)])
    message=TextAreaField('Text', [validators.DataRequired()], render_kw={"rows": 10, "cols": 11})


@app.route('/reply/<string:id>', methods = ['GET', 'POST'])
@admin_login
def reply(id):
    
    cur = mysql.connection.cursor()
    res=cur.execute("SELECT * FROM feedback where id=%s", [id])
    res=cur.fetchone()
    formreply=ReplyForm(request.form)
    formreply.username.data=res['username']
    

    if request.method=='POST' and formreply.validate():
        username=formreply.username.data
        message=formreply.message.data
        cur= mysql.connection.cursor()
        cur.execute("INSERT INTO reply(username, reply)VALUES(%s, %s)", (username, message))
        mysql.connection.commit()
        cur.close()

        cur1= mysql.connection.cursor()
        cur1.execute('select email from users where username=%s', [res['username']])
        res1=cur1.fetchone()
        email=res1['email']

        msg=Message('Help Desk @DEMS', sender='dbezbaruah412@gmail.com', recipients=[email])
        #link=url_for('confirm_email', token=token, _external=True)
        msg.body=message
        mail.send(msg)
        flash('Reply sent!', 'success')
    return render_template('reply_feed.html', formreply=formreply)
    



@app.route('/messages', methods=['GET', 'POST'])
@login_required
def messages():
        
        cur = mysql.connection.cursor()
        cur.execute("SELECT message FROM feedback Where username = %s", [session['username']])
        
        data = cur.fetchall()
        if data is not None:
            for row in data:
                data=row['message']

        cur.execute("SELECT reply FROM reply Where username = %s", [session['username']])
        datas = cur.fetchall()
        
        for mesg in datas:
            if datas is not None:
                datas=mesg['reply']
            else:
                datas="No Message"
        return render_template('messages.html', data=data , datas=datas)





######TESTING BELOW-----DONT GO######
    


def upload_file():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        # if user does not select file, browser also
        # submit a empty part without filename
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))


@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        # if user does not select file, browser also
        # submit a empty part without filename
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            return redirect(url_for('uploaded_file',
                                    filename=filename))
    return render_template('upload.html')





@app.route('/user_details')
@admin_login
def user_details():
    cur=mysql.connection.cursor()
    cur.execute("select * from users")
    datas = cur.fetchall()
    
    #nn=name["nn"]
    #for column in data:
         #name=("select name from users")

    return render_template('user_details.html', datas=datas)



    '''
    <!doctype html>
    <title>Upload new File</title>
    <h1>Upload new File</h1>
    <form method=post enctype=multipart/form-data>
      <p><input type=file name=file>
         <input type=submit value=Upload>
    </form>'''


from flask import send_from_directory

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'],
                               filename)

####END of TESTING####

if __name__ == "__main__":
    app.secret_key='secret123'
    app.run(debug=True)

    