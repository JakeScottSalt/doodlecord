from flask import Flask, render_template, redirect, url_for, request
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, HiddenField
from wtforms.validators import InputRequired, Email, Length, EqualTo
from wtforms.widgets import TextArea
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_socketio import SocketIO, send, emit

app = Flask(__name__)
app.config['SECRET_KEY'] = ' '
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///doodlecord.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = 'false'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
socketio = SocketIO(app)

class usrs(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    usrType = db.Column(db.Integer, default=0)
    usrnm = db.Column(db.String(255), nullable=False, unique=True)
    fName = db.Column(db.String(255), nullable=False)
    sName = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=False, unique=True)
    pswd = db.Column(db.String(255), nullable=False)
    created = db.Column(db.DateTime, default=datetime.utcnow)
    courseId = db.Column(db.Integer)
    sessionId = db.Column(db.Integer)

@login_manager.user_loader
def load_user(usr_id):
    return usrs.query.get(int(usr_id))

class pswdReset(db.Model):
    pswdResetId = db.Column(db.Integer, primary_key=True)
    pswdResetEmail = db.Column(db.String(255), nullable=False)
    pswdResetSelector = db.Column(db.String(255), nullable=False)
    pswdResetToken = db.Column(db.String(255), nullable=False)
    pswdResetExpires = db.Column(db.DateTime, default=datetime.now)

class courseInfo(db.Model):
    courseId = db.Column(db.Integer, primary_key=True)
    courseName = db.Column(db.String(255), nullable=False)
    courseSubjects = db.Column(db.String(255), nullable=False)
    subjectIds = db.Column(db.Integer)

class ucos(db.Model):
    postId = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(255), nullable=False)
    post = db.Column(db.String(255), nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)

class awt(db.Model):
    postId = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(255), nullable=False)
    post = db.Column(db.String(255), nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)

class LoginForm(FlaskForm):
    usrnm = StringField('usrnm', validators=[InputRequired()])
    pswd = PasswordField('pswd', validators=[InputRequired(), Length(min=8, max=80)])

class registerForm(FlaskForm):
    usrnm = StringField('usrnm', validators=[InputRequired()])
    fName = StringField('fName', validators=[InputRequired()])
    sName = StringField('sName', validators=[InputRequired()])
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid Email')])
    pswd =  PasswordField('pswd', validators=[InputRequired(), Length(min=8, max=80), EqualTo('confPswd', message='Passwords don\'t match')])
    confPswd = PasswordField('confPswd', validators=[InputRequired(), Length(min=8, max=80)])

class forumPost(FlaskForm):
    fName = HiddenField('fName', validators=[InputRequired()])
    post = StringField('post',widget=TextArea(), validators=[InputRequired()])

@socketio.on('chat_message')
def chat_message(message):
    socketio.emit('chat_reply', message)
    
@app.route('/')
@login_required
def root():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        usr=usrs.query.filter_by(usrnm=form.usrnm.data).first()
        if usr:
            if check_password_hash(usr.pswd, form.pswd.data):
                login_user(usr)
                return redirect(url_for('root'))
            else:
                return '<h1> Your password is incorrect!</h1>'

        return '<h1> Sorry, we were unable to find an account with that username</h1>'

    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = registerForm()
    if form.validate_on_submit():
        # return '<h1> Valid</h1>'
        hashedPswd = generate_password_hash(form.pswd.data, method='sha256')
        newUsr = usrs(usrnm=form.usrnm.data, fName=form.fName.data, sName=form.sName.data, email=form.email.data, pswd=hashedPswd)
        db.session.add(newUsr)
        db.session.commit()

        return '<h1> Account Created!</h1>'

    return render_template('createAcc.html', form=form)

@app.route('/classes')
@login_required
def classes():
    return render_template('classList.html')
@app.route('/messages')
@login_required
def messages():
    # if form.validate_on_submit():
        # msgUpdate = messages(chatname = form.chatName.data, usrs = form.usrnm.data, messages = form.msgIn.data)
        # db.session.add(msgUpdate)
        # db.session.commit()

    return render_template('chat.html')
# , name=current_user.fName.sName

@app.route('/ucosBlog', methods=['GET', 'POST'])
@login_required
def ucosBlog():
    form = forumPost()
    posts = ucos.query.first()
    if request.method == 'POST':
        if form.validate():
            posts.post = form.post.data

            db.session.commit()
        else:
            print(form.errors)
            return 'failed'

    return render_template('ucosBlog.html', form=form, ucos=posts)

@app.route('/awtBlog', methods=['GET', 'POST'])
@login_required
def awtBlog():
    form = forumPost()
    posts = awt.query.first()
    if request.method == 'POST':
        if form.validate():
            posts.post = form.post.data

            db.session.commit()
        else:
            print(form.errors)
            return 'failed'

    return render_template('awtBlog.html', form=form, awt=posts)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=True)