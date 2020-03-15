import os
from run import app, db
from flask import render_template, flash, redirect, url_for, session, request, logging
# from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps
import sqlite3 as sql
from wtforms.fields.html5 import EmailField

# app.secret_key = os.urandom(24)

# mysql = MySQL()
# app.config['MYSQL_HOST'] = 'localhost'
# app.config['MYSQL_USER'] = 'root'
# app.config['MYSQL_PASSWORD'] = 'Password@123'
# app.config['MYSQL_DB'] = 'chat_db'
# app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

# mysql.init_app(app)

def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, *kwargs)
        else:
            flash('Unauthorized, Please logged in', 'danger')
            return redirect(url_for('login'))
    return wrap

def not_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            flash('Unauthorized, You logged in', 'danger')
            return redirect(url_for('index'))
        else:
            return f(*args, *kwargs)
    return wrap

@app.route('/')
def index():
    return render_template('home.html')

class LoginForm(Form):
    username = StringField('Username', [validators.length(min=1)], render_kw={'autofocus': True})

@app.route('/login', methods=['GET', 'POST'])
@not_logged_in
def login():
    form = LoginForm(request.form)
    if request.method == 'POST' and form.validate():
        username = form.username.data
        password_candidate = request.form['password']
        con = sql.connect("site.db")
        con.row_factory = sql.Row
        curr = con.cursor()
        q = """
        SELECT * FROM users WHERE username=?
        """
        curr.execute(q, (username, ))
        result = curr.fetchall();
        print(result[0][4])
        if len(result) > 0:
            # result = cur.fetchone()
            password = result[0][4]
            uid = result[0][0]
            name = result[0][1]
            if sha256_crypt.verify(password_candidate, password):
                session['logged_in'] = True
                session['uid'] = uid
                session['s_name'] = name
                x = '1'
                conn1 = sql.connect("site.db")
                cur1 = conn1.cursor()
                q = """
                UPDATE users SET online=? WHERE id=?
                """
                cur1.execute(q, (x, uid, ))
                conn1.commit()
                # cur.execute("UPDATE users SET online=%s WHERE id=%s", (x, uid))
                flash('You are now logged in', 'success')
                return redirect(url_for('index'))
            else:
                flash('Incorrect password', 'danger')
                return render_template('login.html', form=form)
        else:
            flash('Username not found', 'danger')
            cur.close()
            return render_template('login.html', form=form)
    return render_template('login.html', form=form)

@app.route('/out')
def logout():
    if 'uid' in session:
        # cur = mysql.connection.cursor()
        uid = session['uid']
        x = '0'
        conn1 = sql.connect("site.db")
        cur1 = conn1.cursor()
        q = """
        UPDATE users SET online=? WHERE id=?
        """
        cur1.execute(q, (x, uid, ))
        conn1.commit()
        # cur.execute("UPDATE users SET online=%s WHERE id=%s", (x, uid))
        session.clear()
        flash('You are logged out', 'success')
        return redirect(url_for('index'))
    return redirect(url_for('login'))

class RegisterForm(Form):
    name = StringField('Name', [validators.length(min=3, max=50)], render_kw={'autofocus': True})
    username = StringField('Username', [validators.length(min=3, max=25)])
    email = EmailField('Email', [validators.DataRequired(), validators.Email(), validators.length(min=4, max=25)])
    password = PasswordField('Password', [validators.length(min=3)])

@app.route('/register', methods=['GET', 'POST'])
@not_logged_in
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))
        conn1 = sql.connect("site.db")
        cur1 = conn1.cursor()
        cur1.execute("INSERT INTO users(name, email, username, password) VALUES(?, ?, ?, ?)",
                    (name, email, username, password))
        conn1.commit()
        # cur = mysql.connection.cursor()
        # cur.execute("INSERT INTO users(name, email, username, password) VALUES(%s, %s, %s, %s)",
                    # (name, email, username, password))
        # mysql.connection.commit()
        # cur.close()
        flash('You are now registered and can login', 'success')
        return redirect(url_for('index'))
    return render_template('register.html', form=form)


class MessageForm(Form):
    body = StringField('', [validators.length(min=1)], render_kw={'autofocus': True})

@app.route('/chatting/<string:id>', methods=['GET', 'POST'])
def chatting(id):
    if 'uid' in session:
        form = MessageForm(request.form)
        con = sql.connect("site.db")
        con.row_factory = sql.Row
        curr = con.cursor()
        q = """
        SELECT * FROM users WHERE id=?
        """
        get_result = curr.execute(q, (id, ))
        l_data = curr.fetchall();
        # cur = mysql.connection.cursor()
        # get_result = cur.execute("SELECT * FROM users WHERE id=%s", [id])
        # l_data = cur.fetchone()
        if len(l_data) > 0:
            session['name'] = l_data[0][1]
            uid = session['uid']
            session['lid'] = id
            if request.method == 'POST' and form.validate():
                txt_body = form.body.data
                conn1 = sql.connect("site.db")
                cur1 = conn1.cursor()
                cur1.execute("INSERT INTO messages(body, msg_by, msg_to) VALUES(?, ?, ?)",
                            (txt_body, id, uid))
                conn1.commit()
                # cur = mysql.connection.cursor()
                # cur.execute("INSERT INTO messages(body, msg_by, msg_to) VALUES(%s, %s, %s)",
                #             (txt_body, id, uid))
                # mysql.connection.commit()
            con = sql.connect("site.db")
            con.row_factory = sql.Row
            curr = con.cursor()
            curr.execute("SELECT * FROM users")
            users = curr.fetchall();
            # cur.execute("SELECT * FROM users")
            # users = cur.fetchall()
            # cur.close()
            return render_template('chat_room.html', users=users, form=form)
        else:
            flash('No permission!', 'danger')
            return redirect(url_for('index'))
    else:
        return redirect(url_for('login'))

@app.route('/chats', methods=['GET', 'POST'])
def chats():
    if 'lid' in session:
        id = session['lid']
        uid = session['uid']
        con = sql.connect("site.db")
        con.row_factory = sql.Row
        curr = con.cursor()
        q = """
        SELECT * FROM messages WHERE (msg_by=? AND msg_to=?) OR (msg_by=? AND msg_to=?) ORDER BY id ASC
        """
        curr.execute(q, (id, uid, uid, id, ))
        chats = curr.fetchall();
        # cur = mysql.connection.cursor()
        # cur.execute("SELECT * FROM messages WHERE (msg_by=%s AND msg_to=%s) OR (msg_by=%s AND msg_to=%s) "
                    # "ORDER BY id ASC", (id, uid, uid, id))
        # chats = cur.fetchall()
        # cur.close()
        return render_template('chats.html', chats=chats,)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)