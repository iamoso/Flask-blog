import os
import sqlite3
import bcrypt
from flask import Flask, request, session, g, redirect, url_for, abort, \
    render_template, flash


app = Flask(__name__)
app.config.from_object(__name__)


def connect_db():
    """Connects to the specific database"""
    rv = sqlite3.connect(app.config['DATABASE'])
    rv.row_factory = sqlite3.Row
    return rv


def get_db():
    """Opens a new database connection if there is none yet for the
    current application context.
    """
    if not hasattr(g, 'sqlite_db'):
        g.sqlite_db = connect_db()
    return g.sqlite_db


@app.teardown_appcontext
def close_db(error):
    """Closes the database again at the end of the request"""
    if hasattr(g, 'sqlite_db'):
        g.sqlite_db.close()


def init_db():
    db = get_db()
    password = bcrypt.hashpw(b'adminpass', bcrypt.gensalt())
    with app.open_resource('schema.sql', mode='r') as f:
        db.cursor().executescript(f.read())
    # db_command = "insert into users (username, password) values ('admin', {})".format(password.decode())
    db.execute("insert into users (username, password) values ('admin', ?)", [password])
    db.commit()


@app.cli.command('initdb')
def initdb_command():
    """Initializes the database"""
    init_db()
    print('Initialized the database.')


@app.route('/')
def show_entries():
    db = get_db()
    cur = db.execute('select title, text from entries order by id desc')
    entries = cur.fetchall()
    return render_template('show_entries.html', entries=entries)


@app.route('/add', methods=['POST'])
def add_entry():
    if not session.get('logged_in'):
        abort(401)
    db = get_db()
    db.execute('insert into entries (title, text) values (?, ?)',
                [request.form['title'], request.form['text']])
    db.commit()
    flash('New entry was succesfully posted')
    return redirect(url_for('show_entries'))


@app.route('/search', methods=['GET', 'POST'])
def search():
    if request.method == 'POST':
        db = get_db()
        cur = db.execute('select title, text from entries where title like ?', ['%' + request.form['search'] + '%'])
        entries = cur.fetchall()
        return render_template('search.html', entries=entries)
    return redirect(url_for('show_entries'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        db = get_db()
        cur = db.execute('select username, password from users order by id desc')
        users = cur.fetchall()
        print(users[0][0])
        print(type(users[0]))
        for user in users:
            if request.form['username'] == user[0]:
                if bcrypt.checkpw(request.form['password'].encode(), user[1].encode()):
                    session['logged_in'] = True
                    flash('You were logged in')
                    return redirect(url_for('show_entries'))
        error = 'Invalid user data'
    return render_template('login.html', error=error)


@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    flash('You were logged out')
    return redirect(url_for('show_entries'))


@app.route('/admin', methods=['GET', 'POST'])
def add_user():
    if not session.get('logged_in'):
        abort(401)

    if request.method == 'POST':
        password = request.form['password'].encode()
        print(password)
        print(type(password))
        password = bcrypt.hashpw(password, bcrypt.gensalt())
        db = get_db()
        db.execute("insert into users (username, password) values (?, ?)", [request.form['username'], password])
        db.commit()
    return render_template('admin.html')

app.config.update(dict(
    DATABASE = os.path.join(app.root_path, 'blog_flask.db'),
    SECRET_KEY = 'development key',
    USERNAME = 'admin',
    PASSWORD = 'default'
))
app.config.from_envvar('FLASKR_SETTINGS', silent=True)
