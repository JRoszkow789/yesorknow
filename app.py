from __future__ import with_statement, division, absolute_import
import sqlite3
from contextlib import closing
from flask import Flask, render_template, request, session, g, redirect
from flask import url_for, abort, flash
from decorators import requires_login
from forms import LoginForm, RegisterForm, AddCategoryForm
from forms import AddQuestionForm, AnswerQuestionForm
from werkzeug import check_password_hash, generate_password_hash
from datetime import datetime, timedelta
from flask_debugtoolbar import DebugToolbarExtension


# Configuration
DATABASE = '/tmp/yn.db'
DEBUG = True
SECRET_KEY = 'dev key yo'
USERNAME = 'admin'
PASSWORD = 'default'


# Create application
app = Flask(__name__)
app.config.from_object(__name__)
toolbar = DebugToolbarExtension(app)


def connect_db():
    '''Returns a connection to the apps database.'''
    return sqlite3.connect(app.config['DATABASE'])


def init_db(pw=''):
    '''Create new database schema with the schema file in the app folder.
    Updated to require password to avoid accidental db resets.
    '''
    if pw != app.config['PASSWORD']:
        return 'ERROR crazy!'
    with closing(connect_db()) as db:
        with app.open_resource('schema.sql') as f:
            db.cursor().executescript(f.read())
        db.commit()


def query_db(query, args=(), one=False):
    ''' Queries the database and returns a list of dictionaries.'''
    cur = g.db.execute(query, args)
    rv = [dict((cur.description[idx][0], value) for idx, value \
          in enumerate(row)) for row in cur.fetchall()]
    return (rv[0] if rv else None) if one else rv


def get_user(username=None, user_id=None):
    '''Return a *safe* user object from the database. A safe user contains 
       harmless information, for extra safety. These items include:
           user_id, user_name, user_role, user_gender.
    '''
    if username is not None:
        return query_db('''select user_id, user_name, user_role, user_gender, 
                           user_join_date from users where user_name = ?''', 
                           [username], one=True)
    elif user_id is not None:
        return query_db('''select user_id, user_name, user_role, user_gender, 
                           user_join_date from users where user_id = ?''', 
                           [user_id], one=True)
    return None


def get_category(categoryname=None, category_id=None):
    '''Helper method to return a category.'''
    if categoryname is not None:
        return query_db('''select category_id, category_name from categories 
                           where category_name = ?''', [categoryname],one=True)
    elif category_id is not None:
        return query_db('''select category_id, category_name from categories 
                           where category_id = ?''', [category_id], one=True) 
    else:
        return None

def categories_list():
    return [(c['category_id'], c['category_name']) for c in query_db('''
             select * from categories''')]


def get_question(question_id):
    '''Returns a useable question object, smaller than the entire tuple the 
       standard query returns. Includes additional useful helper information 
       such as category_name for easier reference and display in jinja. 
       Also contains most needed information including:
       question_id, question_text, category_id, pub_date, and user_id.
    '''
    return query_db('''select question_id, question_text, category_id, 
                       pub_date, user_id from questions where question_id = ?
                    ''', [question_id], one=True)


def format_question(q):
    return dict([('question_id', q['question_id']), 
               ('text', q['question_text']),
               ('asked', get_timelapse_string(q['pub_date'])),
               ('author', get_user(user_id=q['user_id'])['user_name']),
               ('category', get_category(
                            category_id=q['category_id'])['category_name'])]) 
                

def get_answer(answer_id):
    '''Helper method for retrieving an answe object from the database given
       the item's id.  Returns:
           answer_id, answer_choice, question_id, pub_date, user_id
    '''
    return query_db('''select answer_id, answer_choice, question_id, 
                       pub_date, user_id from answers where answer_id = ?''',
                    [answer_id], one=True)


def get_answer_count(question_id):
    ans = query_db('''select * from answers where question_id = ?''', 
        [question_id])
    y_count = 0
    n_count = 0
    for a in ans:
        if a['answer_choice'] == 1:
            y_count += 1
        else:
            n_count += 1
    return (n_count, y_count)


def format_datetime(dt):
    '''Format a raw datetime for display.'''
    return datetime.strftime('%Y-%m-%d @ %H:%M')


def datetime_from_string(s):
    return datetime.strptime(s, '%Y-%m-%d %H:%M:%S.%f')


def get_timelapse_string(dt):
    diff = (datetime.utcnow() - datetime_from_string(dt)).total_seconds()
    if diff > (60*60*24):
        rs = '%d days' % (diff // (60*60*24))
        return rs[:-1] if rs.startswith('1') else rs
    elif diff > (60*60):
        rs = '%d hours' % (diff // (60*60))
        return rs[:-1] if rs.startswith('1') else rs
    elif diff > 60:
        rs = '%d minutes' % (diff // 60)
        return rs[:1] if rs.startswith('1') else rs
    rs = '%d seconds' % diff
    return rs[:-1] if diff == 1 else rs
        
    
def check_password(user, pw_attempt):
    user_full = query_db('''select * from users where user_id = ?''', 
                           [user['user_id']], one=True)
    return check_password_hash(user_full['user_pw_hash'], pw_attempt)


@app.before_request
def before_request():
    '''Makes sure we have a live connection to the app's database before 
    each view request. 

    **Note: In the future, this should be altered to not be a bottleneck, 
            some pages dont need any db access, and others can be cached 
            or something.
    '''
    g.db = connect_db()
    g.user = None
    if 'user_id' in session:
        g.user = get_user(user_id=session['user_id'])

@app.teardown_request
def teardown_request(exception):
    '''Closes the database connection after each view request is closed. 
    This provides transaction safety(I think). Will also end up having to be
    updated to handle concurrency in order to handle multiple users.
    '''
    g.db.close()


###############################
##                   
##     Url Routing 
##
##############################


@app.route('/')
def homepage():
    '''Returns the applications homepage.'''
    return render_template('index.html', 
           questions=[format_question(q) for q in query_db('''
           select * from questions order by pub_date desc''')], user=g.user)


@requires_login
@app.route('/question/<int:question_id>', methods=['GET', 'POST'])
def question_permapage(question_id):
    q = get_question(question_id=question_id)
    if q is None: 
        flash("Sorry, we couldn't find that question.")
        return redirect(url_for('homepage'))
    ans = get_answer_count(question_id)
    if request.method == 'POST':
        g.db.execute('''insert into answers (answer_choice, question_id, 
                        pub_date, last_modified, user_id) values (
                        ?, ?, ?, ?, ?)''', [request.form['choice'], 
                        q['question_id'], 
                        datetime.utcnow(), datetime.utcnow(), 
                        g.user['user_id']])
        g.db.commit()
        flash('great! your answer was recorded')
        return redirect(url_for('homepage'))
    return render_template('single-question.html', answers=ans, 
                                                  question=format_question(q))

@requires_login
@app.route('/question/add', methods=['GET', 'POST'])
def add_question():
    if request.method == 'POST':
        category = request.form['category']
    form = AddQuestionForm(request.form)
    if form.validate_on_submit():
        g.db.execute('''insert into questions (question_text, category_id, 
                        pub_date, last_modified, user_id) values 
                        (?, ?, ?, ?, ?)''', [form.question_text.data, 
                        category, datetime.utcnow(), 
                        datetime.utcnow(), session['user_id']])
        g.db.commit()
        flash("your question was successfully added, awesome!")
        return redirect(url_for('homepage'))
    return render_template('add-question.html', form=form, 
                                          categories=categories_list())


@requires_login
@app.route('/category/add', methods=['GET', 'POST'])
def add_category():
    form = AddCategoryForm(request.form)
    if form.validate_on_submit():
        g.db.execute('''insert into categories (category_name, pub_date, 
                        last_modified, user_id) values (?, ?, ?, ?)''', [
                        form.categoryname.data, datetime.utcnow(), 
                        datetime.utcnow(), session['user_id']])
        g.db.commit()
        flash('Your category has been submitted for review')
        return redirect(url_for('homepage'))
    return render_template('add-category.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def registration():
    if g.user:
        flash('you are already logged in')
        return redirect(url_for('homepage'))
    form = RegisterForm(request.form)
    if form.validate_on_submit():
        if form.username.data == 'Joe':
            g.db.execute('''insert into users (user_name, user_pw_hash, 
                            user_role, user_status, user_gender, 
                            user_zipcode, user_age, user_join_date, 
                            last_modified) values (?, ?, ?, ?, ?, ?, ?, ?, ?
                        )''', [form.username.data, 
                        generate_password_hash(form.password.data), 
                        7, 0, True, 33596, 23, datetime.utcnow(), 
                        datetime.utcnow()])
        else:
            g.db.execute('''insert into users (user_name, user_pw_hash, 
                            user_role, user_status, user_gender, 
                            user_join_date, last_modified) values ( 
                            ?, ?, ?, ?, ?, ?, ?)''' [
                            form.username.data, 
                            generate_password_hash(form.password.data), 
                            1, 0, (False if form.gender.date == 'f' 
                            else True), datetime.utcnow(), datetime.utcnow()])
        g.db.commit()
        flash('thanks for registering, you may login now')
        return redirect(url_for('login'))
    return render_template('user-register.html', form=form)

         
@app.route('/login', methods=['GET', 'POST'])
def login():
    if g.user:
        return redirect(url_for('homepage'))
    form = LoginForm(request.form)
    error = None
    if form.validate_on_submit():
        user_attempt = get_user(username=form.username.data)
        if user_attempt is None:
            error = 'Invalid Username'
        elif not check_password(user_attempt, form.password.data):
            error = 'Invalid password'
        else:
            session['user_id'] = user_attempt['user_id']
            flash('you were successfully logged in')
            return redirect(url_for('homepage'))
    return render_template('login.html', form=form, error=error)


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('you were logged out')
    return redirect(url_for('homepage'))


# For running in shell/standalone
# DO NOT RUN DEBUG IN PRODUCTION!!!!!!!
if __name__ == '__main__':
    app.run(debug=True)
