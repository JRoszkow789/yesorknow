from __future__ import with_statement, division, absolute_import
import sqlite3
from contextlib import closing
from flask import Flask, render_template, request, session, g, redirect
from flask import url_for, abort, flash
from decorators import requires_login
from forms import LoginForm, RegisterForm, AddCategoryForm
from forms import AddQuestionForm, RegisterFormContinued
from werkzeug import check_password_hash, generate_password_hash
from datetime import datetime, timedelta
from flask_debugtoolbar import DebugToolbarExtension
import constants as CTS
from random import choice

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


def insert_db(table, fields=(), values=()):
    cur = g.db.cursor()
    query = 'INSERT INTO %s (%s) VALUES (%s)' % (
            table, ', '.join(fields),
            ', '.join(['?'] * len(values))
            )
    cur.execute(query, values)
    g.db.commit()
    id = cur.lastrowid
    cur.close()
    return id


def get_user(user_name=None, user_id=None, user_email=None):
    '''Simple helper method to return a user object from the database.
       can retrieve user by supplying user_name, user_id, or user_email.
    '''
    if user_name is not None:
        return query_db('''select * from users where user_name = ?''', 
                           [username], one=True)
    elif user_id is not None:
        return query_db('''select * from users where user_id = ?''', 
                           [user_id], one=True)
    elif user_email is not None:
        return query_db('''select * from users where user_email = ?''', 
                           [user_email], one=True)
    return None


def get_user_info(user_id):
    user_info = query_db(
            'select user_id, user_name from users where user_id = ?', 
            [user_id], one=True)
    return user_info


def get_questions(question_id=None, category=None, count=None, random=False):
    """Docstringin it yo"""
    if question_id is not None: 
        rv = query_db(
                'select * from questions where question_id = ?', 
                [question_id], one=True)
        return rv

    q_list = []
    if category is not None and int(category) < 1000: #TODO this is a hack
        q_list = (query_db(
                'select * from questions where category_id = ? order by \
                        pub_date desc', [int(category)]))
    elif category is not None:
        q_list = query_db(
                'select * from questions where category_id = ? order by \
                        pub_date desc', 
                        [get_category(category_name=category)['category_id']])
    else:
        q_list = query_db('select * from questions order by pub_date desc')
    
    if count is not None: 
        return q_list[:count] if len(q_list) > count else q_list
    elif random:
        return choice(q_list)
    
    return q_list


def get_category(category_name=None, category_id=None):
    '''Simple helper method to return a category. can be retrieved 
       by providing either category_name or category_id as a param.
    '''
    if category_name is not None:
        return query_db('''select * from categories where category_name = ?''', 
                           [categoryname],one=True)
    elif category_id is not None:
        return query_db('''select * from categories where category_id = ?''', 
                           [category_id], one=True)
    return None


def formatted_question(question_id=None, question=None):
    if question is not None:
        q = question
    elif question_id is not None:
        q = get_questions(question_id=question_id)
    else: 
        return None
    return dict([('question_id', q['question_id']), 
               ('question_text', q['question_text']),
               ('pub_date', q['pub_date']),
               ('question_user', get_user_info(user_id=q['user_id'])),
               ('question_category', get_category(
                            category_id=q['category_id'])['category_name'])]) 


def formatted_answer_count(question_id):
    '''Returns a two item tuple containing the count of no answers, followed
       by the count of yes answers for the question with the given parameter
       of question_id.
    '''
    #TODO Again gotta be murdering memory, especially on tiny ec2 instance!
    answers = query_db(
            'select answer_choice from answers where question_id = ?' , 
            [question_id])
    y_count = 0
    n_count = 0
    for a in answers:
        if a['answer_choice'] == CTS.NO:
            n_count += 1
        else:
            y_count += 1
    return (n_count, y_count)


def time_since(dt, default="just now"):
    """Returns string representing "time since" e.g. 
       3 days ago, 5 hours ago, etc...
    """
    now = datetime.utcnow()
    diff = (now - datetime.strptime(dt, '%Y-%m-%d %H:%M:%S.%f'))

    periods = (
            (diff.days // 365, "year", "years"), 
            (diff.days // 30, "month", "months"),
            (diff.days // 7, "week", "weeks"),
            (diff.days, "day", "days"),
            (diff.seconds // 3600, "hour", "hours"),
            (diff.seconds // 60, "minute", "minutes"),
            (diff.seconds, "second", "seconds"),
        )
    for period, singular, plural in periods:
        if period: 
            return '%d %s ago' % (period, singular if period == 1 else plural)
    return default


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
        # Original 
        #g.user = get_user(user_id=session['user_id'])
        g.user = query_db(
            'select user_id, user_name from users where user_id = ?', 
            [session['user_id']], one=True)

@app.teardown_request
def teardown_request(exception):
    '''Closes the database connection after each view request is closed. 
    This provides transaction safety(I think). Will also end up having to be
    updated to handle concurrency in order to handle multiple users.
    '''
    g.db.close()


# Error Handling

@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404


###############################
##                   
##     Url Routing 
##
##############################


@app.route('/')
def homepage():
    '''Returns the applications homepage.'''
    return render_template(
            'index.html', 
            questions=[formatted_question(question=q) for q in get_questions()],
            user=g.user)


@app.route('/question/<int:question_id>', methods=['GET', 'POST'])
@requires_login
def question_permapage(question_id):
    q = get_questions(question_id=question_id)
    if q is None: 
        flash("Sorry, we couldn't find that question.")
        return redirect(url_for('homepage'))
    if (request.method == 'POST') and (
            request.form['user_response'] != 'more info...'):
        user_response = (CTS.NO if request.form['user_response'] == 'no' 
                                else CTS.YES)
        g.db.execute('''insert into answers (answer_choice, question_id, 
                        pub_date, last_modified, user_id) values (
                        ?, ?, ?, ?, ?)''', [user_response, q['question_id'], 
                        datetime.utcnow(), datetime.utcnow(), 
                        g.user['user_id']])
        g.db.commit()
        flash('great! your answer was recorded')
        return redirect(url_for('show_results', question_id=question_id))
    return render_template('single-question.html', 
                            question=formatted_question(question=q))


@app.route('/question/<int:question_id>/results')
def show_results(question_id):
    q = formatted_question(question_id=question_id)
    if q is None:
        flash('sorry that question was not found')
        return redirect(url_for('homepage'))
    ans_counts = formatted_answer_count(question_id)
    return render_template(
            'question-results.html', 
            question=q, answers=ans_counts)


@app.route('/question/add', methods=['GET', 'POST'])
@requires_login
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
    return render_template(
            'add-question.html', 
            form=form,
            categories=query_db(
                'select category_id, category_name from categories')
            )


@app.route('/random/<category>')
@app.route('/random')
def random_question_page(category=None):
    """Returns a single random question for display. 
       A category may be specified.
    """
    try:
        q = get_questions(category=category, random=True)
    except IndexError:
        flash('oops, no questions for that category yet... Help us out \
                and post one!', 'warning')
        return redirect(url_for('add_question') if g.user 
                else url_for('homepage'))
    # TODO this is also a dumb hack FIX IT!
    return redirect(url_for(
            'question_permapage', 
            question_id=q['question_id']))


@app.route('/categories', methods=['GET', 'POST'])
def categories_main():
    form = AddCategoryForm(request.form)
    if form.validate_on_submit():
        if g.user is None:
            flash(u'you must be logged in for that!', 'warning')
            return redirect(url_for('login', next=request.path))
        g.db.execute('''insert into categories (category_name, pub_date, 
                        last_modified, user_id) values (?, ?, ?, ?)''', [
                        form.category_name.data, datetime.utcnow(), 
                        datetime.utcnow(), session['user_id']])
        g.db.commit()
        flash('Your category has been submitted for review')
        return redirect(url_for('homepage'))
    categories = query_db('select category_id, category_name from categories')
    return render_template('categories.html', form=form, categories=categories)


@app.route('/register', methods=['GET', 'POST'])
def registration():
    if g.user:
        flash('you are already logged in')
        return redirect(url_for('homepage'))
    if request.method == 'POST':
        user_gender_response = (
            CTS.MALE if request.form['gender_btn'] == 'no' 
                            else CTS.FEMALE)
    form = RegisterForm(request.form)
    if form.validate_on_submit():
        if form.user_email.data == 'Joe@CanopyInnovation.com':
            g.db.execute('''insert into users (user_name, user_pw_hash, 
                            user_role, user_status, user_gender, user_email, 
                            user_zipcode, user_age, user_join_date, 
                            last_modified) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            ''', ['Joe', 
                                generate_password_hash('default'), 
                                CTS.SUPER, CTS.ACTIVE, CTS.MALE, 
                                form.user_email.data, 33596, 23, 
                                datetime.utcnow(), datetime.utcnow()])
            g.db.commit()
            flash('Super user Joe added, welcome sir...')
            return redirect(url_for('login'))
        else:
            #g.db.execute('''insert into users (user_email, user_gender, 
            #                user_status, user_join_date, last_modified) 
            #                values (?, ?, ?, ?, ?)''',  [
            #                form.user_email.data, user_gender_response, 
            #                CTS.PENDING, 
            #                datetime.utcnow(), datetime.utcnow()])
            #g.db.commit()
#TODO this has to be terrible for memory!
            #session['temp_id'] = get_user(
            #                       user_email=form.user_email.data)['user_id']
            new_user_id = insert_db(table='users', fields=(
                'user_email', 'user_gender',
                'user_status', 'user_join_date',
                'last_modified'), values=(
                form.user_email.data, user_gender_response,
                CTS.PENDING, datetime.utcnow(),
                datetime.utcnow()))
            session['temp_id'] = new_user_id
            flash('Achievement: First Question!')
            return redirect(url_for('registration_continued')) 
    return render_template('register-main.html', form=form)


@app.route('/almostthere', methods=['GET', 'POST'])
def registration_continued():
    form = RegisterFormContinued(request.form)
    if form.validate_on_submit() and 'temp_id' in session:
        g.db.execute('''update users set user_name = ?, user_pw_hash = ? 
                        where user_id = ?''', (form.user_name.data, 
                        generate_password_hash(form.user_pw.data), 
                        int(session['temp_id'])))
        g.db.commit()
        session.pop('temp_id', None)
        flash('congratulations you have been registered! you may login now')
        return redirect(url_for('login'))
    return render_template('register2.html', form=form)
    
         
@app.route('/login', methods=['GET', 'POST'])
def login():
    if g.user:
        return redirect(url_for('homepage'))
    form = LoginForm(request.form)
    error = None
    if form.validate_on_submit():
        user_attempt = get_user(user_email=form.user_email.data)
        if user_attempt is None:
            error = 'Invalid email'
        elif not check_password_hash(
                user_attempt['user_pw_hash'], 
                form.user_pw.data):
            error = 'Invalid password'
        else:
            session['user_id'] = user_attempt['user_id']
            flash('you were successfully logged in')
            if request.args.get('next'):
                return redirect(url_for(request.args.get('next')))
            return redirect(url_for('homepage'))
    return render_template('login.html', form=form, error=error)


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('you were logged out')
    return redirect(url_for('homepage'))


# TODO Probably should be serving these as static files?
@app.route('/about')
def about_info():
    return render_template('about.html')


@app.route('/contact')
def contact_info():
    return render_template('contact.html')


# Add some template filters to jinja
app.jinja_env.filters['time_since'] = time_since

# For running in shell/standalone
# DO NOT RUN DEBUG IN PRODUCTION!!!!!!!
if __name__ == '__main__':
    app.run(debug=True)
