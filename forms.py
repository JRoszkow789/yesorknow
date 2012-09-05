from flask.ext.wtf import Form, TextField, PasswordField, TextAreaField
from flask.ext.wtf import RadioField, SelectField, Required, EqualTo

class LoginForm(Form):
    username = TextField('Username', [Required()])
    password = PasswordField('Password', [Required()])

class RegisterForm(Form):
    username = TextField('Desired Username', [Required()])
    password = PasswordField('Password', [Required()])
    gender = RadioField('Gender', [Required()], choices=[('m', 'Male'), 
                                                       ('f', 'Female')])

class AddCategoryForm(Form):
    categoryname = TextField('Proposed Category', [Required()])

class AddQuestionForm(Form):    
    question_text = TextAreaField('Your question here...', [Required()])

class AnswerQuestionForm(Form):
    choice = RadioField('Answer', [Required()], choices=['No', 'Yes'])

