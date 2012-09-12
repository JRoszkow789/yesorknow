from flask.ext.wtf import Form, TextField, PasswordField, TextAreaField
from flask.ext.wtf import SelectField, Required, Email, EqualTo, SubmitField


class LoginForm(Form):
    user_email = TextField('email address', [Required(), Email()])
    user_pw = PasswordField('password', [Required()])


class RegisterForm(Form):
    user_email = TextField('email address', [Required(), Email()])


class RegisterFormContinued(Form):
    user_name = TextField('desired username', [Required()])
    user_pw = PasswordField('password', [Required()])
    user_verify = PasswordField('verify password', [
                                Required(), EqualTo('user_pw')])


class AddCategoryForm(Form):
    category_name = TextField('proposed category', [Required()])


class AddQuestionForm(Form):    
    question_text = TextAreaField('Your question here...', [Required()])

