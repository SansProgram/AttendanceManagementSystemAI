from flask import Flask, render_template, redirect, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt


app = Flask(__name__)
db = SQLAlchemy()
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'thisisasecretkey'
db.init_app(app)
app.app_context().push()

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
  return User.query.get(int(user_id))


# Databas Table
class User(db.Model, UserMixin):
  id = db.Column(db.Integer, primary_key=True)
  email = db.Column(db.String(20), nullable=False, unique=True)
  studentnumber = db.Column(db.String(10), nullable=False, unique=True)
  name = db.Column(db.String(80), nullable=False)
  surname = db.Column(db.String(80), nullable=False)
  password = db.Column(db.String(80), nullable=False)
  
  

# Database Content
class RegisterForm(FlaskForm):
  email = StringField(validators=[InputRequired(), Length(min=4, max=30)], render_kw={"placeholder": "email"})
  studentnumber = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Student/staff Number"})
  name = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Name"})
  surname = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Surname"})
  password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
  submit = SubmitField("Register")

  def validate_email(self, email):
   existing_user_email = User.query.filter_by(email=email.data).first()
   if existing_user_email:
     raise ValidationError("That email already exists. Please choose a different one.")

class LoginForm(FlaskForm):
  email = StringField(validators=[InputRequired(), Length(min=4, max=30)], render_kw={"placeholder": "Institution email"})
  password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
  submit = SubmitField("Login")


# Login System
@app.route('/', methods=['GET', 'POST'])
def login_page():
  form = LoginForm()
  if form.validate_on_submit():
    user = User.query.filter_by(email=form.email.data).first()
    if user:
      email = request.form.get('email')
      if email.startswith('L'):
        if bcrypt.check_password_hash(user.password, form.password.data):
          login_user(user)
          return redirect("https://attendancemanagementsystemai.sansprogram.repl.co/lecturerview")
      else:
        if bcrypt.check_password_hash(user.password, form.password.data):
          login_user(user)
          return redirect("https://attendancemanagementsystemai.sansprogram.repl.co/studentview")
        
  return render_template('login.html', form=form)





# Registration System
@app.route('/signup', methods=['GET', 'POST'])
def signup_page():
  form = RegisterForm()

  if form.validate_on_submit():
    hashed_password = bcrypt.generate_password_hash(form.password.data)
    new_user = User(email=form.email.data, studentnumber=form.studentnumber.data, name=form.name.data, surname=form.surname.data, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    flash('The account has been created!')
    return redirect("https://attendancemanagementsystemai.sansprogram.repl.co/")
  
  return render_template('signup.html', form=form)

# Main Routes

@app.route('/studentview', methods=['GET', 'POST'])
@login_required
def studentview_page():
    # get the current user from Flask-Login
    user = current_user
    return render_template('studentview.html', user=user)

@app.route('/lecturerview', methods=['GET', 'POST'])
@login_required
def lecturerview_page():
  users=User.query.all()
  return render_template('lecturerview.html', users=users)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
  user = current_user
  return render_template('profile.html', user=user)

@app.route('/module_page')
def module_page():
  return render_template('module_page.html')


# logout user
@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
  logout_user()
  return redirect("https://attendancemanagementsystemai.sansprogram.repl.co/")

# Main Function to run
if __name__ == "__main__":
  app.run(host='0.0.0.0', debug=True)
