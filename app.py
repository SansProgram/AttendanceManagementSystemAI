from flask import Flask, render_template, redirect, request, flash, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from joblib import load

import pandas as pd  # Import pandas if not already imported
import random  # Import random if not already imported

# Load the saved model
loaded_model = load('linear_regression_model.joblib')

# Example: Assuming 'new_data' is a DataFrame with a 'Weather' column
def weather_select():
  random_integer = random.randint(1,5)
  if random_integer == 1:
    new_data = pd.DataFrame({'Weather': ['rainy', 'extremely hot', 'warm', 'hot', 'cloudy']})
    weather = "Rainy"
    return new_data, weather
  elif random_integer == 2:
    new_data = pd.DataFrame({'Weather': ['extremely hot', 'warm', 'hot', 'cloudy', 'rainy']})
    weather = "Extremely Hot"
    return new_data, weather
  elif random_integer == 3:
    new_data = pd.DataFrame({'Weather': ['warm', 'hot', 'cloudy', 'rainy', 'extremely hot']})
    weather = "Warm"
    return new_data, weather
  elif random_integer == 4:
    new_data = pd.DataFrame({'Weather': ['hot', 'cloudy', 'rainy', 'extremely hot', 'warm']})
    weather = "Hot"
    return new_data, weather
  elif random_integer == 5:
    new_data = pd.DataFrame({'Weather': ['cloudy', 'rainy', 'extremely hot', 'warm', 'hot']})
    weather = "Cloudy"
    return new_data, weather

new_data, weather = weather_select()

# Convert categorical variables using one-hot encoding
new_data_encoded = pd.get_dummies(new_data, columns=['Weather'], prefix='Weather')

# Make predictions
new_predictions = loaded_model.predict(new_data_encoded)

# Print predictions
weather = weather
print(weather)
prediction = f'Predicted Attendance: {new_predictions[0]}'
print(prediction)

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
  role = db.Column(db.String(1), nullable=False)
  child = db.relationship('Attendance', backref='parent', uselist=False)

class Attendance(db.Model, UserMixin):
  id = db.Column(db.Integer, primary_key=True)
  attendance = db.Column(db.Integer)
  total_days = db.Column(db.Integer, default=0)
  attended_days = db.Column(db.Integer, default=0)
  user_id = db.Column(db.Integer, db.ForeignKey('user.id'))



# Database Content
class RegisterForm(FlaskForm):
  email = StringField(validators=[InputRequired(), Length(min=4, max=30)], render_kw={"placeholder": "email"})
  studentnumber = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Student/staff Number"})
  name = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Name"})
  surname = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Surname"})
  password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
  attendance = StringField(validators=[InputRequired(), Length(min=1, max=20)], render_kw={"placeholder": "Attendance"})
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

    new_user.role = 'S' if len(form.email.data)==23 else 'T'

    new_attendance = Attendance(attendance=form.attendance.data)
    new_user.child = new_attendance
    db.session.add(new_user)
    db.session.commit()
    flash('The account has been created!')
    return redirect("https://attendancemanagementsystemai.sansprogram.repl.co/signup")
  return render_template('signup.html', form=form)


# Main Routes
@app.route('/studentview', methods=['GET', 'POST'])
@login_required
def studentview_page():
  user = current_user
  return render_template('studentview.html', user=user)




def process_attendance_file(file):
  # Assuming the attendance calculation code is in the same file
  students = {}

  # Read the content of the uploaded file and process attendance
  content = file.read().decode('utf-8').splitlines()
  for line in content:
      parts = line.strip().split()
      student_id = parts[0]
      attendance = list(map(int, parts[1:]))

      if student_id not in students:
        students[student_id] = {'attended_days': 0, 'total_days': 0}

      students[student_id]['attended_days'] += sum(attendance)
      students[student_id]['total_days'] += len(attendance)

  # Save the updated attendance data to the database or use as needed
  for student_id, data in students.items():
    user = User.query.filter_by(studentnumber=student_id).first()
    if user:
      user_attendance = Attendance.query.filter_by(user_id=user.id).first()
      if user_attendance:
        user_attendance.total_days += data['total_days']  # Increment total days by the uploaded value
        user_attendance.attended_days += data['attended_days']  # Update attended days
        user_attendance.attendance = (user_attendance.attended_days / user_attendance.total_days) * 100
      else:
        # If the attendance record doesn't exist, create a new one
        new_attendance = Attendance(
          attendance=(data['attended_days'] / data['total_days']) * 100,  # Initial value, assuming 5 total days
          total_days=data['total_days'],
          attended_days=data['attended_days']
        )
        user.child = new_attendance

  db.session.commit()


@app.route('/reset_attendance', methods=['GET', 'POST'])
@login_required
def reset_attendance():
  if current_user.role == 'T':
    # Only teachers can reset attendance
    all_users = User.query.all()

    for user in all_users:
      user_attendance = Attendance.query.filter_by(user_id=user.id).first()
      if user_attendance:
        # Reset the attendance to 0
        user_attendance.attendance = 0

  db.session.commit()
  flash('Attendance values reset successfully!')

  return redirect(url_for('lecturerview_page'))

@app.route('/reset_total_days', methods=['GET', 'POST'])
@login_required
def reset_total_days():
  if current_user.role == 'T':
    # Only teachers can reset attendance
    all_users = User.query.all()

    for user in all_users:
      user_attendance = Attendance.query.filter_by(user_id=user.id).first()
      if user_attendance:
        # Reset the attendance to 0
        user_attendance.total_days = 0

  db.session.commit()
  flash('Attendance values reset successfully!')

  return redirect(url_for('lecturerview_page'))

@app.route('/reset_attended_days', methods=['GET', 'POST'])
@login_required
def reset_attended_days():
  if current_user.role == 'T':
    # Only teachers can reset attendance
    all_users = User.query.all()

    for user in all_users:
      user_attendance = Attendance.query.filter_by(user_id=user.id).first()
      if user_attendance:
        # Reset the attendance to 0
        user_attendance.attended_days = 0

  db.session.commit()
  flash('Attendance values reset successfully!')

  return redirect(url_for('lecturerview_page'))


@app.route('/lecturerview', methods=['GET', 'POST'])
@login_required
def lecturerview_page():
  global weather
  global prediction
  if current_user.role == 'T':
    # Only teachers can access this page
    students = User.query.filter_by(role='S').all()

    # Search functionality
    search_query = request.args.get('search', '')
    if search_query:
      students = [student for student in students if search_query in student.studentnumber]

    # Handle file upload
    if request.method == 'POST':
      file = request.files['file']
      if file:
        # Save the file to a temporary location or process it directly
        process_attendance_file(file)
        flash('Attendance file uploaded successfully!')
      else:
        flash('No file selected!')

    return render_template('lecturerview.html', students=students, search_query=search_query, weather=weather, prediction=prediction)
  else:
    # Redirect non-teachers to a different page or show an error message
    return redirect('/error_page')



@app.route('/error_page')
def error_page():
  return render_template('error_page.html')

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
  user = current_user
  return render_template('profile.html', user=user)

@app.route('/module_page')
def module_page():
  return render_template('module_page.html')


# This must get the value from the database attendance.db
@app.route('/studanalytics', methods=['GET', 'POST'])
@login_required
def studanalytics():
  user = current_user
  current_user_attendance = current_user.child
  percentage = current_user_attendance.attendance if current_user_attendance else 'N/A'
  return render_template('studanalytics.html', percentage=percentage, user=user)

# logout user
@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
  logout_user()
  return redirect("https://attendancemanagementsystemai.sansprogram.repl.co/")

# Main Function to run
if __name__ == "__main__":
  app.run(host='0.0.0.0', debug=True)