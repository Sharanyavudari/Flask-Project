from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_wtf import FlaskForm, RecaptchaField
from flask_mysqldb import MySQL
import re
from flask_bcrypt import Bcrypt
from flask_recaptcha import ReCaptcha
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired,EqualTo
from markupsafe import Markup
import requests
from flask import session
from datetime import timedelta
from flask import abort

def is_password_complex(password):
    # Define the complexity requirements
    min_length = 8
    requires_upper = True
    requires_lower = True
    requires_digit = True
    requires_special = True

    # Check the length
    if len(password) < min_length:
        return False

    # Check for uppercase, lowercase, digit, and special character
    if requires_upper and not re.search(r'[A-Z]', password):
        return False
    if requires_lower and not re.search(r'[a-z]', password):
        return False
    if requires_digit and not re.search(r'\d', password):
        return False
    if requires_special and not re.search(r'[!@#$%^&*()_+{}[\]:;<>,.?~\\]', password):
        return False

    return True

app = Flask(__name__, template_folder='template')

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'Project@1234'
app.config['MYSQL_DB'] = 'user_db'
mysql = MySQL(app)

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=10).total_seconds()

app.secret_key = 'acgdf'

bcrypt = Bcrypt(app)

app.config['RECAPTCHA_PUBLIC_KEY'] = '6LcwRFUoAAAAAHqCUWtWjHhPDqErtv7J6Bg_Bz4F'
app.config['RECAPTCHA_PRIVATE_KEY'] = '6LcwRFUoAAAAABinu9excpWLefAR9WLrmL_RYJoR'
recaptcha = RecaptchaField()


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    recaptcha = RecaptchaField()
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    recaptcha = RecaptchaField()
    submit = SubmitField('Register')


def verify_recaptcha(recaptcha_response):
    secret_key = '6LcwRFUoAAAAABinu9excpWLefAR9WLrmL_RYJoR'
    payload = {
        'secret': secret_key,
        'response': recaptcha_response,
    }
    response = requests.post('https://www.google.com/recaptcha/api/siteverify', data=payload)
    result = response.json()
    return result['success']


def is_valid_username(username):
    # Add any additional username validation logic here
    return bool(re.match(r'^[a-zA-Z0-9_]+$', username))

def is_valid_appointment_data(name, date, time):
    # Add appointment data validation
    if not name or not date or not time:
        return False

    # Validate the date format
    try:
        datetime.strptime(date, '%Y-%m-%d')
    except ValueError:
        return False

    # Add any additional appointment data validation logic here
    return True

@app.route('/')
def main():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == 'POST':
        username = form.username.data
        password = form.password.data
        recaptcha_response = request.form.get('g-recaptcha-response')

        if verify_recaptcha(recaptcha_response):
            cursor = mysql.connection.cursor()
            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            user = cursor.fetchone()
            cursor.close()

            if user and user[2] == password:
                session['user_id'] = user[0]
                session.permanent = True  # Mark the session as permanent
                flash('Login successful!', 'success')
                return render_template('paitent.html')
            else:
                flash('Login failed. Please try again.', 'danger')
        else:
            flash('reCAPTCHA verification failed. Please try again.', 'danger')

    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logout successful!', 'success')

    # Clear the session cookie expiration time
    session.clear()

    return redirect(url_for('main'))


@app.route('/Register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if request.method == 'POST':
        username = form.username.data
        password = form.password.data
        recaptcha_response = request.form.get('g-recaptcha-response')

        # Validate reCAPTCHA
        if not verify_recaptcha(recaptcha_response):
            flash('reCAPTCHA verification failed. Please try again.', 'danger')
            return render_template('Register.html', form=form)

        # Additional validation for username and password
        if not is_valid_username(username):
            flash('Invalid username format.', 'danger')
            return render_template('Register.html', form=form)

        if not is_password_complex(password):
            flash('Password does not meet complexity requirements.', 'danger')
            return render_template('Register.html', form=form)

        # Check if the username already exists in the database
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        existing_user = cursor.fetchone()
        cursor.close()

        if existing_user:
            flash('Username already exists. Please choose a different username.', 'danger')
        else:
            # If the username is unique and password is complex, insert the new user into the database
            cursor = mysql.connection.cursor()
            cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, password))
            mysql.connection.commit()
            cursor.close()

            flash('Registration successful! You can now log in.', 'success')
            return redirect('/login')

    return render_template('Register.html', form=form)
@app.route('/paitent', methods=['GET', 'POST'])
def paitent():
    if 'user_id' not in session:
        flash('You need to log in first.', 'danger')
        return redirect(url_for('login'))

    # Display available appointments
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM appointments")
    appointments = cursor.fetchall()
    cursor.close()
    
    return render_template('paitent.html', appointments=appointments)

@app.route('/booking', methods=['GET', 'POST'])
def booking():
    # Check if the user is logged in
    if 'user_id' not in session:
        flash('You need to log in first.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Get appointment details from the form
        name = request.form['name']
        date = request.form['date']
        time = request.form['time']

        # Add appointment data validation
        if not is_valid_appointment_data(name, date, time):
            flash('Invalid appointment data. Please fill in all fields.', 'danger')
            return render_template('booking.html')

        # Validate the appointment date (e.g., it should be in the future)
        appointment_date = datetime.strptime(date, '%Y-%m-%d')
        if appointment_date < datetime.now():
            flash('Invalid appointment date. Please choose a future date.', 'danger')
            return render_template('booking.html')

        # Insert the appointment data into the database
        cursor = mysql.connection.cursor()
        cursor.execute("INSERT INTO appointments (name, date, time) VALUES (%s, %s, %s)", (name, date, time))
        mysql.connection.commit()
        cursor.close()
        return redirect(url_for('success'))

    return render_template('booking.html')

@app.route('/success')
def success():
    # Check if the user is logged in
    if 'user_id' not in session:
        flash('You need to log in first.', 'danger')
        return redirect(url_for('login'))
    return render_template('success.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
