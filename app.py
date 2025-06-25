from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, jsonify, Response, send_file
from datetime import datetime, timedelta, timezone
import sqlite3
import csv
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
import json
import re
import os
from cryptography.fernet import Fernet
from base64 import b64encode, b64decode

# Initialize Flask application
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Email configuration - using your credentials
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'demoncatofdc@gmail.com'
app.config['MAIL_PASSWORD'] = 'qrwv ibde oppn movr'
app.config['MAIL_DEFAULT_SENDER'] = 'demoncatofdc@gmail.com'

# Initialize database, login manager, and mail
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Create database tables
with app.app_context():
    db.create_all()

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    skin_type = db.Column(db.String(10), nullable=True)
    email_verified = db.Column(db.Boolean, default=False)
    email_verification_token = db.Column(db.String(200), nullable=True)
    password_reset_token = db.Column(db.String(200), nullable=True)
    password_reset_expires = db.Column(db.DateTime, nullable=True)

    def __init__(self, username, email, password, skin_type=None):
        self.username = username
        self.email = email
        self.password = password
        self.skin_type = skin_type

    @staticmethod
    def get_by_username(username):
        return User.query.filter_by(username=username).first()

    @staticmethod
    def get_by_email(email):
        return User.query.filter_by(email=email).first()

    def generate_email_verification_token(self):
        """Generate a token for email verification"""
        self.email_verification_token = serializer.dumps(self.email, salt='email-verification')
        db.session.commit()
        return self.email_verification_token

    def generate_password_reset_token(self):
        """Generate a token for password reset"""
        self.password_reset_token = serializer.dumps(self.email, salt='password-reset')
        self.password_reset_expires = datetime.now(timezone.utc) + timedelta(hours=1)
        db.session.commit()
        return self.password_reset_token

    def verify_email_token(self, token):
        """Verify email verification token"""
        try:
            email = serializer.loads(token, salt='email-verification', max_age=86400)  # 24 hours
            if email == self.email:
                self.email_verified = True
                self.email_verification_token = None
                db.session.commit()
                return True
        except (SignatureExpired, BadTimeSignature):
            pass
        return False

    def verify_password_reset_token(self, token):
        """Verify password reset token"""
        try:
            email = serializer.loads(token, salt='password-reset', max_age=3600)  # 1 hour
            if email == self.email and self.password_reset_expires and datetime.now(timezone.utc) < self.password_reset_expires:
                return True
        except (SignatureExpired, BadTimeSignature):
            pass
        return False

# Email sending functions
def send_email_verification(user):
    """Send email verification email"""
    try:
        print(f"Attempting to send verification email to: {user.email}")
        token = user.generate_email_verification_token()
        verification_url = url_for('verify_email', token=token, _external=True)
        
        html = render_template('email/confirm.html', confirm_url=verification_url)
        msg = Message('Confirm Your TanTime Account', recipients=[user.email], html=html)
        mail.send(msg)
        
        print(f"Verification email sent successfully to {user.email}")
        return True
    except Exception as e:
        print(f"Error sending verification email: {e}")
        return False

def send_password_reset_email(user):
    """Send password reset email"""
    try:
        print(f"Attempting to send password reset email to: {user.email}")
        token = user.generate_password_reset_token()
        reset_url = url_for('reset_password', token=token, _external=True)
        
        html = render_template('email/reset.html', reset_url=reset_url)
        msg = Message('Reset Your TanTime Password', recipients=[user.email], html=html)
        mail.send(msg)
        
        print(f"Password reset email sent successfully to {user.email}")
        return True
    except Exception as e:
        print(f"Error sending password reset email: {e}")
        return False

def send_welcome_email(user):
    """Send welcome email"""
    try:
        print(f"Attempting to send welcome email to: {user.email}")
        welcome_html = render_template('email/welcome.html', name=user.username)
        welcome_msg = Message('Welcome to TanTime!', recipients=[user.email], html=welcome_html)
        mail.send(welcome_msg)
        
        print(f"Welcome email sent successfully to {user.email}")
        return True
    except Exception as e:
        print(f"Error sending welcome email: {e}")
        return False

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        print(f"Login attempt for username: {username}")
        
        if not username or not password:
            flash('Please enter both username and password', 'danger')
            return redirect(url_for('login'))
        
        try:
            user = User.get_by_username(username)
            print(f"User found: {user is not None}")
            
            if user:
                print("Checking password hash")
                if check_password_hash(user.password, password):
                    print("Password check passed")
                    
                    # Check if email is verified
                    if not user.email_verified:
                        flash('Please verify your email address before logging in. Check your inbox or request a new verification email.', 'warning')
                        return redirect(url_for('login'))
                    
                    login_user(user)
                    print(f"User {username} logged in successfully")
                    flash('Login successful!', 'success')
                    return redirect(url_for('dashboard'))
                else:
                    print("Password check failed")
            else:
                print("User not found")
                
            flash('Invalid username or password', 'danger')
        except Exception as e:
            print(f"Login error: {e}")
            flash('An error occurred during login. Please try again.', 'danger')
            
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        skin_type = request.form.get('skin_type', '')
        print(f"Signup attempt for username: {username}")
        
        # Validate inputs
        if not username or not email or not password:
            flash('Please fill in all required fields.', 'danger')
            return redirect(url_for('register'))
        
        # Validate email format
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash('Please enter a valid email address.', 'danger')
            return redirect(url_for('register'))
        
        # Validate password requirements
        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'danger')
            return redirect(url_for('register'))
        
        # Check if user already exists
        if User.get_by_username(username):
            flash('Username already exists. Please choose a different one.', 'danger')
            return redirect(url_for('register'))

        if User.get_by_email(email):
            flash('Email already exists. Please use a different email or login.', 'danger')
            return redirect(url_for('register'))
        
        try:
            # Create new user
            hashed_password = generate_password_hash(password)
            new_user = User(username=username, email=email, password=hashed_password, skin_type=skin_type)
            db.session.add(new_user)
            db.session.commit()
            
            print(f"User {username} created successfully with email {email}")
            
            # Send confirmation email
            print(f"Attempting to send verification email for user {username}")
            if send_email_verification(new_user):
                flash('Account created successfully! Please check your email to verify your account.', 'success')
                print(f"Verification email sent successfully for user {username}")
            else:
                flash('Account created successfully! However, there was an issue sending the verification email. Please contact support.', 'warning')
                print(f"Failed to send verification email for user {username}")
            
            # Send welcome email
            send_welcome_email(new_user)
            
            return redirect(url_for('login'))
            
        except Exception as e:
            print(f"Error creating user: {e}")
            db.session.rollback()
            flash('An error occurred during registration. Please try again.', 'danger')
            return redirect(url_for('register'))
    
    return render_template('register.html')

@app.route('/verify-email/<token>')
def verify_email(token):
    try:
        # Find user by verification token
        user = User.query.filter_by(email_verification_token=token).first()
        if user and user.verify_email_token(token):
            print(f"User {user.username} email verified successfully")
            flash('Email verified successfully! You can now login.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid or expired verification link. Please request a new one.', 'danger')
            return redirect(url_for('login'))
    except Exception as e:
        print(f"Email verification error: {e}")
        flash('An error occurred during email verification. Please try again.', 'danger')
        return redirect(url_for('login'))

@app.route('/resend-verification', methods=['GET', 'POST'])
def resend_verification():
    if request.method == 'POST':
        email = request.form.get('email')
        if not email:
            flash('Please enter your email address', 'danger')
            return redirect(url_for('resend_verification'))
        
        user = User.get_by_email(email)
        if user and not user.email_verified:
            if send_email_verification(user):
                flash('Verification email sent! Please check your inbox.', 'success')
            else:
                flash('Failed to send verification email. Please try again later.', 'danger')
        else:
            flash('Email not found or already verified.', 'info')
        
        return redirect(url_for('login'))
    
    return render_template('resend_verification.html')

@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        
        if not email:
            flash('Please enter your email address.', 'danger')
            return render_template('forgot.html')
        
        try:
            user = User.get_by_email(email)
            if user:
                if send_password_reset_email(user):
                    flash('Password reset email sent! Please check your inbox.', 'success')
                else:
                    flash('Failed to send password reset email. Please try again later.', 'danger')
            else:
                flash('If your email is registered, you will receive a password reset link.', 'info')
        except Exception as e:
            print(f"Password reset error: {e}")
            flash('An error occurred. Please try again.', 'danger')
        
        return redirect(url_for('login'))
    
    return render_template('forgot.html')

@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        # Find user by reset token
        user = User.query.filter_by(password_reset_token=token).first()
        if not user or not user.verify_password_reset_token(token):
            flash('The reset link is invalid or has expired.', 'danger')
            return redirect(url_for('forgot'))
        
        if request.method == 'POST':
            password = request.form.get('password', '').strip()
            
            # Validate password requirements
            if len(password) < 8:
                flash('Password must be at least 8 characters long.', 'danger')
                return render_template('reset.html', token=token)
            
            try:
                user.password = generate_password_hash(password)
                user.password_reset_token = None
                user.password_reset_expires = None
                db.session.commit()
                flash('Your password has been reset! You can now log in.', 'success')
                return redirect(url_for('login'))
            except Exception as e:
                print(f"Password reset error: {e}")
                flash('An error occurred while resetting your password. Please try again.', 'danger')
        
        return render_template('reset.html', token=token)
        
    except Exception as e:
        print(f"Password reset error: {e}")
        flash('An error occurred. Please try again.', 'danger')
        return redirect(url_for('forgot'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True) 
                                                                                             
                                                                                                                                                                                                                                              
                                                                                                                                                                                                                                               