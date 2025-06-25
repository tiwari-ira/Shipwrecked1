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

# Load email configuration from config file if it exists
try:
    from config import *
    app.config['MAIL_SERVER'] = MAIL_SERVER
    app.config['MAIL_PORT'] = MAIL_PORT
    app.config['MAIL_USE_TLS'] = MAIL_USE_TLS
    app.config['MAIL_USERNAME'] = MAIL_USERNAME
    app.config['MAIL_PASSWORD'] = MAIL_PASSWORD
    app.config['MAIL_DEFAULT_SENDER'] = MAIL_DEFAULT_SENDER
    print("Email configuration loaded from config.py")
except ImportError:
    # Default email configuration (for development)
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = 'your-email@gmail.com'  # Replace with your email
    app.config['MAIL_PASSWORD'] = 'your-app-password'     # Replace with your app password
    app.config['MAIL_DEFAULT_SENDER'] = 'your-email@gmail.com'
    print("Warning: No config.py found. Using default email configuration.")
    print("Please create config.py with your email settings (see config_template.py)")

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
    email_verified = db.Column(db.Boolean, default=False)
    email_verification_token = db.Column(db.String(200), nullable=True)
    password_reset_token = db.Column(db.String(200), nullable=True)
    password_reset_expires = db.Column(db.DateTime, nullable=True)

    def __init__(self, username, email, password):
        self.username = encrypt_data(username).decode()
        self.email = email
        self.password = password

    def get_username(self):
        return decrypt_data(self.username.encode())

    @staticmethod
    def get_by_username(username):
        try:
            # First, try to find user with encrypted username (new method)
            encrypted_username = encrypt_data(username).decode()
            print(f"Looking for user with encrypted username: {encrypted_username}")
            
            user = User.query.filter_by(username=encrypted_username).first()
            if user:
                print(f"Found user with encrypted username")
                return user
            
            # If not found, try to find user with plain text username (backward compatibility)
            print(f"User not found with encrypted username, trying plain text")
            user = User.query.filter_by(username=username).first()
            if user:
                print(f"Found user with plain text username - migrating to encrypted")
                # Migrate the user to encrypted username
                try:
                    user.username = encrypted_username
                    db.session.commit()
                    print(f"Successfully migrated user {username} to encrypted username")
                except Exception as e:
                    print(f"Error migrating user: {e}")
                    db.session.rollback()
                return user
            
            # If still not found, check if there are any users with corrupted encryption
            # that might match this username by checking all users
            print(f"Checking for users with corrupted encryption...")
            all_users = User.query.all()
            for user in all_users:
                try:
                    # Try to decrypt the username
                    decrypted_username = decrypt_data(user.username.encode())
                    if decrypted_username == username:
                        print(f"Found user with corrupted encryption, user ID: {user.id}")
                        return user
                except:
                    # If decryption fails, this user has corrupted encryption
                    # We can't recover it automatically, but we can note it
                    continue
            
            print(f"User not found with any method")
            return None
            
        except Exception as e:
            print(f"Error in get_by_username: {e}")
            return None
 
    @staticmethod
    def get_by_email(email):
        return User.query.filter_by(email=email).first()

    @staticmethod
    def get_corrupted_users():
        """Get all users with corrupted encryption that can't be decrypted"""
        corrupted_users = []
        try:
            all_users = User.query.all()
            for user in all_users:
                try:
                    decrypt_data(user.username.encode())
                except:
                    corrupted_users.append(user)
            return corrupted_users
        except Exception as e:
            print(f"Error getting corrupted users: {e}")
            return []

    def fix_username(self, new_username):
        """Fix a corrupted username by setting it to a new encrypted value"""
        try:
            self.username = encrypt_data(new_username).decode()
            db.session.commit()
            return True
        except Exception as e:
            print(f"Error fixing username: {e}")
            db.session.rollback()
            return False

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
        confirm_url = url_for('verify_email', token=token, _external=True)
        
        msg = Message('Verify Your Email - TanTime',
                     recipients=[user.email])
        msg.html = render_template('email/confirm.html', 
                                 username=user.get_username(),
                                 confirm_url=confirm_url)
        
        mail.send(msg)
        print(f"Verification email sent successfully to {user.email}")
        return True
    except Exception as e:
        print(f"Error sending verification email: {e}")
        return False

def send_password_reset_email(user):
    """Send password reset email"""
    try:
        token = user.generate_password_reset_token()
        reset_url = url_for('reset_password', token=token, _external=True)
        
        msg = Message('Reset Your Password - TanTime',
                     recipients=[user.email])
        msg.html = render_template('email/reset.html', 
                                 username=user.get_username(),
                                 reset_url=reset_url)
        
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Error sending password reset email: {e}")
        return False

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

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
                    
                    # Ensure user's database has all required tables
                    ensure_user_db_integrity(username)
                    
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

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        print(f"Signup attempt for username: {username}")
        
        # Validate email format
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash('Please enter a valid email address', 'danger')
            return redirect(url_for('signup'))
        
        # Validate password requirements
        is_valid, message = validate_password(password)
        if not is_valid:
            print(f"Password validation failed: {message}")
            flash(message, 'danger')
            return redirect(url_for('signup'))
        
        hashed_password = generate_password_hash(password)

        if User.get_by_username(username):
            print(f"Username {username} already exists")
            flash('Username already exists. Please choose a different one.', 'danger')
            return redirect(url_for('signup'))

        if User.get_by_email(email):
            print(f"Email {email} already exists")
            flash('Email already exists. Please use a different email or login.', 'danger')
            return redirect(url_for('signup'))

        try:
            new_user = User(username=username, email=email, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            
            print(f"User {username} created successfully with email {email}")
            
            # Send email verification
            print(f"Attempting to send verification email for user {username}")
            if send_email_verification(new_user):
                flash('Account created successfully! Please check your email to verify your account.', 'success')
                print(f"Verification email sent successfully for user {username}")
            else:
                flash('Account created successfully! However, there was an issue sending the verification email. Please contact support.', 'warning')
                print(f"Failed to send verification email for user {username}")
            
            print(f"User {username} created successfully")
            return redirect(url_for('signup_landing'))
            
        except Exception as e:
            print(f"Error creating user: {e}")
            db.session.rollback()
            flash('An error occurred during signup. Please try again.', 'danger')
            return redirect(url_for('signup'))
            
    return render_template('signup.html')

@app.route('/verify-email/<token>')
def verify_email(token):
    try:
        # Find user by verification token
        user = User.query.filter_by(email_verification_token=token).first()
        if user and user.verify_email_token(token):
            # Initialize user's database after email verification
            init_user_db(user.get_username())
            print(f"User database initialized for {user.get_username()}")
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

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        if not email:
            flash('Please enter your email address', 'danger')
            return redirect(url_for('forgot_password'))
        
        user = User.get_by_email(email)
        if user:
            if send_password_reset_email(user):
                flash('Password reset email sent! Please check your inbox.', 'success')
            else:
                flash('Failed to send password reset email. Please try again later.', 'danger')
        else:
            flash('Email not found.', 'info')
        
        return redirect(url_for('login'))
    
    return render_template('forgot.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        # Find user by reset token
        user = User.query.filter_by(password_reset_token=token).first()
        if not user or not user.verify_password_reset_token(token):
            flash('Invalid or expired reset link. Please request a new one.', 'danger')
            return redirect(url_for('forgot_password'))
        
        if request.method == 'POST':
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')
            
            if password != confirm_password:
                flash('Passwords do not match.', 'danger')
                return render_template('reset.html', token=token)
            
            is_valid, message = validate_password(password)
            if not is_valid:
                flash(message, 'danger')
                return render_template('reset.html', token=token)
            
            user.password = generate_password_hash(password)
            user.password_reset_token = None
            user.password_reset_expires = None
            db.session.commit()
            
            flash('Password reset successfully! You can now login with your new password.', 'success')
            return redirect(url_for('login'))
        
        return render_template('reset.html', token=token)
        
    except Exception as e:
        print(f"Password reset error: {e}")
        flash('An error occurred during password reset. Please try again.', 'danger')
        return redirect(url_for('forgot_password'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/signup-landing')
def signup_landing():
    return render_template('signup_landing.html')

@app.route('/')
def index():
    return render_template('index.html')

# Generate encryption key
def generate_key():
    return Fernet.generate_key()

# Initialize encryption
def init_encryption():
    key_file = 'encryption_key.key'
    try:
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                key = f.read()
        else:
            key = generate_key()
            with open(key_file, 'wb') as f:
                f.write(key)
        return Fernet(key)
    except Exception as e:
        print(f"Error initializing encryption: {e}")
        # Fallback: generate new key
        key = generate_key()
        with open(key_file, 'wb') as f:
            f.write(key)
        return Fernet(key)

# Initialize fernet globally
fernet = init_encryption()

def get_user_db_path(username):
    """Get the path to a user's specific database file"""
    return f'tanning_{username}.db'

def init_user_db(username):
    """Initialize a new database for a specific user"""
    db_path = get_user_db_path(username)
    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    # Tanning sessions table
    c.execute('''
        CREATE TABLE IF NOT EXISTS tanning_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT NOT NULL,
            duration INTEGER NOT NULL,
            uv_level INTEGER NOT NULL,
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Tanning goals table
    c.execute('''
        CREATE TABLE IF NOT EXISTS tanning_goals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            goal_type TEXT NOT NULL,
            target_value INTEGER NOT NULL,
            current_value INTEGER DEFAULT 0,
            start_date TEXT NOT NULL,
            end_date TEXT,
            status TEXT DEFAULT 'active',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    conn.commit()
    conn.close()
    print(f"Database initialized for user: {username}")

def get_db_connection(username):
    """Get a database connection for a specific user"""
    db_path = get_user_db_path(username)
    return sqlite3.connect(db_path)

def ensure_user_db_integrity(username):
    """Ensure user's database has all required tables"""
    try:
        init_user_db(username)
        print(f"Database integrity ensured for user: {username}")
    except Exception as e:
        print(f"Error ensuring database integrity for user {username}: {e}")

def encrypt_data(data):
    """Encrypt data using Fernet"""
    if isinstance(data, str):
        data = data.encode()
    return fernet.encrypt(data)

def decrypt_data(encrypted_data):
    """Decrypt data using Fernet"""
    if isinstance(encrypted_data, str):
        encrypted_data = encrypted_data.encode()
    decrypted = fernet.decrypt(encrypted_data)
    return decrypted.decode()

def validate_password(password):
    """Validate password requirements"""
    if len(password) < 7:
        return False, "Password must be at least 7 characters long"
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
    
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    
    return True, "Password is valid"

if __name__ == '__main__':
    app.run(debug=True) 
                                                                                             
                                                                                                                                                                                                                                              
                                                                                                                                                                                                                                               