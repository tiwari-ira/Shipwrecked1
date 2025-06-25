# TanTime - Tanning App

A Flask-based web application for managing tanning sessions and user accounts.

## Features

- User registration and login with email verification
- Password reset functionality
- User dashboard
- Email notifications
- Secure authentication system

## Setup

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Configure email settings in `config.py`:
   ```python
   MAIL_SERVER = 'smtp.gmail.com'
   MAIL_PORT = 587
   MAIL_USE_TLS = True
   MAIL_USERNAME = 'your-email@gmail.com'
   MAIL_PASSWORD = 'your-app-password'
   ```

3. Run the application:
   ```bash
   python app.py
   ```

4. Open your browser and go to `http://127.0.0.1:5000`

## File Structure

- `app.py` - Main Flask application
- `config.py` - Email configuration
- `requirements.txt` - Python dependencies
- `templates/` - HTML templates
- `static/` - CSS and static files
- `instance/` - Database files

## Database

The app uses SQLite databases:
- `instance/users.db` - User accounts and authentication
- `tanning_[username].db` - Individual user data 