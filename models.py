# models.py
# Define your SQLAlchemy models here (User, Session, etc.)

# Example:
# from flask_sqlalchemy import SQLAlchemy
# db = SQLAlchemy()                               
# class User(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     ... 

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

from app import app

db = SQLAlchemy(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    skin_type = db.Column(db.String(10), nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password) 