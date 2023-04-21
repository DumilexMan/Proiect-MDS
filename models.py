from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin
from flask_sqlalchemy import SQLAlchemy
from datetime import timedelta


app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:mirceapetcu@localhost/mds_db'
app.secret_key = "secret_key"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.permanent_session_lifetime = timedelta(hours=4)

db = SQLAlchemy(app)


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id_user = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    username = db.Column(db.String(40),unique = True)
    name = db.Column(db.String(100))
    address = db.Column(db.String(100))
    posts = db.relationship('Post', backref='author', lazy=True)
    role = db.Column(db.String(20), default='user')


class Product(db.Model):
    __tablename__ = 'products'
    id_product = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    price = db.Column(db.Float)
    category = db.Column(db.String(100))

class Post(db.Model):
    __tablename__ = 'posts'
    id_listing = db.Column(db.Integer, primary_key = True)
    title = db.Column(db.String(100))
    description = db.Column(db.Text)
    id_user = db.Column(db.Integer, db.ForeignKey('users.id_user'), nullable=False)
    price = db.Column(db.Float)
    start_date = db.Column(db.DateTime)
    end_date = db.Column(db.DateTime)
    id_product = db.Column(db.Integer, db.ForeignKey('products.id_product'), nullable=False)

class Auction(db.Model):
    __tablename__ = 'auctions'
    id_auction = db.Column(db.Integer, primary_key = True)
    id_user = db.Column(db.Integer, db.ForeignKey('users.id_user'), nullable=False)
    starting_price = db.Column(db.Float)
    curent_price = db.Column(db.Float)
    start_date = db.Column(db.DateTime)
    end_date = db.Column(db.DateTime)
    id_product = db.Column(db.Integer, db.ForeignKey('products.id_product'), nullable=False)


with app.app_context():
    # Create database tables
    db.create_all()
