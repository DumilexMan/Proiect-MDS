from flask import Flask,jsonify
# from flask_mysqldb import MySQL
from flask import render_template
# from flask_mysqldb import MySQL
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin
from flask_sqlalchemy import SQLAlchemy


app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:mirceapetcu@localhost/mds_db'

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
    description = db.Column(db.Text)
    price = db.Column(db.Float)

class Post(db.Model):
    __tablename__ = 'posts'
    id_listing = db.Column(db.Integer, primary_key = True)
    title = db.Column(db.String(100))
    description = db.Column(db.Text)
    id_user = db.Column(db.Integer, db.ForeignKey('users.id_user'), nullable=False)
    price = db.Column(db.Float)
    start_date = db.Column(db.DateTime)
    end_date = db.Column(db.DateTime)

class Auction(db.Model):
    __tablename__ = 'auctions'
    id_auction = db.Column(db.Integer, primary_key = True)
    id_user = db.Column(db.Integer, db.ForeignKey('users.id_user'), nullable=False)
    starting_price = db.Column(db.Float)
    curent_price = db.Column(db.Float)
    start_date = db.Column(db.DateTime)
    end_date = db.Column(db.DateTime)


with app.app_context():
    # Create database tables
    db.create_all()

# Initialize the Flask-Login extension
login_manager = LoginManager()
login_manager.init_app(app)

# Define the user_loader function
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/produse')
def get_produse():
    rows = Product.query.all()
    return jsonify(rows)

@app.route('/')
def home():
    return render_template("index.html")

if __name__ == '__main__':
    app.run(debug=True)
