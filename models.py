from sqlalchemy import Enum
from flask import Flask
from flask_login import  UserMixin
from flask_sqlalchemy import SQLAlchemy
from datetime import timedelta, datetime

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:mirceapetcu@localhost/mds_db'
app.secret_key = "proiect_Scolar"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.permanent_session_lifetime = timedelta(hours=1)

db = SQLAlchemy(app)


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id_user = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100),unique = True, nullable=False)
    username = db.Column(db.String(40),unique = True, nullable=False)
    name = db.Column(db.String(100))
    address = db.Column(db.String(100))
    posts = db.relationship('Post', backref='author', lazy=True)
    role = db.Column(Enum('user', 'admin'), nullable=False, default='user')
    last_active = db.Column(db.DateTime)

    def update_last_active(self):
        self.last_active = datetime.now()
        db.session.commit()

    def is_authenticated(self):
        if self.last_active is not None and datetime.utcnow() - self.last_active <= timedelta(hours=1):
            return True
        return False

    def get_id(self):
        return str(self.id_user)


class Product(db.Model):
    __tablename__ = 'products'
    id_product = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    price = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(100))
    id_user = db.Column(db.Integer, db.ForeignKey('users.id_user'), nullable=False)

class Post(db.Model):
    __tablename__ = 'posts'
    id_post = db.Column(db.Integer, primary_key = True)
    title = db.Column(db.String(100))
    description = db.Column(db.Text)
    id_user = db.Column(db.Integer, db.ForeignKey('users.id_user'), nullable=False)
    price = db.Column(db.Float, nullable=False)
    start_date = db.Column(db.DateTime)
    end_date = db.Column(db.DateTime)
    id_product = db.Column(db.Integer, db.ForeignKey('products.id_product'), nullable=False)
    status = db.Column(Enum('active', 'closed'), nullable=False, default='active')

class Auction(db.Model):
    __tablename__ = 'auctions'
    id_auction = db.Column(db.Integer, primary_key = True)
    id_user = db.Column(db.Integer, db.ForeignKey('users.id_user'), nullable=False)
    starting_price = db.Column(db.Float, nullable=False)
    curent_price = db.Column(db.Float)
    start_date = db.Column(db.DateTime)
    end_date = db.Column(db.DateTime)
    id_product = db.Column(db.Integer, db.ForeignKey('products.id_product'), nullable=False)

class Transaction(db.Model):
    __tablename__ = 'transactions'
    id_transaction = db.Column(db.Integer, primary_key=True)
    buyer_id = db.Column(db.Integer, db.ForeignKey('users.id_user'),nullable=False)
    seller_id = db.Column(db.Integer, db.ForeignKey('users.id_user'),nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id_product'),nullable=False)
    price = db.Column(db.Float, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)

with app.app_context():
    # Create database tables
    db.create_all()
