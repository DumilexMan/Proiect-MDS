
from sqlalchemy import Enum
from flask import Flask
from flask_login import  UserMixin
from flask_sqlalchemy import SQLAlchemy
from datetime import timedelta, datetime

app = Flask(__name__)

<<<<<<< Updated upstream
<<<<<<< Updated upstream
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root@localhost/test'
=======
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/test'
>>>>>>> Stashed changes
=======
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/test'
>>>>>>> Stashed changes
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
    buyer_rating=db.Column(db.Float,nullable=False,default=0)
    seller_rating = db.Column(db.Float, nullable=False, default=0)
    nr_buyer_ratings= db.Column(db.Integer, nullable=False, default=0)
    nr_seller_ratings = db.Column(db.Integer, nullable=False, default=0)

    def update_last_active(self):
        self.last_active = datetime.now()
        db.session.commit()

    def is_authenticated(self):
        if self.last_active is not None and datetime.utcnow() - self.last_active <= timedelta(hours=1):
            return True
        return False

    def get_id(self):
        return str(self.id_user)


class Feedback(db.Model):
    __tablename__ = 'feedbacks'
    id_feedback = db.Column(db.Integer, primary_key=True)
    id_seller = db.Column(db.Integer, db.ForeignKey('users.id_user'), nullable=False)
    id_buyer = db.Column(db.Integer, db.ForeignKey('users.id_user'), nullable=False)
    id_product= db.Column(db.Integer, db.ForeignKey('products.id_product'), nullable=False)
    rating= db.Column(db.Integer, nullable=False)
    feedback_text = db.Column(db.String(1000), nullable=False)
    feedback_time = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.VARCHAR(10), nullable=False, default='vanzator')



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
    status = db.Column(Enum('active', 'closed'), nullable=False, default='active')
    winner_id = db.Column(db.Integer, db.ForeignKey('users.id_user'), default = None,nullable=True)
    title = db.Column(db.String(100),nullable=False)
    description = db.Column(db.Text,nullable=False)

class Question(db.Model):
    __tablename__ = 'questions'
    id_question = db.Column(db.Integer, primary_key = True)
    question_text = db.Column(db.String(1000), nullable=False)
    question_time = db.Column(db.DateTime, default=datetime.utcnow)
    id_user = db.Column(db.Integer, db.ForeignKey('users.id_user'), nullable=False)
class Answer(db.Model):
 __tablename__ = 'answers'
 id_answer = db.Column(db.Integer, primary_key = True)
 answer_text = db.Column(db.String(1000), nullable=False)
 answer_time = db.Column(db.DateTime, default=datetime.utcnow)
 id_question = db.Column(db.Integer, db.ForeignKey('questions.id_question'), nullable=False)
 id_user = db.Column(db.Integer, db.ForeignKey('users.id_user'), nullable=False)
class Bid(db.Model):
    __tablename__ = 'bids'
    id_bid = db.Column(db.Integer, primary_key = True)
    id_user = db.Column(db.Integer, db.ForeignKey('users.id_user'), nullable=False)
    id_auction = db.Column(db.Integer, db.ForeignKey('auctions.id_auction'), nullable=False)
    price = db.Column(db.Float, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)

class Transaction(db.Model):
    __tablename__ = 'transactions'
    id_transaction = db.Column(db.Integer, primary_key=True)
    buyer_id = db.Column(db.Integer, db.ForeignKey('users.id_user'),nullable=False)
    seller_id = db.Column(db.Integer, db.ForeignKey('users.id_user'),nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id_product'),nullable=False)
    price = db.Column(db.Float, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)


class Message(db.Model):
    __tablename__ = 'Message'
    id_message = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id_user'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.id_user'), nullable=False)
    message_text = db.Column(db.String(1000), nullable=False)
    message_time = db.Column(db.DateTime, default=datetime.utcnow)

with app.app_context():
    # Create database tables
    db.create_all()
