from flask import Flask, render_template, request, redirect, url_for, flash,jsonify, session
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from models import app, db, User, Product, Post, Auction, Transaction
import hashlib
from datetime import datetime, timedelta
import json
from flask import request
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt



login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
bcrypt = Bcrypt()

class RegisterForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=30)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=40)], render_kw={"placeholder": "Password"})
    email = StringField(validators=[
                           InputRequired(), Length(min=4, max=50)], render_kw={"placeholder": "Email"})
    name = StringField(validators=[
                           InputRequired(), Length(min=4, max=30)], render_kw={"placeholder": "Name"})
    address = StringField(validators=[
                           InputRequired(), Length(min=4, max=100)], render_kw={"placeholder": "Address"})
    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')


class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')

@login_manager.user_loader
def load_user(id_user):
    return User.query.get(int(id_user))



@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@ app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            email=form.email.data,
            name=form.name.data,
            address=form.address.data,
            password=bcrypt.generate_password_hash(form.password.data).decode('utf-8'),
            role='user',
            last_active=datetime.utcnow()
        )

        db.session.add(user)
        db.session.commit()

        flash('Your account has been created! You are now able to log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


def get_user_by_username(username):
    return User.query.filter_by(username=username).first()

@app.route('/add_product', methods=['GET', 'POST'])
@login_required
def add_product():
    if request.method == 'POST':
        name = request.form['name']
        price = request.form['price']
        category = request.form['category']
        user = get_user_by_username(session['user'])
        if user is None:
            return redirect(url_for('login'))
        else:
            # Crează un obiect de tipul Product cu datele primite prin POST și salvează-l în baza de date
            product = Product(name=name,price = price, category = category,
                              id_user=user.id_user)
            db.session.add(product)
            db.session.commit()

            # Redirecționează utilizatorul către pagina de afișare a produselor
            return redirect(url_for('products'))
    else:
        return render_template('add_product.html')


# ruta pentru crearea unui nou anunt
@app.route('/create_post', methods=['GET', 'POST'])
@login_required
def create_post():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        price = request.form['price']
        image_url = request.form['image_url']
        start_date = datetime.now()
        end_date = start_date + timedelta(days=30)
        id_product = request.form['id_product']
        user = get_user_by_username(session['user'])
        if user is None:
            return redirect(url_for('login'))
        else:
            post = Post(title=title, description=description, id_user= user.id_user, price=price, start_date=start_date, end_date=end_date, id_product=id_product)
            db.session.add(post)
            db.session.commit()

            return redirect(url_for('posts_ownded_by_user'))
    else:
        return render_template('create_post.html',datetime = datetime)


@app.route('/products')
def products():
    products = Product.query.all()
    product_list = []
    for product in products:
        product_dict = product.__dict__
        del product_dict['_sa_instance_state']  # Remove the SQLAlchemy state from the dictionary
        product_list.append(product_dict)
    return jsonify(product_list)

@app.route('/posts_ownded_by_user')
@login_required
def posts_ownded_by_user():
    user = get_user_by_username(session['user'])
    posts = Post.query.filter_by(id_user=user.id_user).all()
    post_list = []
    for post in posts:
        post_dict = post.__dict__
        del post_dict['_sa_instance_state']
        post_list.append(post_dict)
    return jsonify(post_list)

@app.route('/posts')
def posts():
    posts = Post.query.all()
    post_list = []
    for post in posts:
        post_dict = post.__dict__
        del post_dict['_sa_instance_state']
        post_list.append(post_dict)
    return jsonify(post_list)


@app.route('/posts/<int:post_id>', methods=['GET'])
def get_post(post_id):
    # Get the post with the specified ID from the database
    post = Post.query.get_or_404(post_id)

    # Return a JSON response with the post details
    return jsonify({
        'id': post.id_post,
        'title': post.title,
        'description': post.description,
        'price': post.price,
        'product_id': post.id_product,
        'status': post.status,
        'start_date': post.start_date,
        'end_date': post.end_date,
        'id_user': post.id_user
    }), 200


@app.route('/posts/<int:id_post>/buy', methods=['POST'])
@login_required
def buy_product(id_post):
    post = Post.query.get_or_404(id_post)
    product = Product.query.get_or_404(post.id_product)
    if post.id_user == current_user.id_user:
        flash('You cannot buy your own product!', 'warning')
        return redirect(url_for('get_post', post_id=id_post))
    elif post.status == 'closed':
        flash('This product is already sold!', 'warning')
        return redirect(url_for('get_post', post_id=id_post))
    else:
        transaction = Transaction(buyer_id=current_user.id_user, seller_id = post.id_user, product_id = post.id_product, price = post.price)
        db.session.add(transaction)
        product.id_user = current_user.id_user
        db.session.commit()
        flash('You have successfully bought the product!', 'success')
        return redirect(url_for('get_post', post_id=id_post))


    # Update the status of the post to "sold"
    post = Post.query.get_or_404(post_id)
    post.status = "closed"
    db.session.commit()

    return jsonify({'message': 'Transaction created successfully'}), 201

@app.route('/')
def home():
    return render_template("index.html")

if __name__ == '__main__':
    app.run(debug=True)
