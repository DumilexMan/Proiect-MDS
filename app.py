# import socketio
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from models import app, db, User, Product, Post, Auction, Transaction, Message
import hashlib
from datetime import datetime, timedelta
import json
from flask import request
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from flask_socketio import SocketIO, emit
from flask_socketio import SocketIO, join_room
from flask_socketio import SocketIO, leave_room

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
bcrypt = Bcrypt()
socketio = SocketIO(app)


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


@app.route('/register', methods=['GET', 'POST'])
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
        user = current_user
        if user is None:
            return redirect(url_for('login'))
        else:
            # Crează un obiect de tipul Product cu datele primite prin POST și salvează-l în baza de date
            product = Product(name=name, price=price, category=category,
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
        user = current_user
        if user is None:
            return redirect(url_for('login'))
        else:
            post = Post(title=title, description=description, id_user=user.id_user, price=price, start_date=start_date,
                        end_date=end_date, id_product=id_product)
            db.session.add(post)
            db.session.commit()

            return redirect(url_for('posts_ownded_by_user'))
    else:
        return render_template('create_post.html', datetime=datetime)


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
    user = current_user
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
    return render_template('posts.html', posts=posts)


@app.route('/posts/<int:post_id>', methods=['POST', 'GET'])
def get_post(post_id):
    # Get the post with the specified ID from the database
    post = Post.query.get_or_404(post_id)
    # if request.method == 'POST':
    #     message = request.form['message']
    #     owner_username = request.form['owner_username']
    #     socketio.emit('direct_message', {'message': message, 'ownerUsername': owner_username})
    return render_template('post.html', post=post)


@app.route('/posts/<int:id_post>/buy', methods=['POST', 'GET'])
@login_required
def buy_product(id_post):
    if request.method == 'POST':
        post = Post.query.get_or_404(id_post)
        product = Product.query.get_or_404(post.id_product)
        if post.id_user == current_user.id_user:
            flash('You cannot buy your own product!', 'warning')
            return redirect(url_for('get_post', post_id=id_post))
        elif post.status == 'closed':
            flash('This product is already sold!', 'warning')
            return redirect(url_for('get_post', post_id=id_post))
        else:
            transaction = Transaction(buyer_id=current_user.id_user, seller_id=post.id_user, product_id=post.id_product,
                                      price=post.price)
            db.session.add(transaction)
            product.id_user = current_user.id_user
            post.status = "closed"
            db.session.commit()
            flash('You have successfully bought the product!', 'success')
            return redirect(url_for('posts'))

    else:
        return redirect(url_for('get_post', post_id=id_post))


@app.route('/message')
@login_required
def message():
    return render_template('message.html', username=current_user.username)


@app.route('/')
def home():
    return render_template("index.html")


from flask import request, jsonify
from flask_socketio import emit


#
# @app.route('/send_message', methods=['POST'])
# def send_message():
#     message = request.json['message']
#     post_id = request.json['post_id']
#     user_id = request.json['user_id']
#
#     # Send email message to post owner using SendGrid or another email provider
#     # ...
#
#     return jsonify({'success': True})
#
#
# @app.route('/receive_message', methods=['POST'])
# def receive_message():
#     message = request.json['message']
#     post_id = request.json['post_id']
#     user_id = request.json['user_id']
#
#     emit('message_received', {'message': message, 'user_id': user_id}, room=post_id)
#
#     return jsonify({'success': True})

#######################################################
@socketio.on('join')
def handle_join(data):
    room = data['post_id']
    join_room(room)


# @socketio.on('send_message')
# def handle_send_message(data):
#     emit('receive_message', data, room=data['post_id'])

#######################################################

@app.route('/send_message', methods=['GET', 'POST'])
@login_required
def send_message():
    # Parse request data
    if request.method == 'POST':
        sender_id = current_user.id_user
        receiver_id = request.form['receiver_id']
        message_text = request.form['message_text']

        # Validate request data
        if not receiver_id or not message_text:
            return 'Toate câmpurile sunt obligatorii!', 400

        # Create a new message
        new_message = Message(sender_id=sender_id,
                              receiver_id=receiver_id,
                              message_text=message_text)

        # Add message to database
        db.session.add(new_message)
        db.session.commit()

        # Return success message
        flash('Mesajul a fost trimis cu succes!', 'success')
        return redirect(url_for('send_message'))

    else:
        return render_template('send_message.html')


# Functie pentru a vizualiza mesajele
# Se foloseste de id-ul personal al utilizatorului logat
# Este nevoie sa fie logat
@app.route('/messages', methods=['POST', 'GET'])
@login_required
def messages():
    # Obtine utilizatorul curent
    user = current_user

    # Obține mesajele primite
    received_messages = Message.query.filter_by(receiver_id=user.id_user).all()

    # Obține mesajele trimise
    sent_messages = Message.query.filter_by(sender_id=user.id_user).all()

    # Creeaza un dictionar cu toate mesajele grupate dupa utilizatorul corespondent
    # messages_dict = {}
    # for message in received_messages:
    #     if message.sender_id not in messages_dict:
    #         messages_dict[sender.username] = {'username': sender.username, 'messages': [message.message_text]}
    #     else:
    #         messages_dict[sender.username]['messages'].append(message.message_text)
    #
    # for message in sent_messages:
    #     receiver = User.query.filter_by(id_user=message.receiver_id).first()
    #     if message.receiver_id not in messages_dict:
    #         messages_dict[receiver.username] = {'username': receiver.username, 'messages': [message.message_text]}
    #     else:
    #         messages_dict[receiver.username]['messages'].append(message.message_text)

    # Rendereaza pagina html cu mesajele

    # Cum o sa fac:
    # O sa adun toata conversatia cu cineva si ii pun ca cheie id-ul persoanei careia i-a fost trimis un mesaj
    # O sa le ordonez dupa data ca sa fie aranjate frumos

    mesaje_dict = {}

    # aici sunt mesajele trimise
    # ele au sender id-ul meu
    # o sa aiba si reciever id-ul persoanei cu care m-am conversat
    for mesaj in sent_messages:
        receiver = User.query.filter_by(id_user=mesaj.receiver_id).first()
        if receiver.username not in mesaje_dict:
            mesaje_dict[receiver.username] = {'messages': [{'text': mesaj.message_text, 'time': mesaj.message_time}]}
        else:
            mesaje_dict[receiver.username]['messages'].append({'text': mesaj.message_text, 'time': mesaj.message_time})

    # Acum avem toate mesajele pe care le-am trimis
    # Ne trebuie mesajele pe care le-am primit

    for mesaj in received_messages:
        sender = User.query.filter_by(id_user=mesaj.sender_id).first()
        if sender.username not in mesaje_dict:
            mesaje_dict[sender.username] = {'messages': [{'text': mesaj.message_text, 'time': mesaj.message_time}]}
        else:
            mesaje_dict[sender.username]['messages'].append({'text': mesaj.message_text, 'time': mesaj.message_time})

    sorted_dict = dict(sorted(mesaje_dict.items(), key=lambda x: x[1]['messages'][-1]['time']))

    return render_template('view_messages.html', messages=sorted_dict)


#
# @app.route('/view_messages')
# @login_required
# def view_message():
#     id_us = current_user.id_user
#     messages = Message.query.filter_by(receiver_id=id_us).all()
#     messages += Message.query.filter_by(sender_id=id_us).all()
#     # s_name =
#     # nume sender
#     user = User.query.filter_by(id_user=id_us).first()
#     r_name = user.username if user else None
#     # nume receiver
#
#     return render_template('view_messages.html', reciever=r_name, messages=messages)


@app.route('/view_messages/<int:sender_id>/<int:receiver_id>')
def messages_pers(sender_id, receiver_id):
    sender_id = current_user.id_user
    sender = User.query.get(sender_id)
    receiver = User.query.get(receiver_id)
    messages = Message.query.filter_by(receiver_id=receiver_id).all()

    return render_template('view_messages.html', sender=sender, receiver=receiver, messages=messages)


if __name__ == '__main__':
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True)
