# import socketio
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, abort
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from models import app, db, User, Product, Post, Auction, Transaction, Bid, Message, Question, Answer
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


@app.errorhandler(ConnectionError)
def handle_connection_error(error):
    flash('Email-ul este deja folosit!')
    return redirect(request.referrer or url_for('/register'))


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

    def validate_email(self, address):
        existing_user_address = User.query.filter_by(
            address=address.data).first()
        if existing_user_address:
            raise ValidationError(
                'That email address already exists. Please choose a different one.')


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
            else:
                flash('Invalid username or password', 'danger')
                return redirect(url_for('login', form=form))
        else:
            flash('Invalid username or password', 'danger')
            return redirect(url_for('login', form=form))
    return render_template('login.html', form=form)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    posts = Post.query.filter_by(id_user=current_user.id_user).all()
    products = Product.query.filter_by(id_user=current_user.id_user).all()
    auctions = Auction.query.filter_by(id_user=current_user.id_user).all()
    return render_template('dashboard.html', posts=posts, products=products, auctions=auctions)


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


@app.route('/edit_data', methods=['GET', 'POST'])
@login_required
def edit_data():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        address = request.form['address']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8'),
        user = current_user
        if user is None:
            return redirect(url_for('login'))
        else:
            user.username = username
            user.email = email
            user.password = password
            user.address = address
            db.session.commit()
            return redirect(url_for('dashboard'))
    else:
        return render_template('edit_data.html')


def check_for_drugs(text):
    drug_names = ['marijuana', 'cocaine', 'heroin', 'ecstasy', 'lsd', 'methamphetamine', 'crystal meth', 'pcp',
                  'ketamine']
    for drug in drug_names:
        if drug in text.lower():
            return True
    return False


@app.route('/add_product', methods=['GET', 'POST'])
@login_required
def add_product():
    if request.method == 'POST':
        name = request.form['name']
        if check_for_drugs(name):
            flash('This product does not conform with our terms and conditions.')
            return redirect(url_for('add_product'))

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
        # image_url = request.form['image_url']
        start_date = datetime.now()
        end_date = start_date + timedelta(days=30)
        id_product = request.form['id_product']
        user = current_user
        product = Product.query.filter_by(id_product=id_product).first()
        if product is None:
            flash('This product does not exist.')
            return redirect(url_for('create_post'))
        if product.id_user != user.id_user:
            flash('This product does not belong to you.')
            return redirect(url_for('create_post'))
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


@app.route('/posts_filter_by_category/<string:category>')
def posts_filter_by_category(category):
    posts = Post.query.filter_by(category=category).all()
    return render_template('posts.html', posts=posts)


@app.route('/posts_filter_by_price/<int:lower_price>/<int:upper_price>')
def posts_filter_by_price(lower_price, upper_price):
    posts = Post.query.filter(Post.price >= lower_price, Post.price <= upper_price).all()
    return render_template('posts.html', posts=posts, lower_price=lower_price, upper_price=upper_price)


@app.route('/posts_filter_descending_by_price')
def posts_filter_descending_by_price():
    posts = Post.query.order_by(Post.price.desc()).all()
    return render_template('posts.html', posts=posts)


@app.route('/posts_filter_ascending_by_price')
def posts_filter_ascending_by_price():
    posts = Post.query.order_by(Post.price.asc()).all()
    return render_template('posts.html', posts=posts)


@app.route('/posts_filter_by_date/<string:date>')
def posts_filter_by_date(date):
    posts = Post.query.filter(Post.start_date <= date, Post.end_date >= date).all()
    return render_template('posts.html', posts=posts)


@app.route('/posts/<int:post_id>', methods=['POST', 'GET'])
def get_post(post_id):
    # Get the post with the specified ID from the database
    post = Post.query.get_or_404(post_id)
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


######Auction######
@app.route('/auctions/create', methods=['GET', 'POST'])
@login_required
def create_auction():
    if request.method == 'POST':
        id_user = current_user.id_user
        title = request.form['title']
        starting_price = request.form['starting_price']
        start_date = request.form['start_date']
        end_date = request.form['end_date']
        id_product = request.form['id_product']
        description = request.form['description']
        if start_date > end_date:
            flash('The start date must be before the end date!', 'warning')
            return redirect(url_for('create_auction'))
        if start_date < datetime.now():
            flash('The start date must be in the future!', 'warning')
            return redirect(url_for('create_auction'))
        if end_date < datetime.now():
            flash('The end date must be in the future!', 'warning')
            return redirect(url_for('create_auction'))
        if int(starting_price) < 0:
            flash('The price must be positive!', 'warning')
            return redirect(url_for('create_auction'))
        product = Product.query.filter_by(id_product=id_product).first()
        if product is None:
            flash('This product does not exist.')
            return redirect(url_for('create_auction'))
        if product.id_user != id_user:
            flash('This product does not belong to you.')
            return redirect(url_for('create_auction'))

        auction = Auction(description=description, title=title, id_user=id_user, starting_price=starting_price,
                          curent_price=starting_price,
                          start_date=start_date, end_date=end_date, id_product=id_product)
        db.session.add(auction)
        db.session.commit()
        return redirect(url_for('auctions'))
    else:
        return render_template('create_auction.html', datetime=datetime)


@app.route('/auctions', methods=['GET'])
def auctions():
    auctions = Auction.query.all()
    if auctions is None:
        flash('There are no auctions.')
        return redirect(url_for('index'))
    return render_template('auctions.html', auctions=auctions)


@app.route('/auctions/<int:id_auction>/delete', methods=['POST', 'GET'])
@login_required
def delete_auction(id_auction):
    auction = Auction.query.get_or_404(id_auction)
    if auction.id_user != current_user.id_user:
        flash('You cannot delete this auction!', 'warning')
        return redirect(url_for('auctions'))
    db.session.delete(auction)
    db.session.commit()
    flash('You have successfully deleted the auction!', 'success')
    return redirect(url_for('auctions'))


@app.route('/auctions_ordered_ascending_by_end_date')
def auctions_order_by_end_date():
    auctions = Auction.query.order_by(Auction.end_date.asc()).all()

    return render_template('auctions.html', auctions=auctions)


@app.route('/auctions_ordered_descending_by_current_price')
def auctions_order_by_current_price():
    auctions = Auction.query.order_by(Auction.curent_price.desc()).all()
    return render_template('auctions.html', auctions=auctions)


@app.route('/auctions_with_status_open')
def auctions_with_status_open():
    auctions = Auction.query.filter_by(status='open').all()
    if auctions is None:
        flash('There are no auctions.')
        return redirect(url_for('index'))
    return render_template('auctions.html', auctions=auctions)


@app.route('/auctions_with_status_closed')
def auctions_with_status_closed():
    auctions = Auction.query.filter_by(status='closed').all()
    if auctions is None:
        flash('There are no auctions.')
        return redirect(url_for('index'))
    return render_template('auctions.html', auctions=auctions)


@app.route('/auctions_with_status_open_with_current_price_between<int:price1>/<int:price2>')
def auctions_with_status_open_with_current_price_between(price1, price2):
    if price1 > price2:
        flash('The lower price must be lower than the upper price!', 'warning')
        return redirect(url_for('auctions'))
    auctions = Auction.query.filter(Auction.status == 'open', Auction.curent_price.between(price1, price2)).all()
    return render_template('auctions.html', auctions=auctions, lower_price=price1, upper_price=price2)


@app.route('/auctions/<int:id_auction>', methods=['GET'])
def get_auction(id_auction):
    auction = Auction.query.get_or_404(id_auction)
    return render_template('auction.html', auction=auction, id_auction=id_auction)


@app.route('/auctions/<int:id_auction>/create_bid', methods=['GET'])
def create_bid(id_auction):
    return render_template('create_bid.html', id_auction=id_auction)


@app.route('/auctions/<int:auction_id>/add_bid', methods=['POST', 'GET'])
@login_required
def add_bid(auction_id):
    if request.method == 'POST':
        auction = Auction.query.get_or_404(auction_id)
        product = Product.query.get_or_404(auction.id_product)
        if auction.id_user == current_user.id_user:
            flash('You cannot bid on your own product!', 'warning')
            return redirect(url_for('get_auction', id_auction=auction_id))
        elif auction.status == 'closed':
            flash('This product is already sold!', 'warning')
            return redirect(url_for('get_auction', id_auction=auction_id))
        else:
            id_user = current_user.id_user
            price = request.form['price']
            bid = Bid(id_user=id_user, price=price, id_auction=auction_id)
            db.session.add(bid)
            if int(price) > int(auction.curent_price):
                auction.curent_price = bid.price
                auction.winner_id = bid.id_user
                db.session.commit()
                flash('You have successfully bid on the product!', 'success')
                return redirect(url_for('auctions'))
            else:
                flash('Your bid is lower than the current price!', 'warning')
                return redirect(url_for('get_auction', id_auction=auction_id))
    else:
        return redirect(url_for('add_bid', auction_id=auction_id))


@app.route('/auctions/<int:auction_id>/close', methods=['POST', 'GET'])
@login_required
def close_auction(auction_id):
    if request.method == 'POST':
        auction = Auction.query.get_or_404(auction_id)
        product = Product.query.get_or_404(auction.id_product)
        if auction.id_user == current_user.id_user:
            auction.status = 'closed'
            product.id_user = auction.winner_id
            transaction = Transaction(buyer_id=auction.winner_id, seller_id=auction.id_user,
                                      product_id=auction.id_product,
                                      price=auction.curent_price)
            db.session.add(transaction)
            db.session.commit()
            flash('You have successfully closed the auction!', 'success')
            return redirect(url_for('auctions'))
        else:
            flash('You cannot close this auction!', 'warning')
            return redirect(url_for('get_auction', auction_id=auction_id))
    else:
        return redirect(url_for('get_auction', auction_id=auction_id))


def encrypt(text):
    swapped_text = ''
    for i in range(0, len(text), 5):
        chunk = text[i:i + 5]
        if len(chunk) == 5:
            swapped_chunk = chr(ord(chunk[0]) + i) + chunk[3] + chunk[2] + chunk[1] + chunk[4]
            swapped_text += swapped_chunk
        else:
            swapped_text += chunk

    return swapped_text


def decrypt(text):
    original_text = ''
    for i in range(0, len(text), 5):
        chunk = text[i:i + 5]
        if len(chunk) == 5:
            original_chunk = chr(ord(chunk[0]) - i) + chunk[3] + chunk[2] + chunk[1] + chunk[4]
            original_text += original_chunk
        else:
            original_text += chunk

    return original_text


@app.route('/view_questions', methods=['GET', 'POST'])
def questions():
    dict = {}
    questions = Question.query.all()
    for question in questions:
        raspunsuri = Answer.query.filter_by(id_question=question.id_question)
        for raspuns in raspunsuri:
            if question.question_text not in dict:
                dict[question.question_text] = [raspuns.answer_text]
            else:
                dict[question.question_text].append(raspuns.answer_text)
    return render_template('view_questions.html', intrebari_raspunsuri=dict)


# Functie pentru trimis mesaje
@app.route('/send_message', methods=['GET', 'POST'])
@login_required
def send_message():
    # Parse request data
    if request.method == 'POST':
        sender_id = current_user.id_user
        receiver_name = request.form['receiver_name']
        receiver_id = User.query.filter_by(username=receiver_name).first()
        if receiver_id is None:
            flash('Nume gresit')
            return redirect(url_for('send_message'))

        receiver_id = receiver_id.id_user
        message_text = request.form['message_text']
        message_text = encrypt(message_text)
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

    mesaje_dict = {}

    # aici sunt mesajele trimise
    # ele au sender id-ul meu
    # o sa aiba si reciever id-ul persoanei cu care m-am conversat
    for mesaj in sent_messages:
        mesaj.message_text = decrypt(mesaj.message_text)
        receiver = User.query.filter_by(id_user=mesaj.receiver_id).first()
        if receiver.username not in mesaje_dict:
            mesaje_dict[receiver.username] = {
                'messages': [{'text': mesaj.message_text, 'time': mesaj.message_time, 's/r': 's'}]}
        else:
            mesaje_dict[receiver.username]['messages'].append(
                {'text': mesaj.message_text, 'time': mesaj.message_time, 's/r': 's'})

    # Acum avem toate mesajele pe care le-am trimis
    # Ne trebuie mesajele pe care le-am primit

    for mesaj in received_messages:
        mesaj.message_text = decrypt(mesaj.message_text)
        sender = User.query.filter_by(id_user=mesaj.sender_id).first()
        if sender.username not in mesaje_dict:
            mesaje_dict[sender.username] = {
                'messages': [{'text': mesaj.message_text, 'time': mesaj.message_time, 's/r': 'r'}]}
        else:
            mesaje_dict[sender.username]['messages'].append(
                {'text': mesaj.message_text, 'time': mesaj.message_time, 's/r': 'r'})

    sorted_dict = dict(sorted(mesaje_dict.items(), key=lambda x: x[1]['messages'][-1]['time']))

    for key in mesaje_dict.keys():
        sorted_dict[key]['messages'] = sorted(mesaje_dict[key]['messages'], key=lambda x: x['time'])

    return render_template('view_messages.html', messages=sorted_dict)


@app.route('/')
def home():
    return render_template("index.html")


if __name__ == '__main__':
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True)
