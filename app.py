from flask import Flask, render_template, request, redirect, url_for, flash,jsonify, session
from flask_login import  LoginManager,login_user, logout_user, login_required, UserMixin
from flask_sqlalchemy import SQLAlchemy
from models import app, db, User, Product, Post, Auction
import hashlib


login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        username = request.form['username']
        name = request.form['name']
        address = request.form['address']

        # Generăm un hash SHA-256 pentru parolă
        password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()

        user = User(email=email, password=password_hash, username=username, name=name, address=address)

        db.session.add(user)
        db.session.commit()

        session.permanent = True
        session['user'] = username

        return redirect(url_for('dashboard'))
    else:
        return render_template('register.html')


@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username, password=password).first()
        if user:
            session.permanent = True
            session['user'] = username

            return redirect(url_for('dashboard'))
        else:
            return redirect(url_for('login'))
    else:
        return render_template('login.html')


@app.route('/dashboard')
# @login_required
def dashboard():
    if 'user' in session:
        username = session['user']
        user = User.query.filter_by(username=username).first()
        if user is not None:
            # Utilizatorul este autentificat
            # Afisati pagina de bord aici
            return render_template('dashboard.html', current_user=user)
        else:
            # Utilizatorul nu exista in baza de date
            return redirect(url_for('login'))
    else:
        # Utilizatorul nu este autentificat
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('home'))


@app.route('/produse')
def get_produse():
    rows = Product.query.all()
    return jsonify(rows)

@app.route('/')
def home():
    return render_template("index.html")

if __name__ == '__main__':
    app.run(debug=True)
