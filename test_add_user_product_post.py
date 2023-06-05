import unittest
from datetime import datetime

from flask import Flask
from werkzeug.security import generate_password_hash

from app import app, LoginForm, bcrypt
from models import db, User, Product, Post
from flask_testing import TestCase
from flask_login import current_user



class ModelsTestCase(unittest.TestCase):
    def setUp(self):
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        app.config['TESTING'] = True
        self.app = app.test_client()
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()

    def test_user_model(self):
        user = User(
            email='test@example.com',
            password='password',
            username='testuser',
            name='Test User',
            address='Test Address',
            role='user',
            last_active=datetime.utcnow()
        )

        db.session.add(user)
        db.session.commit()

        retrieved_user = User.query.filter_by(username='testuser').first()
        self.assertIsNotNone(retrieved_user)
        self.assertEqual(retrieved_user.email, 'test@example.com')
        self.assertEqual(retrieved_user.name, 'Test User')
        self.assertEqual(retrieved_user.address, 'Test Address')
        self.assertEqual(retrieved_user.role, 'user')
        self.assertIsNotNone(retrieved_user.last_active)

    def test_product_model(self):
        product = Product(
            name='Test Product',
            price=10.99,
            category='Test Category',
            id_user=1
        )

        db.session.add(product)
        db.session.commit()

        retrieved_product = Product.query.filter_by(name='Test Product').first()
        self.assertIsNotNone(retrieved_product)
        self.assertEqual(retrieved_product.price, 10.99)
        self.assertEqual(retrieved_product.category, 'Test Category')
        self.assertEqual(retrieved_product.id_user, 1)

    def test_post_model(self):
        post = Post(
            title='Test Post',
            description='Test Description',
            id_user=1,
            price=9.99,
            start_date=datetime.utcnow(),
            end_date=datetime.utcnow(),
            id_product=1,
            status='active'
        )

        db.session.add(post)
        db.session.commit()

        retrieved_post = Post.query.filter_by(title='Test Post').first()
        self.assertIsNotNone(retrieved_post)
        self.assertEqual(retrieved_post.description, 'Test Description')
        self.assertEqual(retrieved_post.id_user, 1)
        self.assertEqual(retrieved_post.price, 9.99)
        self.assertIsNotNone(retrieved_post.start_date)
        self.assertIsNotNone(retrieved_post.end_date)
        self.assertEqual(retrieved_post.id_product, 1)
        self.assertEqual(retrieved_post.status, 'active')


if __name__ == '__main__':
    unittest.main()
