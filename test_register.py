import unittest

from flask import Flask
from flask import url_for
from flask_testing import TestCase

from app import app,RegisterForm
from models import User,db
from flask_login import current_user


class RegistrationTestCase(TestCase):
    def create_app(self):
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        return app

    def setUp(self):
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()

    def test_registration(self):
        # Create a test user
        username = 'testuser'
        email = 'test@example.com'
        password = 'testpassword'
        name = 'Test User'
        address = '123 Test St'

        response = self.client.get(url_for('register'))
        self.assert200(response)

        # Submit the registration form
        response = self.client.post(url_for('register'), data={
            'username': username,
            'email': email,
            'password': password,
            'name': name,
            'address': address,
        }, follow_redirects=True)

        self.assert200(response)
        self.assertIn(b'Your account has been created!', response.data)

        # Check if the user is added to the database
        user = User.query.filter_by(username=username).first()
        self.assertIsNotNone(user)
        self.assertEqual(user.email, email)
        self.assertEqual(user.name, name)
        self.assertEqual(user.address, address)

        # Check if the user can log in with the registered credentials
        response = self.client.post(url_for('login'), data={
            'username': username,
            'password': password,
        }, follow_redirects=True)

        self.assert200(response)
        self.assertIn(b'Welcome, ' + name.encode('utf-8'), response.data)
        self.assertEqual(user, current_user)


if __name__ == '__main__':
    unittest.main()
