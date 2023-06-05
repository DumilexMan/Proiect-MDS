import unittest
from datetime import datetime

from flask import Flask
from werkzeug.security import generate_password_hash

from app import app, LoginForm, bcrypt
from models import db, User, Product, Post
from flask_testing import TestCase
from flask_login import current_user


class AppTestCase(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()

    def test_home_route(self):
        response = self.app.get('/')
        self.assertEqual(response.status_code, 200)


if __name__ == '__main__':
    unittest.main()
