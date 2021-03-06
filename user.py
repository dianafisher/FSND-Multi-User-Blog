from google.appengine.ext import ndb
import hashlib
import urllib
import hmac
import random
from string import letters

"""
user.py - This file contains the class definitions for the User entity.
"""


def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group='default'):
    return ndb.Key('users', group)


""" Choose an avatar image randomly from the svg folder """


def get_avatar_path():
    index = random.randint(0, 115)
    # print 'index: {}'.format(index)
    path = '/static/svg/user_avatar_{}.svg'.format(index)
    # print 'path: {}'.format(path)
    return path


class User(ndb.Model):
    username = ndb.StringProperty(required=True)
    password_hash = ndb.StringProperty(required=True)
    email = ndb.StringProperty()
    avatar_url = ndb.StringProperty(required=True)

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.query().filter(User.username == name).get()

        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    username=name,
                    password_hash=pw_hash,
                    email=email,
                    avatar_url=get_avatar_path())

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        print 'u = {}'.format(u)
        if u and valid_pw(name, pw, u.password_hash):
            return u
