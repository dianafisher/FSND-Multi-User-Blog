import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import ndb

from user import User
from post import Post

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), 'templates')
JINJA_ENVIRONMENT = jinja2.Environment(
    loader = jinja2.FileSystemLoader(TEMPLATE_DIR),
    autoescape = True)


SECRET = 'loki'

"""
    Utility methods
"""
def render_str(template, **params):
    t = JINJA_ENVIRONMENT.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(SECRET, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

"""
    Methods to check validity of inputs
"""
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)


"""
    Base class for all handlers
"""
class Handler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        cookie_header = '{}={}; Path=/'.format(name, cookie_val)
        self.response.headers.add_header('Set-Cookie', cookie_header)

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', user.key.urlsafe())

    def logout(self):
        # Clear out the cookie.
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        print 'uid = {}'.format(uid)
        self.user = uid and ndb.Key(urlsafe=uid).get()

"""
    Handler for the front (main) page of the blog which lists all posts.
"""
class FrontHandler(Handler):

    def get(self):
        posts = Post.query().order(-Post.created)
        self.render("front.html", posts = posts)

"""
    Handler for the sign up page.
"""
class SignupHandler(Handler):

    def get(self):
        self.render('signup.html')

    def post(self):
        have_error = False
        self.username = self.request.get("username")
        self.password = self.request.get("password")
        self.verified_password = self.request.get("verify")
        self.email = self.request.get("email")

        # create a dictionary to hold any error messages
        params = dict(username = self.username,
                        email = self.email)

        # check for valid username
        if not valid_username(self.username):
            params['username_error'] = "That's not a valid username."
            have_error = True

        print 'checking password {}'.format(self.password)
        # check for valid password
        if not valid_password(self.password):
            params['password_error'] = "That's not a valid password."
            have_error = True
        else:
            # check that passwords match
            print 'password: %s, verified: %s' % (self.password, self.verified_password)

            if not self.password == self.verified_password:
                params['verify_error'] = "Passwords do not match!"
                have_error = True

        # check for valid email
        if not valid_email(self.email):
            params['email_error'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup.html', **params)
        else:
            # make sure the user doesn't already exist
            user = User.by_name(self.username)
            if user:
                username_error = 'User already exists!'
                self.render('signup.html', username_error=username_error)
            else:
                # create a new User instance
                u = User.register(self.username, self.password, self.email)

                # store it in the database
                user_key = u.put()

                # log in the new user
                self.login(u)

                # redirect to the welcome page
                self.redirect("/welcome")

"""
    Handler for the login page.
"""
class LoginHandler(Handler):

    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/welcome')
        else:
            msg = 'Invalid login'
            self.render('login.html', login_error = msg)


"""
    Handler for logging out.  Clears the current cookie and redirects to the signup page.
"""
class LogoutHandler(Handler):

    def get(self):
        self.logout()
        self.redirect('/signup')

"""
    Handler for creation of new posts.
"""
class NewPostHandler(Handler):

    def get(self):
        # If the user is logged in, show the new post page.  Otherwise, show the login page.
        if self.user:
            self.render('newpost.html')
        else:
            self.redirect("/login")
"""
    Handler for the welcome page which is shown after an account has been created.
    If a user attempts to view this page without signing in first, then they are redirected
    to the sign in page.
"""
class WelcomeHandler(Handler):

    def get(self):
        if self.user:
            self.render('welcome.html', username = self.user.username)
        else:
            self.redirect('/signup')

        # cookie_str = self.request.cookies.get('user_id')
        # if cookie_str:
        #     cookie_val = check_secure_val(cookie_str)
        #     print "cookie = {}".format(cookie_val)
        #     self.render('welcome.html', username=cookie_val)
        # else:
        #     # redirect to the signup page
        #     self.redirect('/signup')

app = webapp2.WSGIApplication([('/', FrontHandler),
                               ('/signup', SignupHandler),
                               ('/login', LoginHandler),
                               ('/logout', LogoutHandler),
                               ('/newpost', NewPostHandler),
                               ('/welcome', WelcomeHandler),
                               ],
                              debug=True)