import os
import re
import random
import hashlib
import hmac
import time
from string import letters

import webapp2
import jinja2

from google.appengine.ext import ndb

from user import User
from post import Post
from comment import Comment
from like import Like

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), 'templates')
JINJA_ENVIRONMENT = jinja2.Environment(
    loader=jinja2.FileSystemLoader(TEMPLATE_DIR),
    autoescape=True)


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


def get_by_urlsafe(urlsafe, model):
    """Returns an ndb.Model entity that the urlsafe key points to. Checks
        that the type of entity returned is of the correct kind. Raises an
        error if the key String is malformed or the entity is of the incorrect
        kind
    Args:
        urlsafe: A urlsafe key string
        model: The expected entity kind
    Returns:
        The entity that the urlsafe Key string points to or None if no entity
        exists.
    Raises:
        ValueError
    """

    key = ndb.Key(urlsafe=urlsafe)
    print '---> key: {}'.format(key)
    entity = key.get()
    if not entity:
        return None
    if not isinstance(entity, model):
        raise ValueError('Incorrect Kind')
    return entity


"""
    Methods to check validity of inputs
"""
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)


"""
    Handler

    Base class for all handlers
"""


class Handler(webapp2.RequestHandler):

    def redirect_after_delay(self, redirect_url):
        time.sleep(0.1)
        self.redirect(redirect_url)

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
        """Clears out the cookie from the header."""
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        # print 'uid = {}'.format(uid)
        self.user = uid and ndb.Key(urlsafe=uid).get()


"""
    FrontHandler

    Handler for the front (main) page of the blog which lists all posts.
"""


class FrontHandler(Handler):

    def get(self):
        posts = Post.query().order(-Post.created)
        self.render("front.html", posts=posts)


"""
    SignupHandler

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
        params = dict(username=self.username, email=self.email)

        # check for valid username
        if not valid_username(self.username):
            params['username_error'] = "That's not a valid username."
            have_error = True

        # check for valid password
        if not valid_password(self.password):
            params['password_error'] = "That's not a valid password."
            have_error = True
        else:
            # check that passwords match
            print 'password: %s, verified: %s' % \
                (self.password, self.verified_password)

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
    LoginHandler

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
            self.render('login.html', login_error=msg)


"""
    LogoutHandler

    Handler for logging out.
    Clears the cookie and redirects to the signup page.
"""


class LogoutHandler(Handler):

    def get(self):
        self.logout()
        self.redirect('/signup')

"""
    NewPostHandler

    Handler for creation of new posts.
"""


class NewPostHandler(Handler):

    def get(self):
        """If the user is logged in, show the new post page.
        Otherwise, show the login page."""
        if self.user:
            self.render('newpost.html')
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            # create a new post
            post = Post.new_post(user=self.user,
                                 subject=subject,
                                 content=content)

            # redirect to the new post.
            self.redirect('/{}'.format(post.key.id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html",
                        subject=subject,
                        content=content,
                        error=error)


"""
    PostHandler

    Handler for individual blog posts.
"""


class PostHandler(Handler):

    def get(self, post_id):
        # print 'looking for post with id: {}'.format(post_id)
        post = Post.get_by_id(int(post_id))
        # print 'post: {}'.format(post)

        # show 404 error page if the post cannot be found.
        if not post:
            self.error(404)
            return

        # get the comments
        comments = post.get_comments()
        print comments
        num_comments = len(comments)
        print 'num comments = {}'.format(num_comments)

        self.render("permalink.html", post=post, comments=comments)

    def post(self, post_id):

        if not self.user:
            self.redirect('/')

        post = Post.get_by_id(int(post_id))
        if not post:
            self.error(404)
            return

        text = self.request.get('comment')

        if post and text:
            # create new comment.
            comment = Comment.new_comment(user=self.user.key,
                                          post=post.key,
                                          content=text)
            # reload the page
            self.redirect_after_delay('/{}'.format(post.key.id()))
        else:
            self.error(404)


class EditPostHandler(Handler):

    def get(self, post_id):
        post = Post.get_by_id(int(post_id))

        # show 404 error page if the post cannot be found.
        if not post:
            self.error(404)
            return

        self.render("editpost.html",
                    post=post,
                    error="")

    def post(self, post_id):
        post = Post.get_by_id(int(post_id))
        if not post:
            print "post not found"
        else:
            subject = self.request.get('subject')
            content = self.request.get('content')

            print "editing post to {}, {}".format(subject, content)
            post.subject = subject
            post.content = content

            # save the new values
            post.put()

            # redirect back to the post page
            self.redirect('/{}'.format(post_id))


class LikePostHandler(Handler):

    def post(self, post_id):
        if not self.user:
            self.redirect('/')

        post = Post.get_by_id(int(post_id))
        if post:
            # create new like instance.
            like = Like.new_like(user=self.user.key,
                                 post=post.key)

            # reload the page
            self.redirect_after_delay('/{}'.format(post.key.id()))


class UnlikePostHandler(Handler):

    def post(self, post_id):
        if not self.user:
            self.redirect('/')

        post = Post.get_by_id(int(post_id))
        if post:
            print post.key
            query = Like.query(Like.post == post.key)
            like = query.get()

        if like:
            # print "post = {}".format(post)
            post_id = post.key.id()
            like.key.delete()
            # redirect to the post page
            self.redirect_after_delay('/{}'.format(post_id))


class DeletePostHandler(Handler):

    # def get(self, post_id):
    #     post = Post.get_by_id(int(post_id))
    #     if post:
    #         post.key.delete()
    #     else:
    #         print "post not found."

    #     # redirect to the front page
    #     self.redirect('/')

    def post(self, post_id):
        post = Post.get_by_id(int(post_id))
        if post:
            post.key.delete()
            # redirect to the front page
            self.redirect('/')

        else:
            self.error(404)


class EditCommentHandler(Handler):
    def post(self, comment_id):
        comment = Comment.get_by_id(int(comment_id))
        if comment:
            text = self.request.get('comment-edit')
            print 'new comment text: {}'.format(text)
            comment.content = text
            comment.put()

            post = comment.post.get()
            post_id = post.key.id()

            # redirect back to the post page
            self.redirect_after_delay('/{}'.format(post_id))
        else:
            self.error(404)


class DeleteCommentHandler(Handler):

    def post(self, comment_id):
        comment = Comment.get_by_id(int(comment_id))
        if comment:
            post = comment.post.get()
            # print "post = {}".format(post)
            post_id = post.key.id()
            comment.key.delete()
            # redirect to the post page
            self.redirect_after_delay('/{}'.format(post_id))
        else:
            self.error(404)

"""
    WelcomeHandler

    Handler for the welcome page shown after an account has been created.
    If a user attempts to view this page without signing in first,
    then they are redirected to the sign in page.
"""


class WelcomeHandler(Handler):

    def get(self):
        if self.user:
            self.render('welcome.html', username=self.user.username)
        else:
            self.redirect('/signup')


app = webapp2.WSGIApplication([('/', FrontHandler),
                               ('/signup', SignupHandler),
                               ('/login', LoginHandler),
                               ('/logout', LogoutHandler),
                               ('/newpost', NewPostHandler),
                               ('/welcome', WelcomeHandler),
                               ('/([0-9]+)', PostHandler),
                               ('/([0-9]+)/edit', EditPostHandler),
                               ('/([0-9]+)/like', LikePostHandler),
                               ('/([0-9]+)/unlike', UnlikePostHandler),
                               ('/([0-9]+)/delete', DeletePostHandler),
                               ('/comment/([0-9]+)/edit', EditCommentHandler),
                               ('/comment/([0-9]+)/delete',
                                DeleteCommentHandler)
                               ],
                              debug=True)