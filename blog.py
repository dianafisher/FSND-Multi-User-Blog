import os
import re
import random
import hashlib
import hmac
import time
from string import letters

import webapp2
import jinja2
import logging

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

    def handle_exception(self, exception, debug):
        print exception
        print 'exception: {}'.format(exception)
        # Log the error.
        logging.exception(exception)

        # Set a custom message.
        # self.response.write('An error occurred.')
        self.render("500.html")

        # If the exception is a HTTPException, use its error code.
        # Otherwise use a generic 500 error code.
        if isinstance(exception, webapp2.HTTPException):
            self.response.set_status(exception.code)
        else:
            self.response.set_status(500)

    def redirect_after_delay(self, redirect_url):
        time.sleep(0.1)
        self.redirect(redirect_url)

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        print "rendering template: {}".format(template)
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
            print "params: {}".format(params)
            self.render('signup.html', **params)
        else:
            # make sure the user doesn't already exist
            user = User.by_name(self.username)
            if user:
                params['username_error'] = 'User already exists!'
                self.render('signup.html', **params)
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
            # redirect to login page if not logged in
            self.redirect("/login")

    def post(self):
        # redirect to front page if not logged in
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
        # print "user = {}".format(self.user)
        # if no signed in user, redirect to the login page
        if not self.user:
            self.redirect('/login')
            return

        post = Post.get_by_id(int(post_id))

        # show 404 error page if the post cannot be found.
        if not post:
            self.error(404)
            return

        # get the comments
        comments = post.get_comments()

        owner = post.user.get()

        owner_id = owner.key.id()
        user_id = self.user.key.id()

        # create a dictionary to hold any error messages
        params = dict(post=post, comments=comments, owner=owner)

        # print 'owner: {}'.format(owner)
        self.render("permalink.html", **params)

    def post(self, post_id):
        # if no signed in user, redirect to the login page
        if not self.user:
            self.redirect('/login')
            return

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

    def delete(self, post_id):
        # redirect to login page if not logged in
        if not self.user:
            self.redirect('/login')
            return

        post = Post.get_by_id(int(post_id))
        if post:
            post.key.delete()
        else:
            self.error(404)


## TODO: Check for both subject and content
class EditPostHandler(Handler):

    def get(self, post_id):
        if not self.user:
            self.redirect('/')
            return

        print "self.user = {}".format(self.user)

        post = Post.get_by_id(int(post_id))
        # show 404 error page if the post cannot be found.
        if not post:
            self.error(404)
            return

        params = dict(post=post)

        # check that the current user is the owner of the post.
        owner = post.user.get()
        owner_id = owner.key.id()
        user_id = self.user.key.id()

        print 'owner_id = {}, user_id = {}'.format(owner_id, user_id)

        if owner_id is not user_id:
            params['permissions_error'] = "Only the original author may edit\
            this post."
            self.render("postpermissionserror.html", **params)
        else:
            self.render("editpost.html", **params)

    def post(self, post_id):
        # if no signed in user, redirect to the login page
        if not self.user:
            self.redirect('/login')
            return

        post = Post.get_by_id(int(post_id))
        if not post:
            self.error(404)
            return
        else:
            subject = self.request.get('subject')
            content = self.request.get('content')

            # print "editing post to {}, {}".format(subject, content)
            post.subject = subject
            post.content = content

            # save the new values
            post.put()

            # redirect back to the post page
            self.redirect('/{}'.format(post_id))


class LikePostHandler(Handler):

    def get(self, post_id):
        self.redirect_after_delay('/{}'.format(post_id))

    def post(self, post_id):
        if not self.user:
            self.redirect('/')
            return

        """if this user has already liked this post,
        then they should not be allowed to like it again"""

        post = Post.get_by_id(int(post_id))
        if post:

            # get all likes for this post
            query = Like.query(Like.post == post.key)
            results = query.get()

            q = query.filter(Like.user == self.user.key)

            result = q.fetch()
            print "result = {}".format(result)

            """this user has already liked this post,
            so don't let them like it again."""

            if result:

                # get the comments
                comments = post.get_comments()
                owner = post.user.get()

                # create a dictionary to hold any error messages
                params = dict(post=post, comments=comments, owner=owner)
                params['like_error'] = "You have already liked this post."
                print 'params: {}'.format(params)

                self.render("permalink.html", **params)
                return

            # create new like instance.
            like = Like.new_like(user=self.user.key,
                                 post=post.key)

            # reload the page
            self.redirect_after_delay('/{}'.format(post.key.id()))
        else:
            self.error(404)


class UnlikePostHandler(Handler):

    def get(self, post_id):
        self.redirect_after_delay('/{}'.format(post_id))

    def post(self, post_id):
        if not self.user:
            self.redirect('/')

        post = Post.get_by_id(int(post_id))
        if post:
            # print post.key
            query = Like.query(Like.post == post.key)
            like = query.get()

        if like:
            # print "post = {}".format(post)
            post_id = post.key.id()
            like.key.delete()
            # redirect to the post page
            self.redirect_after_delay('/{}'.format(post_id))
        else:
            self.error(404)


class EditCommentHandler(Handler):

    def get(self, post_id):
        self.redirect_after_delay('/{}'.format(post_id))

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

    def get(self, post_id):
        self.redirect_after_delay('/{}'.format(post_id))

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
            self.render('welcome.html', user=self.user)
        else:
            self.redirect('/signup')

"""
    UserHandler


"""


class UserHandler(Handler):

    def get(self, user_id):
        if not self.user:
            self.redirect('/login')
            return

        user = User.get_by_id(int(user_id))
        if not user:
            self.error(404)
            return
        else:
            self.render('user.html', user=user)


class AvatarHandler(Handler):

    def get(self):
        avatars = []
        for x in range(115):
            avatar = {}
            avatar['name'] = 'avatar_{}.svg'.format(x)
            avatar['url'] = '/static/svg/user_avatar_{}.svg'.format(x)
            avatars.append(avatar)

        self.render('avatars.html', avatars=avatars)




"""
    Error Handlers
"""


def handle_404(request, response, exception):
    logging.exception(exception)
    response.write(render_str("404.html"))
    response.set_status(404)


def handle_500(request, response, exception):
    response.write(render_str("500.html"))
    response.set_status(500)

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
                               ('/comment/([0-9]+)/edit', EditCommentHandler),
                               ('/comment/([0-9]+)/delete',
                                DeleteCommentHandler),
                               ('/user/([0-9]+)', UserHandler),
                               ('/avatars', AvatarHandler)
                               ],
                              debug=True)

app.error_handlers[404] = handle_404
# app.error_handlers[500] = handle_500
