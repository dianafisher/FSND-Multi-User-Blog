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
    # print '---> key: {}'.format(key)
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
        print '--> !!! exception: {}'.format(exception)
        # Log the error.
        logging.exception(exception)

        # Set a custom message.
        self.render("500.html")

        # If the exception is a HTTPException, use its error code.
        # Otherwise use a generic 500 error code.
        if isinstance(exception, webapp2.HTTPException):
            self.response.set_status(exception.code)
        else:
            self.response.set_status(500)

    def render_404(self, error_message):
        self.render("404.html", error_message=error_message)
        self.response.set_status(404)

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
        count = posts.count()
        self.render("front.html", count=count, posts=posts)


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
                print 'new user: {}'.format(u)

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
        # if the user is already logged in, redirect to the front page.
        if self.user:
            self.redirect('/')
            return

        # otherwise, show the login page
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
        if self.user:
            self.logout()
            self.redirect('/signup')
        else:
            self.redirect('/')

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
    # get method renders the specified post in its own page
    def get(self, post_id):

        post = Post.get_by_id(int(post_id))

        # show 404 error page if the post cannot be found.
        if not post:
            self.render_404(
                error_message="Post {} not found.".format(post_id))
            return

        params = self.create_params(post)

        # print 'owner: {}'.format(owner)
        self.render("permalink.html", **params)

    # create_params method is a utility method to create template parameters
    def create_params(self, post):

        # get the comments
        comments = post.get_comments()
        owner = post.user.get()
        has_liked = False
        # check if the logged in user has liked this post
        if self.user:
            user_id = self.user.key.id()

            # check if the current user has liked this post
            has_liked = post.is_liked_by(self.user)

        params = dict(post=post,
                      comments=comments,
                      owner=owner,
                      has_liked=has_liked)
        return params

    # post method creates a Comment instance for the specfied post.
    def post(self, post_id):

        # if no signed in user, redirect to the login page
        if not self.user:
            self.redirect('/login')
            return

        post = Post.get_by_id(int(post_id))
        if not post:
            self.render_404(
                error_message="Post {} not found.".format(post_id))
            return

        text = self.request.get('comment')

        if len(text) == 0:
            text = None

        if post and text:
            # create new comment.
            comment = Comment.new_comment(user=self.user.key,
                                          post=post.key,
                                          content=text)
            # reload the page
            self.redirect_after_delay('/{}'.format(post.key.id()))
        else:
            params = self.create_params(post)
            params['comment_error'] = "Comment text cannot be emtpy."
            self.render("permalink.html", **params)

    # delete method deletes the specified Post instance
    def delete(self, post_id):
        # redirect to login page if not logged in
        if not self.user:
            self.redirect('/login')
            return

        post = Post.get_by_id(int(post_id))
        if post:
            post.key.delete()
        else:
            self.render_404(
                error_message="Post {} not found.".format(post_id))


"""
    EditPostHandler

    Handler for editing blog posts.
"""


class EditPostHandler(Handler):

    def get(self, post_id):
        # if not looged in, redirect to the login page.
        if not self.user:
            self.redirect('/login')
            return

        post = Post.get_by_id(int(post_id))

        # show 404 error page if the post cannot be found.
        if not post:
            self.render_404(
                error_message="Post {} not found.".format(post_id))
            return

        params = dict(post=post)

        # check that the current user is the owner of the post.
        owner = post.user.get()
        owner_id = owner.key.id()
        user_id = self.user.key.id()

        if owner_id is not user_id:
            params['permissions_error'] = "Only the original author may edit this post."
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
            self.render_404(
                error_message="Post {} not found.".format(post_id))
            return
        else:
            # check that the current user is the owner of the post.
            owner = post.user.get()
            owner_id = owner.key.id()
            user_id = self.user.key.id()
            params = dict(post=post)

            if owner_id is not user_id:
                params['permissions_error'] = "Only the original author may edit this post."
                self.render("postpermissionserror.html", **params)

            subject = None
            content = None

            subject = self.request.get('subject')
            content = self.request.get('content')

            if subject and content:
                # update the post
                post.subject = subject
                post.content = content

                # save the new values
                post.put()

                # redirect back to the post page
                self.redirect('/{}'.format(post_id))

            else:
                error = "subject and content, please!"
                self.render("editpost.html",
                            post=post,
                            error=error)

"""
    LikePostHandler

    Handler for liking blog posts.
"""


class LikePostHandler(Handler):

    # get method just redirects to post page
    def get(self, post_id):
        self.redirect_after_delay('/{}'.format(post_id))

    def post(self, post_id):
        # if no signed in user, redirect to the login page
        if not self.user:
            self.redirect('/login')
            return

        # get the post from the datastore
        post = Post.get_by_id(int(post_id))
        if post:

            # get the comments
            comments = post.get_comments()
            owner = post.user.get()

            # create a dictionary to hold any error messages
            params = dict(post=post, comments=comments, owner=owner)

            # Do not allow the author to like their own post.
            owner = post.user.get()
            owner_id = owner.key.id()
            user_id = self.user.key.id()

            if owner_id is user_id:
                params['error'] = "You are not allowed to like your own post."
                self.render("permalink.html", **params)
                return

            if post.is_liked_by(self.user):
                # Do not allow a user to like a post more than once.
                params['like_error'] = "You have already liked this post."

                self.render("permalink.html", **params)
                return

            # create new like instance.
            like = Like.new_like(user=self.user.key,
                                 post=post.key)

            # reload the page
            self.redirect_after_delay('/{}'.format(post.key.id()))
        else:
            self.render_404(
                error_message="Post {} not found.".format(post_id))

"""
    UnlikePostHandler

    Handler for unliking blog posts.
"""


class UnlikePostHandler(Handler):

    # get method just redirects to post page
    def get(self, post_id):
        self.redirect_after_delay('/{}'.format(post_id))

    # post method deletes the Like entity for the specified post
    def post(self, post_id):
        # if no signed in user, redirect to the login page
        if not self.user:
            self.redirect('/login')

        post = Post.get_by_id(int(post_id))
        if post:
            query = Like.query(Like.post == post.key)
            like = query.get()
        else:
            self.render_404(
                error_message="Post {} not found.".format(post_id))
        if like:
            post_id = post.key.id()
            like.key.delete()
            # redirect to the post page
            self.redirect_after_delay('/{}'.format(post_id))
        else:
            # create a dictionary to hold any error messages
            params = dict(post=post,
                          comments=post.get_comments(),
                          owner=post.user.get())

            # user has not liked this post, so show an error.
            params['error'] = "Cannot unlike a post which has not been liked."
            self.render("permalink.html", **params)


"""
    CommentHandler
"""


class CommentsHandler(Handler):

    # get method returns all comments for a post
    def get(self, post_id):
        if not self.user:
            self.redirect('/login')

        post = Post.get_by_id(int(post_id))
        if post:
            # get the comments for this post
            comments = post.get_comments()
            self.render("comments.html", comments=comments)
        else:
            self.render_404(
                error_message="Post {} not found.".format(post_id))

"""
    EditCommentHandler
"""


class EditCommentHandler(Handler):

    # post method will update the comment text
    def post(self, comment_id):
        comment = Comment.get_by_id(int(comment_id))

        if comment:
            # check that the signed in user is owns this comment
            owner = comment.user.get()
            owner_id = owner.key.id()
            user_id = self.user.key.id()

            post = comment.post.get()
            if owner_id is not user_id:
                # create a dictionary to hold any error messages
                params = dict(post=post,
                              comments=post.get_comments(),
                              owner=post.user.get())

                params['error'] = "Cannot edit another user's comment."
                self.render("permalink.html", **params)

            else:
                # update the comment
                text = self.request.get('comment-edit')
                comment.content = text
                comment.put()
                post_id = post.key.id()

                # redirect back to the post page
                self.redirect_after_delay('/{}'.format(post_id))
        else:
            # comment not found
            self.render_404(
                error_message="Comment {} not found.".format(comment_id))

"""
    DeleteCommentHandler
"""


class DeleteCommentHandler(Handler):

    # post method deletes the specified comment from the datastore
    def post(self, comment_id):
        comment = Comment.get_by_id(int(comment_id))
        if comment:
            post = comment.post.get()

            # check that the signed in user is owns this comment
            owner = comment.user.get()
            owner_id = owner.key.id()
            user_id = self.user.key.id()

            if owner_id is not user_id:
                # create a dictionary to hold any error messages
                params = dict(post=post,
                              comments=post.get_comments(),
                              owner=post.user.get())

                params['error'] = "Cannot delete another user's comment."
                self.render("permalink.html", **params)

            else:
                # delete the comment
                post_id = post.key.id()
                comment.key.delete()
                # redirect to the post page
                self.redirect_after_delay('/{}'.format(post_id))
        else:
            self.render_404(
                error_message="Comment {} not found.".format(comment_id))


"""
    WelcomeHandler

    Handler for the welcome page shown after an account has been created.
    If a user attempts to view this page without signing in first,
    then they are redirected to the sign in page.
"""


class WelcomeHandler(Handler):

    def get(self):
        if self.user:
            # Get the posts authored by this user.
            query = Post.query(Post.user == self.user.key)
            posts = query.fetch()
            print 'self.user: {}'.format(self.user)
            self.render('welcome.html', user=self.user, posts=posts)
        else:
            self.redirect('/signup')

"""
    UserHandler

    Handler to show details of and posts by selected user.
"""


class UserHandler(Handler):

    def get(self, user_id):

        if not self.user:
            self.redirect('/login')
            return

        u = User.by_id(int(user_id))
        print 'user = {}'.format(u)
        if not u:
            self.render_404(error_message="User {} not found.".format(user_id))
            return
        else:
            # Get the posts authored by this user.
            query = Post.query(Post.user == u.key)
            posts = query.fetch()
            self.render('user.html', u=u, posts=posts, user=self.user)


"""
    UsersHandler
"""


class UsersHandler(Handler):
    # get method renders all users in the system.
    def get(self):
        if not self.user:
            self.redirect('/login')
            return

        query = User.query()
        users = query.fetch()
        self.render("users.html", users=users)

"""
    AvatarHandler
"""


class AvatarHandler(Handler):

    def get(self):
        avatars = []
        for x in range(116):
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
                               ('/([0-9]+)/comments', CommentsHandler),
                               ('/comment/([0-9]+)/edit', EditCommentHandler),
                               ('/comment/([0-9]+)/delete',
                                DeleteCommentHandler),
                               ('/user/([0-9]+)', UserHandler),
                               ('/users', UsersHandler),
                               ('/avatars', AvatarHandler)
                               ],
                              debug=True)

app.error_handlers[404] = handle_404
app.error_handlers[500] = handle_500
