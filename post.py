from google.appengine.ext import ndb
import utils

"""
post.py - This file contains the class definitions for the Post entity.
"""


class Post(ndb.Model):
    user = ndb.KeyProperty(required=True, kind='User')
    subject = ndb.StringProperty(required=True)
    content = ndb.TextProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)
    last_modified = ndb.DateTimeProperty(auto_now=True)

    @classmethod
    def new_post(cls, user, subject, content):
        """ creates and returns a new Post instance"""
        post = Post(user=user.key, subject=subject, content=content)
        post.put()
        return post

    def render(self):
        # replace new line characters with breaks
        self.__render_text = self.content.replace('\n', '<br>')
        return utils.render_str('post.html', post=self)
