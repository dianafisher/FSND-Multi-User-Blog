from google.appengine.ext import ndb

import utils

"""
comment.py - This file contains the class definitions for the Comment entity.
"""


class Comment(ndb.Model):
    user = ndb.KeyProperty(required=True, kind='User')
    post = ndb.KeyProperty(required=True, kind='Post')
    content = ndb.TextProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)
    last_modified = ndb.DateTimeProperty(auto_now=True)

    @classmethod
    def new_comment(cls, user, post, content):
        """ creates and returns a new Comment instance"""
        comment = Comment(user=user, post=post, content=content)
        comment.put()
        return comment

    def render(self):
        # replace new line characters with breaks
        self.__render_text = self.content.replace('\n', '<br>')
        return utils.render_str('comment.html',
                                comment=self)
