from google.appengine.ext import ndb

import utils

"""
like.py - This file contains the class definitions for the Like entity.
"""


class Like(ndb.Model):
    user = ndb.KeyProperty(required=True, kind='User')
    post = ndb.KeyProperty(required=True, kind='Post')
    created = ndb.DateTimeProperty(auto_now_add=True)

    @classmethod
    def new_like(cls, user, post):
        """ creates and returns a new Like instance"""
        like = Like(user=user, post=post)
        like.put()
        return like
