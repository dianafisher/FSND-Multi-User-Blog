from google.appengine.ext import ndb
import utils

from comment import Comment

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
        comments = self.get_comments()
        print comments
        num_comments = len(comments)
        num_likes = 10000
        print 'num comments = {}'.format(num_comments)
        return utils.render_str('post.html',
                                post=self,
                                comment_count=num_comments,
                                like_count=num_likes)

    def get_comments(self):
        """queries the datastore for comments on this post"""
        comments_query = Comment.query(Comment.post == self.key).order(-Comment.created)
        comments = comments_query.fetch(10)
        return comments
