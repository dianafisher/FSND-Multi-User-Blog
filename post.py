from google.appengine.ext import ndb
import utils

from comment import Comment
from like import Like

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

        comments_query = Comment.query(Comment.post == self.key)\
            .order(-Comment.created)

        num_comments = comments_query.count()
        if num_comments == 1:
            text = "comment"
        else:
            text = "comments"
        comment_count = "{} {}".format(num_comments, text)

        likes_query = Like.query(Like.post == self.key)
        num_likes = likes_query.count()
        if num_likes == 1:
            text = "like"
        else:
            text = "likes"
        like_count = "{} {}".format(num_likes, text)

        user = self.user.get()

        return utils.render_str('post.html',
                                post=self,
                                author=user,
                                comment_count=comment_count,
                                like_count=like_count)

    def get_comments(self):
        """queries the datastore for comments on this post"""
        comments_query = Comment.query(Comment.post == self.key)\
            .order(Comment.created)
        comments = comments_query.fetch()
        return comments

    def get_likes(self):
        """ queries the datastore for likes on this post """
        likes_query = Like.query(Like.post == self.key)
        likes = likes_query.fetch()
        return likes

    def get_owner_id(self):
        owner = self.user.get()
        owner_id = owner.key.id()
        return owner_id

    def is_liked_by(self, user):
        # get all likes for this post
        query = Like.query(Like.post == self.key)
        results = query.get()

        q = query.filter(Like.user == user.key)

        result = q.fetch()
        # print "result = {}".format(result)
        return result
