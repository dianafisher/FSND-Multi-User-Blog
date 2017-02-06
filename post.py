from google.appengine.ext import ndb
# from google.appengine.ext import db

"""
post.py - This file contains the class definitions for the Post entity.
"""

class Post(ndb.Model):
    title = ndb.StringProperty(required = True)
    content = ndb.TextProperty(required = True)
    created = ndb.DateTimeProperty(auto_now_add = True)
    last_modified = ndb.DateTimeProperty(auto_now = True)

    def render(self):
        # replace new line characters with breaks
        self.__render_text = self.content.replace('\n', '<br>')
        return render('post.html', post = self)